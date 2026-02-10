package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"
)

const maxMessageSize = 10 * 1024 * 1024 // 10MB

// Config holds configuration for a proxy instance.
type Config struct {
	Command   string
	Args      []string
	SessionID string
}

// Proxy is the core bidirectional MCP proxy.
type Proxy struct {
	config Config
	chain  *InterceptorChain
	logger *slog.Logger

	cmd       *exec.Cmd
	downStdin io.WriteCloser
}

func NewProxy(cfg Config, chain *InterceptorChain, logger *slog.Logger) *Proxy {
	if cfg.SessionID == "" {
		cfg.SessionID = shortID()
	}
	return &Proxy{
		config: cfg,
		chain:  chain,
		logger: logger,
	}
}

// SessionID returns the session identifier for this proxy instance.
func (p *Proxy) SessionID() string {
	return p.config.SessionID
}

// Run starts the downstream process and begins bidirectional proxying.
// It blocks until the context is cancelled or the downstream process exits.
func (p *Proxy) Run(ctx context.Context) error {
	p.cmd = exec.CommandContext(ctx, p.config.Command, p.config.Args...)

	var err error
	p.downStdin, err = p.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	downStdout, err := p.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	p.cmd.Stderr = os.Stderr

	if err := p.cmd.Start(); err != nil {
		return fmt.Errorf("start downstream %q: %w", p.config.Command, err)
	}

	p.logger.Info("downstream started",
		"command", p.config.Command,
		"args", p.config.Args,
		"pid", p.cmd.Process.Pid,
		"session", p.config.SessionID,
	)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	// Host stdin → downstream stdin
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := p.pipeMessages(ctx, os.Stdin, p.downStdin, DirHostToServer); err != nil {
			errCh <- fmt.Errorf("host->downstream: %w", err)
		}
		p.downStdin.Close()
	}()

	// Downstream stdout → host stdout
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := p.pipeMessages(ctx, downStdout, os.Stdout, DirServerToHost); err != nil {
			errCh <- fmt.Errorf("downstream->host: %w", err)
		}
	}()

	waitErr := p.cmd.Wait()
	cancel()
	wg.Wait()

	select {
	case err := <-errCh:
		if waitErr != nil {
			return waitErr
		}
		return err
	default:
	}
	return waitErr
}

// pipeMessages reads newline-delimited JSON from src, runs it through
// the interceptor chain, and writes surviving messages to dst.
func (p *Proxy) pipeMessages(ctx context.Context, src io.Reader, dst io.Writer, dir Direction) error {
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 64*1024), maxMessageSize)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// Copy — scanner reuses buffer
		raw := make([]byte, len(line))
		copy(raw, line)

		parsed, parseErr := ParseMessage(raw)

		msg := &InterceptedMessage{
			Timestamp: time.Now(),
			SessionID: p.config.SessionID,
			Direction: dir,
			RawBytes:  raw,
			Parsed:    parsed,
			ParseErr:  parseErr,
		}

		if parseErr != nil {
			p.logger.Warn("unparseable message, forwarding raw",
				"direction", dir,
				"error", parseErr,
			)
			// Forward unparseable messages as-is to avoid breaking the connection
			if _, err := dst.Write(append(raw, '\n')); err != nil {
				return fmt.Errorf("write: %w", err)
			}
			continue
		}

		result, chainErr := p.chain.Process(ctx, msg)
		if chainErr != nil {
			p.sendBlockError(dir, msg, chainErr)
			continue
		}
		if result == nil {
			p.logger.Debug("message dropped",
				"method", parsed.Method,
				"direction", dir,
			)
			continue
		}

		if _, err := dst.Write(append(result, '\n')); err != nil {
			return fmt.Errorf("write: %w", err)
		}
	}
	return scanner.Err()
}

// sendBlockError sends a JSON-RPC error back to the message's sender.
func (p *Proxy) sendBlockError(dir Direction, msg *InterceptedMessage, chainErr error) {
	if msg.Parsed.ID == nil {
		return // can't respond to notifications
	}

	errBytes := MakeErrorResponse(msg.Parsed.ID, -32600, chainErr.Error())

	// Error goes back to the sender:
	// host_to_server blocked → respond on stdout (back to host)
	// server_to_host blocked → respond on downstream stdin (back to server)
	var target io.Writer
	if dir == DirHostToServer {
		target = os.Stdout
	} else {
		target = p.downStdin
	}

	if _, err := target.Write(append(errBytes, '\n')); err != nil {
		p.logger.Error("failed to send block error", "error", err)
	}

	p.logger.Warn("message blocked",
		"method", msg.Parsed.Method,
		"direction", dir,
		"reason", chainErr.Error(),
	)
}

func shortID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}
