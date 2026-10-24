package container

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

const defaultProcessOutputLimit int64 = 1 << 20
const processPipeWait = time.Second

// OutputCaptureMetadata describes the original streams only when Complete is true.
// Complete=false means that a deadline or forced pipe closure prevented proving EOF.
type OutputCaptureMetadata struct {
	Complete                bool
	StdoutOriginalSizeBytes int64
	StderrOriginalSizeBytes int64
	StdoutTruncated         bool
	StderrTruncated         bool
}

type OutputCaptureMetadataProvider interface{ CaptureMetadata() OutputCaptureMetadata }

type OutputLimitError struct {
	Metadata OutputCaptureMetadata
	Cause    error
}

func (e *OutputLimitError) Error() string                          { return "process output limit exceeded" }
func (e *OutputLimitError) Unwrap() error                          { return e.Cause }
func (e *OutputLimitError) CaptureMetadata() OutputCaptureMetadata { return e.Metadata }

type CaptureIncompleteError struct {
	Metadata OutputCaptureMetadata
	Cause    error
}

func (e *CaptureIncompleteError) Error() string                          { return "process output capture incomplete" }
func (e *CaptureIncompleteError) Unwrap() error                          { return e.Cause }
func (e *CaptureIncompleteError) CaptureMetadata() OutputCaptureMetadata { return e.Metadata }

// Control process output is not workload output. Keep the failure/cancellation,
// but do not let an outer workload consumer mistake its counts for task streams.
func controlProcessError(err error, message string) error {
	var metadata OutputCaptureMetadataProvider
	if !errors.As(err, &metadata) {
		return err
	}
	var cause error
	if errors.Is(err, context.Canceled) {
		cause = context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		cause = errors.Join(cause, context.DeadlineExceeded)
	}
	return errors.Join(errors.New(message), cause)
}

func effectiveOutputLimit(limit int64) int64 {
	if limit > 0 {
		return limit
	}
	return defaultProcessOutputLimit
}

// Each pipe keeps its rolling tail before a deterministic aggregate rebalance.
// Writers always drain: exceeding the limit never changes the child's pipe behavior.
type processCapture struct {
	mu       sync.Mutex
	limit    int64
	tails    [2][]byte
	original [2]int64
}
type processCaptureWriter struct {
	capture *processCapture
	stream  int
}

func (w processCaptureWriter) Write(p []byte) (int, error) {
	c := w.capture
	c.mu.Lock()
	defer c.mu.Unlock()
	c.original[w.stream] += int64(len(p))
	if int64(len(p)) >= c.limit {
		c.tails[w.stream] = append(c.tails[w.stream][:0], p[len(p)-int(c.limit):]...)
	} else {
		old := c.tails[w.stream]
		if int64(len(old)+len(p)) > c.limit {
			old = old[len(old)+len(p)-int(c.limit):]
		}
		c.tails[w.stream] = append(old, p...)
	}
	return len(p), nil
}
func (c *processCapture) result(complete bool) ([]byte, []byte, OutputCaptureMetadata) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a, b := c.tails[0], c.tails[1]
	if int64(len(a))+int64(len(b)) > c.limit {
		x := min(int64(len(a)), c.limit/2)
		y := min(int64(len(b)), c.limit-c.limit/2)
		left := c.limit - x - y
		extra := min(left, int64(len(a))-x)
		x += extra
		left -= extra
		y += min(left, int64(len(b))-y)
		a = a[len(a)-int(x):]
		b = b[len(b)-int(y):]
	}
	m := OutputCaptureMetadata{Complete: complete, StdoutOriginalSizeBytes: c.original[0], StderrOriginalSizeBytes: c.original[1],
		StdoutTruncated: c.original[0] > int64(len(a)), StderrTruncated: c.original[1] > int64(len(b))}
	return bytes.Clone(a), bytes.Clone(b), m
}

func runBoundedProcess(ctx context.Context, stdin []byte, limit int64, name string, args ...string) ([]byte, []byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Minute)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = processPipeWait
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	capture := &processCapture{limit: effectiveOutputLimit(limit)}
	// Own the read pipes: exec.Wait can hide ErrWaitDelay behind a nonzero exit.
	// Explicit EOF tracking is necessary before calling original byte counts complete.
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	defer stdoutRead.Close()
	defer stdoutWrite.Close()
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	defer stderrRead.Close()
	defer stderrWrite.Close()
	cmd.Stdout = stdoutWrite
	cmd.Stderr = stderrWrite
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	_ = stdoutWrite.Close()
	_ = stderrWrite.Close()
	drains := make(chan error, 2)
	go func() {
		_, err := io.Copy(processCaptureWriter{capture: capture, stream: 0}, stdoutRead)
		drains <- err
	}()
	go func() {
		_, err := io.Copy(processCaptureWriter{capture: capture, stream: 1}, stderrRead)
		drains <- err
	}()
	err = cmd.Wait()
	timer := time.NewTimer(processPipeWait)
	defer timer.Stop()
	complete := ctx.Err() == nil && !errors.Is(err, exec.ErrWaitDelay)
	for pending := 2; pending > 0; {
		select {
		case drainErr := <-drains:
			pending--
			if drainErr != nil {
				complete = false
				err = errors.Join(err, drainErr)
			}
		case <-timer.C:
			complete = false
			err = errors.Join(err, exec.ErrWaitDelay)
			_ = stdoutRead.Close()
			_ = stderrRead.Close()
		}
	}
	out, stderr, metadata := capture.result(complete)
	if !complete {
		return nil, nil, &CaptureIncompleteError{Metadata: metadata, Cause: errors.Join(err, ctx.Err())}
	}
	if metadata.StdoutOriginalSizeBytes+metadata.StderrOriginalSizeBytes > capture.limit {
		return out, stderr, &OutputLimitError{Metadata: metadata, Cause: err}
	}
	return out, stderr, err
}

// Bound injected runner results too; an existing metadata error remains authoritative.
func boundRunnerOutput(out, stderr []byte, err error, limit int64) ([]byte, []byte, error) {
	var prior OutputCaptureMetadataProvider
	var original *OutputCaptureMetadata
	if errors.As(err, &prior) {
		m := prior.CaptureMetadata()
		if !m.Complete {
			return nil, nil, err
		}
		original = &m
	}
	capture := &processCapture{limit: effectiveOutputLimit(limit)}
	_, _ = (processCaptureWriter{capture: capture, stream: 0}).Write(out)
	_, _ = (processCaptureWriter{capture: capture, stream: 1}).Write(stderr)
	out, stderr, metadata := capture.result(true)
	if original != nil {
		metadata.StdoutOriginalSizeBytes = original.StdoutOriginalSizeBytes
		metadata.StderrOriginalSizeBytes = original.StderrOriginalSizeBytes
		metadata.StdoutTruncated = metadata.StdoutOriginalSizeBytes > int64(len(out))
		metadata.StderrTruncated = metadata.StderrOriginalSizeBytes > int64(len(stderr))
	}
	if metadata.StdoutOriginalSizeBytes+metadata.StderrOriginalSizeBytes > capture.limit {
		return out, stderr, &OutputLimitError{Metadata: metadata, Cause: err}
	}
	return out, stderr, err
}
