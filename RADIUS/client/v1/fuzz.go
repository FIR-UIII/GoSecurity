package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"
)

// fuzzMutation applies one random structural mutation to a copy of base and
// returns the mutated packet along with a short description of what was
// changed (useful to reproduce an interesting finding).
func fuzzMutation(base RawPacket, rng *rand.Rand) (RawPacket, string) {
	p := base.Clone()

	kinds := []string{
		"bitflip-value", "truncate-value", "oversize-value", "bad-length-byte",
		"duplicate-attr", "unknown-type-attr", "empty-value", "garbage-attr",
		"corrupt-total-length", "invalid-code", "extreme-id", "strip-attributes",
	}
	kind := kinds[rng.Intn(len(kinds))]

	switch kind {
	case "bitflip-value":
		if len(p.Attrs) > 0 {
			i := rng.Intn(len(p.Attrs))
			if len(p.Attrs[i].Value) > 0 {
				j := rng.Intn(len(p.Attrs[i].Value))
				p.Attrs[i].Value[j] ^= 1 << uint(rng.Intn(8))
			}
		}

	case "truncate-value":
		if len(p.Attrs) > 0 {
			i := rng.Intn(len(p.Attrs))
			if n := len(p.Attrs[i].Value); n > 1 {
				p.Attrs[i].Value = p.Attrs[i].Value[:rng.Intn(n)]
			}
		}

	case "oversize-value":
		if len(p.Attrs) > 0 {
			i := rng.Intn(len(p.Attrs))
			pad := make([]byte, 200+rng.Intn(200)) // push past the 253-byte AVP limit
			rng.Read(pad)
			p.Attrs[i].Value = append(p.Attrs[i].Value, pad...)
		}

	case "bad-length-byte":
		if len(p.Attrs) > 0 {
			i := rng.Intn(len(p.Attrs))
			// pick a length byte that lies about the real value size
			p.Attrs[i].LenOverride = rng.Intn(256)
		}

	case "duplicate-attr":
		if len(p.Attrs) > 0 {
			i := rng.Intn(len(p.Attrs))
			p.Attrs = append(p.Attrs, p.Attrs[i].clone())
		}

	case "unknown-type-attr":
		v := make([]byte, 1+rng.Intn(16))
		rng.Read(v)
		p.Attrs = append(p.Attrs, AttrSpec{Type: byte(rng.Intn(256)), Value: v, LenOverride: -1})

	case "empty-value":
		if len(p.Attrs) > 0 {
			i := rng.Intn(len(p.Attrs))
			p.Attrs[i].Value = nil
		}

	case "garbage-attr":
		v := make([]byte, rng.Intn(64))
		rng.Read(v)
		p.Attrs = append(p.Attrs, AttrSpec{Type: byte(rng.Intn(256)), Value: v, LenOverride: -1})

	case "corrupt-total-length":
		body := 0
		for _, a := range p.Attrs {
			body += 2 + len(a.Value)
		}
		real := 20 + body
		delta := rng.Intn(41) - 20 // real-20 .. real+20
		p.LengthOverride = real + delta

	case "invalid-code":
		p.Code = byte(rng.Intn(256))

	case "extreme-id":
		ids := []byte{0, 1, 127, 128, 255}
		p.ID = ids[rng.Intn(len(ids))]

	case "strip-attributes":
		p.Attrs = nil
	}

	return p, kind
}

// fuzzOptions configures a fuzzing run.
type fuzzOptions struct {
	Addr       string
	Iterations int
	Seed       int64
	Timeout    time.Duration
	Verbose    bool
	Delay      time.Duration
}

// runFuzz repeatedly mutates base and sends the result to addr, logging a
// one-line summary per iteration and a full raw+decoded dump whenever the
// exchange is "interesting" (network error/timeout, or an unexpected /
// unknown response code) or when opts.Verbose is set.
func runFuzz(ctx context.Context, base RawPacket, opts fuzzOptions) error {
	rng := rand.New(rand.NewSource(opts.Seed))
	fmt.Printf("[fuzz] target=%s iterations=%d seed=%d\n", opts.Addr, opts.Iterations, opts.Seed)

	var interesting int
	for i := 0; i < opts.Iterations; i++ {
		pkt, mutation := fuzzMutation(base, rng)
		raw := pkt.Build()

		if opts.Verbose {
			dumpPacket("to server", raw)
		}

		resp, rtt, err := exchangeRaw(ctx, opts.Addr, raw, opts.Timeout)

		isInteresting := err != nil
		var respCodeStr string
		if err == nil {
			respCodeStr = decodeRespCodeSummary(resp)
			if !isKnownResponseCode(resp) {
				isInteresting = true
			}
		}

		if isInteresting {
			interesting++
		}

		if opts.Verbose || isInteresting {
			if err != nil {
				fmt.Printf("[fuzz #%d] mutation=%-20s attrs=[%s] -> ERROR: %v\n", i, mutation, summarizeAttrs(pkt.Attrs), err)
			} else {
				fmt.Printf("[fuzz #%d] mutation=%-20s attrs=[%s] -> %s (rtt=%s)\n", i, mutation, summarizeAttrs(pkt.Attrs), respCodeStr, rtt)
			}
			if !opts.Verbose {
				// wasn't printed above; show full detail for the interesting case
				dumpPacket("to server", raw)
			}
			if err == nil {
				dumpPacket("from server", resp)
			}
		} else {
			fmt.Printf("[fuzz #%d] mutation=%-20s attrs=[%s] -> %s (rtt=%s)\n", i, mutation, summarizeAttrs(pkt.Attrs), respCodeStr, rtt)
		}

		if opts.Delay > 0 {
			time.Sleep(opts.Delay)
		}
	}

	fmt.Printf("[fuzz] done: %d/%d iterations produced an interesting result (error or unexpected code)\n", interesting, opts.Iterations)
	return nil
}

func isKnownResponseCode(raw []byte) bool {
	if len(raw) < 1 {
		return false
	}
	switch raw[0] {
	case 2, 3, 11: // Access-Accept, Access-Reject, Access-Challenge
		return true
	default:
		return false
	}
}

func decodeRespCodeSummary(raw []byte) string {
	if len(raw) < 4 {
		return fmt.Sprintf("<short response, %d bytes>", len(raw))
	}
	length := int(raw[2])<<8 | int(raw[3])
	return fmt.Sprintf("code=%d len=%d(declared)/%d(actual)", raw[0], length, len(raw))
}

// exchangeRaw sends raw bytes over UDP to addr and waits for a single
// response datagram, honoring both ctx and an explicit timeout.
func exchangeRaw(ctx context.Context, addr string, raw []byte, timeout time.Duration) ([]byte, time.Duration, error) {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, 0, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, 0, fmt.Errorf("set deadline: %w", err)
	}

	start := time.Now()
	if _, err := conn.Write(raw); err != nil {
		return nil, 0, fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	rtt := time.Since(start)
	if err != nil {
		return nil, rtt, fmt.Errorf("read: %w", err)
	}
	return buf[:n], rtt, nil
}
