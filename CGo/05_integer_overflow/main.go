// TOPIC: Integer Overflow → Unsafe Memory Access
// CWE-190: Integer Overflow | CWE-680: Integer Overflow to Buffer Overflow
//
// unsafe.Slice(ptr, n) trusts n completely. If n comes from attacker-controlled
// input without validation, three classes of bugs arise:
//
//  1. Negative n      → runtime panic (unsafe.Slice rejects negative length)
//  2. n > real alloc  → the slice lies about its bounds; iterating it reads
//                        unowned heap memory (info-leak / arbitrary read)
//  3. int32→uint32    → int32(-1) becomes uint32(4294967295); passing that to
//                        make() or malloc() triggers an OOM or huge allocation
//
// Run: go run ./05_integer_overflow/

package main

import (
	"errors"
	"fmt"
	"math"
	"unsafe"
)

// ── ANTI-PATTERNS ─────────────────────────────────────────────────────────────

// antipatternUnsafeSliceNoValidation passes userLen directly to unsafe.Slice.
// If userLen is negative, Go panics. If it exceeds the allocation, the slice
// covers unowned memory — reads leak adjacent heap data.
//
// We guard the actual call to avoid a crash in the demo, but the real code
// vulnerability is the missing validation before the unsafe.Slice call.
func antipatternUnsafeSliceNoValidation(buf []byte, userLen int) {
	fmt.Printf("ANTI-PATTERN | buf len=%d, attacker-supplied len=%d\n", len(buf), userLen)

	if userLen < 0 {
		fmt.Printf("ANTI-PATTERN | unsafe.Slice(&buf[0], %d) → runtime panic: negative length\n", userLen)
		return
	}
	if userLen > len(buf) {
		fmt.Printf("ANTI-PATTERN | unsafe.Slice(&buf[0], %d) → slice spans %d unowned bytes\n",
			userLen, userLen-len(buf))
		fmt.Println("ANTI-PATTERN | ↳ iterating it leaks adjacent heap contents (skipping actual call)")
		return
	}
	// Reachable only when userLen is in bounds — safe by coincidence, not design.
	safe := unsafe.Slice(&buf[0], userLen)
	fmt.Printf("ANTI-PATTERN | (happened to be safe this run): %v\n", safe)
}

// antipatternSignedToUnsigned shows two patterns:
// 1. Direct signed→unsigned widening wraps negative values to huge numbers.
// 2. A "naive fix" that resets to 0 and silently continues is also wrong.
func antipatternSignedToUnsigned() {
	var wireLen int32 = -1 // attacker-controlled wire field

	// WRONG: widening int32 to uint32 without validating sign first.
	// int32(-1) in two's complement is 0xFFFFFFFF → uint32(4294967295).
	allocSize := uint32(wireLen)
	fmt.Printf("ANTI-PATTERN | int32(-1) → uint32 = %d  (≈4 GB — OOM or huge slice)\n", allocSize)

	// Also wrong: "fixing" by resetting to 0 and continuing.
	// 0-length allocation silently produces an empty buffer that will be read.
	if wireLen < 0 {
		wireLen = 0 // BUG: should return an error, not silently continue
	}
	fmt.Printf("ANTI-PATTERN | naïve reset to 0 then continues — allocates %d bytes (empty, still wrong)\n", wireLen)
}

// antipatternLengthFromMultiplication shows integer overflow before allocation.
// rows=100000, cols=100000 → rows*cols overflows int32 → small/negative size.
func antipatternLengthFromMultiplication() {
	var rows, cols int32 = 100_000, 100_000
	total := rows * cols // overflows int32! wraps to 1410065408 or negative
	fmt.Printf("ANTI-PATTERN | int32(100000)*int32(100000) = %d (overflowed! expected %d)\n",
		total, int64(rows)*int64(cols))
	// make([]byte, total) allocates far less than a 100k×100k matrix needs.
}

// ── SAFE ALTERNATIVES ─────────────────────────────────────────────────────────

// safeSliceFromUserLen validates every precondition before touching unsafe.
func safeSliceFromUserLen(buf []byte, userLen int) ([]byte, error) {
	if userLen < 0 {
		return nil, fmt.Errorf("length must be ≥ 0, got %d", userLen)
	}
	if userLen > len(buf) {
		return nil, fmt.Errorf("length %d exceeds buffer size %d", userLen, len(buf))
	}
	// Safe: no unsafe needed at all — regular slice expression has runtime bounds check.
	return buf[:userLen], nil
}

// safeMultiplyForAllocation uses int64 arithmetic and checks for overflow
// before converting back to int for make().
func safeMultiplyForAllocation(rows, cols int) ([]byte, error) {
	if rows <= 0 || cols <= 0 {
		return nil, errors.New("dimensions must be positive")
	}
	// Perform the multiplication in int64 to prevent int32/int overflow.
	total64 := int64(rows) * int64(cols)
	if total64 > math.MaxInt32 { // or whatever your practical limit is
		return nil, fmt.Errorf("allocation %d exceeds limit", total64)
	}
	buf := make([]byte, int(total64))
	return buf, nil
}

func main() {
	fmt.Println("=== 05: Integer Overflow → Unsafe Memory Access ===")
	fmt.Println()

	buf := make([]byte, 16)
	for i := range buf {
		buf[i] = byte(i + 1)
	}

	antipatternUnsafeSliceNoValidation(buf, -1)
	antipatternUnsafeSliceNoValidation(buf, 1<<20)
	antipatternUnsafeSliceNoValidation(buf, 8) // "works" by luck
	antipatternSignedToUnsigned()
	antipatternLengthFromMultiplication()
	fmt.Println()

	if sl, err := safeSliceFromUserLen(buf, -1); err != nil {
		fmt.Println("SAFE         | rejected:", err)
	} else {
		_ = sl
	}
	if sl, err := safeSliceFromUserLen(buf, 1<<20); err != nil {
		fmt.Println("SAFE         | rejected:", err)
	} else {
		_ = sl
	}
	if sl, err := safeSliceFromUserLen(buf, 8); err != nil {
		fmt.Println("SAFE         | rejected:", err)
	} else {
		fmt.Printf("SAFE         | valid slice: %v\n", sl)
	}

	if _, err := safeMultiplyForAllocation(100_000, 100_000); err != nil {
		fmt.Println("SAFE         | allocation rejected:", err)
	}
	if b, err := safeMultiplyForAllocation(10, 10); err == nil {
		fmt.Printf("SAFE         | 10×10 allocation OK, len=%d\n", len(b))
	}
}
