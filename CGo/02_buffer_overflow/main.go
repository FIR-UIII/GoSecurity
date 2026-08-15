// TOPIC: Heap Over-Read / Over-Write via unsafe.Slice
// CWE-125: Out-of-Bounds Read | CWE-787: Out-of-bounds Write
//
// unsafe.Slice(ptr, n) creates a slice of length n starting at ptr.
// The Go runtime trusts n completely — it does NOT verify that n bytes
// were actually allocated. This is the same primitive that made
// Heartbleed (CVE-2014-0160) possible: read more than was written.
//
// Run: go run ./02_buffer_overflow/

package main

import (
	"fmt"
	"unsafe"
)

// ── ANTI-PATTERNS ─────────────────────────────────────────────────────────────

// Two adjacent fields in a struct are guaranteed contiguous in memory.
// This lets us show a safe, reproducible over-read/write demo.
type HeapBlock struct {
	User  [8]byte // only this region belongs to the "user"
	Admin [8]byte // adjacent — attacker should NOT reach this
}

// antipatternHeapOverread creates a slice that claims to span both User and Admin,
// then reads Admin bytes the "user" was never supposed to see.
// Pattern: Heartbleed — server returns more bytes than the request payload.
func antipatternHeapOverread() {
	block := &HeapBlock{}
	fmt.Printf("sizeof(HeapBlock) = %d bytes\n", unsafe.Sizeof(*block))
	copy(block.User[:], "USERDATA")
	copy(block.Admin[:], "ADMINKEY") // secret adjacent data

	fmt.Printf("Legitimate view  → User:  %q\n", block.User)

	// unsafe.Slice says "there are 16 bytes starting here" — Go believes it.
	// The extra 8 bytes read belong to block.Admin (unowned by the user).
	leak := unsafe.Slice(&block.User[0], unsafe.Sizeof(*block)) // 16 bytes
	fmt.Printf("size of leak slice = %d bytes\n", unsafe.Sizeof(leak))
	fmt.Printf("leak value: %q\n", string(leak[:]))
}

// antipatternHeapOverwrite extends a write slice past the user's buffer
// and corrupts the adjacent Admin field.
// Pattern: stack/heap buffer overflow — overwrites control data next to the buffer.
func antipatternHeapOverwrite() {
	block := &HeapBlock{}
	copy(block.User[:], "USERDATA")
	copy(block.Admin[:], "ADMINKEY")

	fmt.Printf("ANTI-PATTERN | Before overflow → Admin: %q\n", block.Admin)

	// Attacker-controlled write goes 8 bytes past the end of block.User.
	overflow := unsafe.Slice(&block.User[0], unsafe.Sizeof(*block))
	overflow[8] = 'X' // writes into block.Admin[0]
	overflow[9] = 'X' // writes into block.Admin[1]

	fmt.Printf("ANTI-PATTERN | After  overflow → Admin: %q ← corrupted!\n", block.Admin)
}

// ── SAFE ALTERNATIVES ─────────────────────────────────────────────────────────

func safeSliceAccess() {
	buf := make([]byte, 8)
	copy(buf, "USERDATA")

	// Go's built-in slicing is bounds-checked at runtime.
	// buf[:16] would panic: "runtime error: slice bounds out of range".
	requestedLen := 16
	if requestedLen > len(buf) {
		fmt.Printf("SAFE         | Requested %d bytes from %d-byte buf — rejected\n",
			requestedLen, len(buf))
		return
	}
	fmt.Printf("SAFE         | Read %d bytes: %q\n", requestedLen, buf[:requestedLen])
}

func safeCopy() {
	src := []byte("ADMINKEY — secret!")
	dst := make([]byte, 4) // destination is smaller than source

	// copy never writes more than min(len(dst), len(src)) — no overflow possible.
	n := copy(dst, src)
	fmt.Printf("SAFE         | copy wrote %d bytes into 4-byte dst: %q\n", n, dst)
}

func safeUnsafeSliceWithValidation(base []byte, requestedLen int) {
	if len(base) == 0 {
		fmt.Println("SAFE         | nil/empty base — rejected")
		return
	}
	if requestedLen < 0 || requestedLen > len(base) {
		fmt.Printf("SAFE         | requestedLen=%d exceeds base len=%d — rejected\n",
			requestedLen, len(base))
		return
	}
	// unsafe.Slice is only safe after the length is proven within bounds.
	view := unsafe.Slice(&base[0], requestedLen)
	fmt.Printf("SAFE         | unsafe.Slice after validation (len=%d): %q\n", requestedLen, view)
}

func main() {
	fmt.Println("=== 02: Buffer Overflow / Out-of-Bounds Access ===")
	fmt.Println("Case 1 | Heap over-read (Heartbleed-style)")

	antipatternHeapOverread()
	fmt.Println()
	antipatternHeapOverwrite()
	fmt.Println("Case 2 | Safe slice access and copy with validation")

	safeSliceAccess()
	safeCopy()
	safeUnsafeSliceWithValidation([]byte("USERDATA"), 16) // rejected
	safeUnsafeSliceWithValidation([]byte("USERDATA"), 4)  // accepted
}
