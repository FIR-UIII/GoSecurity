// TOPIC: Type Confusion via unsafe.Pointer
// CWE-843: Access of Resource Using Incompatible Type
//
// unsafe.Pointer disables Go's type system entirely: any pointer can be cast
// to any other pointer type. An attacker with the ability to write to or
// reinterpret memory can change a program's logical state — e.g. flip IsAdmin —
// without ever calling a setter or triggering a bounds check.
//
// Run: go run ./01_type_confusion/

package main

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"unsafe"
)

// ── ANTI-PATTERNS ─────────────────────────────────────────────────────────────

type User struct {
	IsAdmin bool  // offset 0  (1 byte + 7 bytes padding on 64-bit)
	ID      int64 // offset 8
}

// antipatternPrivilegeEscalation rewrites the IsAdmin field by treating the
// struct as a raw byte array. No accessor, no validation — pure memory write.
// Same technique used in deserialization exploits and memory-corruption bugs.
func antipatternPrivilegeEscalation() {
	u := User{IsAdmin: false, ID: 42}
	fmt.Printf("Case 1 | `u` before: %v\n", u)

	// unsafe.Slice находит через unsafe.Pointer адрес структуры u
	// Важно что это тот же адрес что и &u, но теперь Go не знает что это структура User,
	// и позволяет работать с ней как с массивом байтов.
	// unsafe.Sizeof(u) возвращает размер структуры User в байтах (16 на 64-битной системе),
	// и создает срез байтов длиной sizeof(u) (16 байт на 64-битной системе).
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&u)), unsafe.Sizeof(u))
	fmt.Printf("Case 1 | `u` raw before: %v\n", raw)
	// raw теперь указывает на первые 16 байт структуры u, и мы можем изменять их напрямую.
	// допуская что raw это какая то логика которая как то получает пользовательский ввод
	raw[0] = 0x01 // byte 0 is IsAdmin; flip it from false→true

	fmt.Printf("Case 1 | `u` after: %v\n", u)
	fmt.Printf("Case 1 | `u` raw after: %v\n", raw)
}

// antipatternUintptrDangling converts a pointer to uintptr across statements.
// uintptr is just an integer — the GC does NOT treat it as a live reference.
// Go's GC is non-moving, so the address stored in base won't change.
// But once no *Pair pointer exists, the GC is free to FREE (collect) the object.
// base then points to freed memory — a dangling pointer.
//
// Rule: never store uintptr across statements; the conversion MUST stay in one
// expression passed directly to unsafe.Pointer.
// antipatternUintptrDanglingProven is the same bug, but with a finalizer as a
// GC witness so you can *see* the collection happen while base is still held.
func antipatternUintptrDangling() {
	type Pair struct{ A, B int64 }
	type Replacement struct{ A, B int64 }

	p := &Pair{A: 100, B: 200}
	base := uintptr(unsafe.Pointer(p))
	fmt.Printf("Case 2 | `p` before 0x%x  with values A=%d B=%d\n", base, p.A, p.B)

	// Финализатор — свидетель GC: срабатывает ровно когда объект освобождается.
	var collected int32
	runtime.SetFinalizer(p, func(*Pair) {
		atomic.StoreInt32(&collected, 1)
	})

	// Убираем единственную Go-ссылку — теперь *p недостижим для GC.
	p = nil
	runtime.GC()      // первый проход: помечает *p недостижимым, ставит финализатор в очередь
	runtime.Gosched() // даём горутине финализатора выполниться
	runtime.GC()      // второй проход: финализатор выполнен, объект больше не защищён finalizer'ом
	runtime.Gosched()

	if atomic.LoadInt32(&collected) == 1 {
		fmt.Printf("Case 2 | *p по адресу 0x%x освобождён GC, base — висячий указатель!\n", base)
	} else {
		fmt.Println("Case 2 | финализатор ещё не сработал (попробуй запустить ещё раз)")
	}

	for i := 0; i < 10000000; i++ {
		x := &Pair{
			A: int64(i),
			B: 0xDEADBEEF,
		}
		runtime.KeepAlive(x)
	}

	// Значение может всё ещё быть 200.
	// Это не делает доступ безопасным: память уже не принадлежит живому Pair
	// и может быть переиспользована allocator'ом.
	bVal := *(*int64)(unsafe.Pointer(base + 8))
	fmt.Printf("Case 2 | base+8 после GC: %d  (ожидалось 200 — теперь мусор или 0)\n", bVal)
}

func main() {
	antipatternPrivilegeEscalation()
	fmt.Println("======")
	antipatternUintptrDangling()
	fmt.Println("======")
}
