### Настройка
```
go env [-json] [var ...]

```

### Переменные
```go
var i int // обьявление переменной и типа без присвоения
var i, j int = 1, 2 // обьявление переменной с указанием типа и присвоением
i := 4 // := заменяется var для обьявления переменной. Go автоматически попытается угадать тип
x = 4 // если переменная была обьявлена и тип был ранее указан и присваиванием значения. Иначе undefined
var ( // множественное присваивание и объявление
	ToBe   bool       = false
	MaxInt uint64     = 1<<64 - 1
)
```

### Типы 
```go
bool
string
int  int8  int16  int32  int64
uint uint8 uint16 uint32 uint64 uintptr
byte // alias for uint8
rune // alias for int32
     // represents a Unicode code point
float32 float64
complex64 complex128
```
### Packages amd import
```go
package main

import "fmt"
// Or multiple 
import (
	"fmt"
	"time"
	"math/rand" // импортируется файл с package rand внутри библиотеки math
)

// функция НАЗВАНИЕ(АРГ1_вход, АРГ2_вход, ... ТИП_вход) ТИП_выхода {тело функции}
func add(x, y int) int {
	return x + y
}

// функция НАЗВАНИЕ(АРГ_вход ТИП_вход) (АРГ1_выход, АРГ2_выход ТИП_выхода) {тело функции}
func split(sum int) (x, y int) {
	x = sum * 4 / 9
	y = sum - x
	return
}

// точка входа в программу - обязательный параметр
func main() {
	fmt.Println(add(42, 13))
	fmt.Println(split(17))
}
```