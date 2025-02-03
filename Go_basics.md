### Основные команды
```bash
$ go env [-json] [var ...] # GOROOT (расположение исполняемого go) и GOPATH (местоположение рабочего пространства проекта)
tree $GOPATH
	|_ bin - содержит скомпилированные и установленные исполняемые файлы Go
	|_ pkg - содержит пакеты, включая сторонние зависимости Go
	|_ src - содержит весь исходный код, который мы создаем
$ go run [main.go] # запустить программу (компилирует и выполняет основной пакет в $GOPATH/src)
$ go build [main.go] # скомпилировать программу
$ go build -ldflags "-w -s" [main.go] # убрать отладочную информацию и таблицу символов при сборке - сократить размер на 30% размер файла

$ go install github.com/stacktitan/ldapauth # скачать внешний пакет в $GOPATH/src pip install
$ go doc fmt.Println # документация по пакетам

$ go fmt /path/to/your/package # форматирование под синтаксис и стилистику go
$ golint
$ go vet

# Кросскомпиляция (под разные архитектуры и ОС)
$ GOOS="linux" GOARCH="amd64" go build hello.go # скомпилировать ранее собранную программу для amd64 linux
$ ls
hello hello.go
$ file hello
hello: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
```

### Переменные
```go
// способ 1. обьявление с указанием типа и присвоением
var i = int(3) // ИЛИ
var i, j int = 1, 2

// способ 2. обьявление переменной и типа без присвоения
var i int
	i = 3 

// способ 3. автоматическое объявение с присвоением
i := 4 

// способ 4. множественное присваивание и объявление
var ( 
	ToBe   bool       = false
	MaxInt uint64     = 1<<64 - 1
)

const Pi = 3.14 // константы обьявляются через = 
```

### Типы переменных
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

### Типы данных
```go
// Массив (array) - коллекция фиксированного размера. USE: всегда фиксированная длина. 
// НАЗВАНИЕ := [ДЛИНА]ТИП{АРГ, АРГ ...}
arr := [4]int{3, 2, 5, 4} // массив из четырех целых значений. Нет ссылок, но можно использовать указатели. Присвоение = создаст новую ячейку в памяти

// Срез (slice) - последовательность элементов одного типа переменной длины. USE: добавить или из которой удалить элементы, не знаем размер, нужно часто менять
// PY: список string = [0]
// НАЗВАНИЕ := []ТИП{АРГ, АРГ ...}
var slice1 = []int{6, 1, 2} // длина всегда пустая 
slice2 := []int{6, 1, 2} 

// Карты (map) - ассоциативный массив или хеш-таблица. USE: обработка неструктурированных данных. PY: словарь dict = {}
// НАЗВАНИЕ := map[ТИП_КЛЮЧА]ТИП_ЗНАЧЕНИЙ{"КЛЮЧ": "ЗНАЧЕНИЕ", ...}
ages := make(map[string]int)

ages := map[string]int{
    "Alice": 25, 
    "Bob":   30,
    "John":   60,
}

// Произвольный тип
type Person struct { // определяет новую структуру, содержащую два поля: string с именем Name и int с именем Age
	Name string
	Age int
}

// Указатели, структуры и интерфейсы
var count = int(42)
ptr := &count // & создает указатель
fmt.Println(*ptr) // выводим адрес переменной
*ptr = 100 // присваивается новое значение в RAM
fmt.Println(count) // выводим адрес переменной
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
	return // допускается пустой возврат если вначале указывается аргумент и тип выхода
}

// точка входа в программу - обязательный параметр
func main() {
	fmt.Println(add(42, 13))
	fmt.Println(split(17)) // https://pkg.go.dev/fmt
	fmt.Printf("%v", s)
}
```

### Iteration
```go
var s, sep string // обьявление переменных, до выполнения итерации
for i := 0; i < 10; i += 1 { // for УСЛОВИЕ_CТАРТА; УСЛОВИЕ_вначале_каждого_цикла - обязательно; УСЛОВИЕ_в_конце_каждого_цикла  
	sum += i // делать на каждой итерации
}

nums := []int{2,4,6,8} // инициализируем срез целых чисел nums
for idx, val := range nums { // перебора среза по длине (range) по индексу(idx) и значению(val). Если idx не нужно - можно заменить на _
	fmt.Println(idx, val)
}
```

### Condition
```go
// IF - ELSE
func sqrt(x float64) string {
	if x < 0 {
		return sqrt(-x) + "i"
	} else {
	fmt.Println("X > 0")
}
	return fmt.Sprint(math.Sqrt(x))
} 
```

### Многопоточность
```go
func f() {
	fmt.Println("f function")
}

func main() {
	go f()
	time.Sleep(1 * time.Second)
	fmt.Println("main function")
}
```

### Обработка ошибок
```go
// в Go нет синтаксиса для обработки ошибок try/catch/finally
type error interface {
	Error() string
}
```