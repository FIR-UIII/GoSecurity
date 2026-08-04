# Code review 
Understand the code structure;
    > https://go.dev/doc/tutorial/add-a-test
Use static analysis tools to check for relevant warnings and low-hanging fruits;
    > docker run --rm -v "${PWD}:/src" returntocorp/semgrep --config 'p/golang'
    > $ gosec ./...
    > $ govulncheck ./...
Map the Go modules usage
    > $ cat  go.mod
Dive into the module’s code;
Searching for Vulnerabilities Inside the Modules;
Analyze sources and sinks, from the application to the modules.

# Playground
https://github.com/0c34/govwa

# Поиск и устранение уязвимостей
```go
// Install GoSec
$ go install github.com/securego/gosec/v2/cmd/gosec@latest
// Run GoSec
$ gosec ./...

// Install govulncheck
$ go install golang.org/x/vuln/cmd/govulncheck@latest
// Run govulncheck
$ govulncheck ./...

// Install staticcheck
$ go install honnef.co/go/tools/cmd/staticcheck@latest
$ staticcheck ./..
```

# Сборка исходного файла
```go
// Потенциальные риски go get
* Автоматическая загрузка кода из интернета
* Вы не контролируете, какой именно код будет скачан.
* Если злоумышленник захватил репозиторий или домен, он может подменить пакет.
* Отсутствие проверки целостности (до Go 1.13)
* Ранние версии Go не проверяли контрольные суммы модулей. Сейчас используется checksum database (sum.golang.org), но его доступность зависит от сети.
* Не используется централизованный подход через go.mod и go.sum

// Лучшие практики безопасности при сборке проекта на Go
go mod tidy
go build
Избегайте установки бинарников через go get .... Лучше go install pkg@version
```
