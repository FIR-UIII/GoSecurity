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

curl "http://localhost:8080/15/unsafe-placeholders?name=%27%20OR%20%271%27=%271
curl "http://localhost:8080/15/safe-placeholders?name=alice&role=user"

curl "http://localhost:8080/16/unsafe-table?table=resource_config_versions&scope_id=scope-1&version=v1"
curl "http://localhost:8080/16/safe-table?table=resource_config_versions&scope_id=scope-1&version=v1"

curl -G \
  --data-urlencode 'table=users (users, version) VALUES ($1, $2); DROP TABLE users;--' \
  --data-urlencode 'scope_id=scope-1' \
  --data-urlencode 'version=v1' \
  "http://localhost:8080/16/unsafe-table"