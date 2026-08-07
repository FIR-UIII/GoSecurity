Клиент для тестирования RADIUS сервера

```
# позитивный тест
go run client.go -addr 10.0.0.1:1812 -secret mysecret -user art -pass 12345 -expect accept -mode pap

# негативный тест (неверный пароль)
go run client.go -addr 10.0.0.1:1812 -secret mysecret -user art -pass wrong -expect reject -mode pap
```

Сервер для тестирования
```bash
docker run -it --rm \
  --name freeradius \
  --platform linux/amd64 \
  -p 1812:1812/udp \
  -p 1813:1813/udp \
  -v "$(pwd)/client/cmd/.raddb/clients.conf:/etc/freeradius/clients.conf:ro" \
  -v "$(pwd)/client/cmd/.raddb/authorize:/etc/freeradius/mods-config/files/authorize:ro" \
  freeradius/freeradius-server:latest -X
```