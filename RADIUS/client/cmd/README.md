Клиент для тестирования RADIUS сервера

```
# позитивный тест
go run client.go -addr 10.0.0.1:1812 -secret mysecret -user art -pass 12345 -expect accept -mode pap

# негативный тест (неверный пароль)
go run client.go -addr 10.0.0.1:1812 -secret mysecret -user art -pass wrong -expect reject -mode pap
```