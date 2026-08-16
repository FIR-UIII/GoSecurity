Клиент/фаззер для тестирования RADIUS сервера.

Каждый обмен пакетами логируется в консоль: сырые байты (hex) и разобранная
структура (код, id, длина, authenticator, список атрибутов), в стиле:

```
raw RADIUS packet to server (43 bytes):
0186002b996465612f9e31c504089099aa86e8aa01056172740212e11e89d7f43e5dc1e297c51225f9eda9
decoded:
  code      = Access-Request
  id        = 134
  len       = 43
  authenticator= 996465612f9e31c504089099aa86e8aa
  \attributes\
   |###[ User-Name ]###
   |  type      = User-Name
   |  len       = 5
   |  value     = b'art'
   |###[ User-Password ]###
   |  type      = User-Password
   |  len       = 18
   |  value     = e11e89d7f43e5dc1e297c51225f9eda9
```

## Режимы (`-mode`)

- `pap` — один Access-Request с User-Password (PAP).
- `eap-md5` — двухраундовый обмен EAP-MD5.
- `raw` — полностью кастомный пакет: код и произвольный набор атрибутов
  задаются флагами `-code` и `-attr` (удобно для проверки одной гипотезы).
- `fuzz` — многократная отправка мутированных пакетов на основе базового
  (`pap` или `attrs`), с логированием только "интересных" случаев (ошибка/
  таймаут/неожиданный код ответа), либо всех — при `-fuzz-verbose`.

```
# позитивный тест
go run ./client/cmd -addr localhost:1812 -secret MyRadiusSecret123 -user art -pass 12345 -expect accept -mode pap

# негативный тест (неверный пароль)
go run ./client/cmd -addr localhost:1812 -secret MyRadiusSecret123 -user art -pass wrong -expect reject -mode pap

# ручное конструирование пакета: тип атрибута, вид значения и (опционально) поддельная длина
#   -attr "<type>=<kind>:<value>[;len=N]", kind: str | int | ip | hex | pwd
go run ./client/cmd -mode raw -addr localhost:1812 -secret MyRadiusSecret123 \
  -code Access-Request \
  -attr "User-Name=str:art" \
  -attr "User-Password=pwd:12345" \
  -attr "5=int:1" \
  -expect accept

# фаззинг: 500 мутаций базового PAP-пакета (битфлипы, поддельные длины,
# дублирующиеся/неизвестные атрибуты, кривая общая длина пакета и т.д.)
go run ./client/cmd -mode fuzz -addr localhost:1812 -secret mysecret \
  -user art -pass 12345 -fuzz-base pap -fuzz-iterations 500 -fuzz-seed 1

# фаззинг произвольного набора атрибутов, заданного через -attr
go run ./client/cmd -mode fuzz -addr localhost:1812 -secret MyRadiusSecret123 \
  -fuzz-base attrs -code Access-Request \
  -attr "User-Name=str:art" -attr "User-Password=pwd:12345" \
  -fuzz-iterations 200 -fuzz-verbose
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