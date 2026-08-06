# RADIUS RFC 2865 Lab (Server First)

This module is a guided lab for implementing a RADIUS authentication server and client in Go.

## Current Focus
- Build server first.
- RFC 2865 authentication flow (Access-Request, Access-Accept, Access-Reject).
- PAP validation with in-memory users.

## Suggested Run Target
- Server UDP port: 1812

## Learning Rule
- Implement each TODO yourself first.
- Use review feedback after each attempt.

### Protocol RFC 2865
Каждое сообщение RADIUS — это самодостаточная датаграмма (Binary Datagram), содержащая 20-байтовый заголовок фиксированного размера и набор атрибутов переменной длины.
Заголовок состоящий из:
Code (1 байт / 8 бит): Access-Request, Access-Accept, Access-Reject [см](https://datatracker.ietf.org/doc/html/rfc2865#section-3)
Identifier (1 байт / 8 бит): Сквозной ID запроса (от 0 до 255). Так как UDP не гарантирует порядок и сопоставление, клиент (NAS) ставит этот ID, а сервер ОБЯЗАН вернуть тот же самый ID в ответе (Accept, Reject или Challenge). По нему NAS понимает, на какой именно запрос пришел ответ.
Length (2 байта / 16 бит): Полная длина RADIUS-пакета в байтах (включая заголовок Code+Identifier+Length+Authenticator и все атрибуты).
Authenticator (16 байт / 128 бит): если это запрос от NAS то указывается Request Authenticator: Случайное 16-байтовое число (Salt), генерируемое клиентом (NAS). Используется как соль для шифрования паролей (например, User-Password маскируется через MD5 с использованием Shared Secret и этого Authenticator).
Если это ответ то Response Authenticator, где передается хеш MD5 от комбинации [Code + Identifier + Length + Request Authenticator + Attributes + Shared Secret]. Гарантирует NAS, что ответ пришел именно от того сервера, у которого есть такой же Shared Secret, и что пакет не подменили по дороге.

После 20-байтового заголовка идут атрибуты — пары «ключ-значение», упакованные в стандартную TLV-структуру:
Type (1 байт): Номер атрибута (например: 1 = User-Name, 2 = User-Password, 4 = NAS-IP-Address).
Length (1 байт): Общая длина этого атрибута (Type + Length + Value).
Value (от 0 до 253 байт): Полезная нагрузка указанная из типа (строка, IP-адрес, число, бинарные данные).

```
Клиент (NAS)                                RADIUS Сервер
    |                                            |
    | ------ 1. Access-Request (ID: 42) -------->|  (Проверка логина/пароля)
    | <----- 11. Access-Challenge (ID: 42) ----- |  (Запрос OTP / MFA)
    |                                            |
    | ------ 1. Access-Request (ID: 43) -------->|  (Отправка OTP + State)
    | <----- 2. Access-Accept (ID: 43) --------- |  (Доступ разрешен + VLAN)
    |                                            |
    | === Сессия открыта (Пользователь в сети) ==|
    |                                            |
    | ------ 4. Accounting-Request (Start) ----->|  (Запись начала сессии)
    | <----- 5. Accounting-Response ------------ |
    |                                            |
    | ------ 4. Accounting-Request (Stop) ------>|  (Сессия закрыта: 150 MB)
    | <----- 5. Accounting-Response ------------ |
```

Что дальше
> Динамическая авторизация — CoA и Disconnect (RFC 3576 / RFC 5176). Суть: Раньше RADIUS-сервер был пассивным: он только отвечал на запросы NAS. RFC ввел CoA (Change of Authorization) и Disconnect Messages. Теперь RADIUS-сервер сам может отправить на NAS пакет: "Сбрось этого пользователя прямо сейчас" (Disconnect-Request) или "Поменяй ему VLAN/скорость на лету" (CoA-Request)
> Переход на EAP и защита от подделки (RFC 3579). Суть: Отказ от передачи открытых/маскированных MD5 паролей в пользу EAP (Extensible Authentication Protocol).
> RadSec: RADIUS over TLS / DTLS (RFC 6614). Суть: Завернуть весь RADIUS-трафик в безопасный туннель (TLS по TCP или DTLS по UDP).
> Diameter: Наследник нового поколения (RFC 3588 / RFC 6733). Суть: Полный отказ от RADIUS в пользу переработанного с нуля протокола (Diameter = «в два раза больше, чем Radius»).