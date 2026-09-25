1) убрать ошибку
при запуске клиента без флагов - нужно вывести ошибку и пример запуска приложения.
Сейчас поведение: 
PS> .\client.exe 
panic: unknown mode: eap-md5

goroutine 1 [running]:
main.main()
        C:/Users/Admin/Desktop/Project/GoSecurity/RADIUS/client/v2/main.go:52 +0x445


2) выводить [packet] parsed response только когда еть флаг -v. применить такой выводит не только для packet но и для raw, fuzz, challange

2026/09/25 09:38:13 [packet] sending 99 bytes: 017b0063000102030405060708090a0b0c0d0e0c010e72616473656374657374303102120fda014cd6d5c9092c06695c391e736a201d52414449555374657374696e673a726164697573736563746573745012dd57c64303d1705287d63e054d331833
2026/09/25 09:38:13 [packet] response 62 bytes: 037b003eb365c367a77dffd0123821c4b0860674121857726f6e672070617373776f7264206f72204f54502e5012183ad16b71b8870f6448300cb7f47e55
2026/09/25 09:38:13 [packet] parsed response:
code: 03 (Access-Reject)
Identifier: 7b
Length: 003e
Response Authenticator: b365c367a77dffd0123821c4b0860674
Attributes:
  type: Reply-Message, len: 24, value: 57726f6e672070617373776f7264206f72204f54502e ("Wrong password or OTP.")
  type: Message-Authenticator, len: 18, value: 183ad16b71b8870f6448300cb7f47e55

3) измениь логику mutateMarkedRange - убрать from to а сделать указание файла откуда будут браться значения.
Пример ожидаемого поведения
  - name: "radius-password-otp-auth-flow - negative: password injection + valid otp"
    type: fuzz
    code: Access-Request
    authenticator: "000102030405060708090a0b0c0d0e0c"
    attrs:
      - type: User-Name
        value: "radsectest01"
      - type: User-Password
        value: "<FUZZ>654491"
      - type: NAS-Identifier
        value: "RADIUStesting:radiussectest"
      - type: Message-Authenticator
    response: Access-Reject
    fuzzlist: /list.txt

А лист /list.txt содержит каждое значение с новой строки (пример):
'or
/xx
<script>

По итогу в value: "<FUZZ>654491" значение становится в value: "'or654491" для первого запроса