№1 нужно чтобы при ответе 
2026/09/23 13:05:02 [packet] response 38 bytes: 03ca002666afa67932210cc79e07e98ad608c09150129f138c890217d41ed6eb005cba3034ea
2026/09/23 13:05:02 [packet] parsed response attributes: [{80 [159 19 140 137 2 23 212 30 214 235 0 92 186 48 52 234]}]

в лог выводилась информация в виде
2026/09/23 13:05:02 [packet] parsed response: 
code: 03
Identifier: ca
Length: 0026
Response Authenticator: 66afa67932210cc79e07e98ad608c091
Attributes: 
  type: State, len: 50; value: 32333362633235642d336164372d343036662d393662322d3262343936663665356335613a42335554326f6454774e77
  type: Reply-Message, value: 54; value: ...
  type: Prompt, len: 6l value: ...
  и так далее

====
№ 2 Когда отправляем запрос на DoS или ломаем логику сервера то нужно добавить новый ожидаемый ответ. Например проверка на buffer underflow
  - name: "Поле Authenticator меньше 16 байт (15 байт)"
    type: raw
    packet_hex: "0C3B002B000102030405060708090A0B0C0D0E04067F000001501200000000000000000000000000000000"
    response: Reject

Но в логах видим:
2026/09/23 14:09:00 [scenario "Поле Authenticator меньше 16 байт (15 байт)"] FAILED: network: read error: read udp 10.124.177.51:49530->10.126.120.208:1812: i/o timeout
2026/09/23 14:09:00 [summary] 1 scenario(s): 0 ok, 1 failed
2026/09/23 14:09:00 one or more scenarios failed: 1 of 1 scenario(s) failed

Нужно изменить логику если происходит таймаут - то в сценарии так и должно быть 
  - name: "Поле Authenticator меньше 16 байт (15 байт)"
    type: raw
    packet_hex: "0C3B002B000102030405060708090A0B0C0D0E04067F000001501200000000000000000000000000000000"
    response: Timeout

===
убрать из приложения otp fuzz