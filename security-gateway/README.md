сервис-прокси перед backend, который:
валидирует JWT (подпись, exp, aud, iss)
делает rate limiting по IP/пользователю
проверяет входные JSON по schema
фильтрует простые атаки (SQLi/XSS patterns, path traversal)
ведет audit-логи с correlation id
добавляет security headers и mTLS для внутренних вызовов