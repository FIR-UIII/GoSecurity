'use strict';

// =============================================================================
// Node.js SQL injection lab
// -----------------------------------------------------------------------------
// Один файл. Поднимает HTTP-сервер и отдаёт пары эндпоинтов:
//   /unsafe-...  — уязвимый вариант (можно проэксплуатировать)
//   /safe-...    — тот же сценарий, но без инъекции
//
// Ядро работает на встроенном драйвере `node:sqlite` (Node >= 22.5, стабильно
// с Node 24). Внешних зависимостей не требует.
//
// Дополнительно, ЕСЛИ установлены `knex` и/или `sequelize`, включаются секции
// с query builder и ORM (там свои неочевидные инъекции). Без установки эти
// роуты просто отвечают 503 с подсказкой.
//
//   node server.js                 # запуск
//   npm install                    # чтобы включить knex + sequelize секции
//
// Открыть http://localhost:3000/  — там список всех сценариев с примерами.
// GET /reset  — пересоздать и перезаполнить все БД (после DROP TABLE и т.п.).
// =============================================================================

const http = require('node:http');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;

// -----------------------------------------------------------------------------
// Опциональные модули
// -----------------------------------------------------------------------------

let KnexFactory = null;
let SequelizeLib = null;
try { KnexFactory = require('knex'); } catch { /* не установлен */ }
try { SequelizeLib = require('sequelize'); } catch { /* не установлен */ }

// -----------------------------------------------------------------------------
// Хранилища
// -----------------------------------------------------------------------------

const rawDb = new DatabaseSync(':memory:');

let knex = null;              // экземпляр knex
let sequelize = null;         // экземпляр sequelize
let User = null;              // модель sequelize
let Op = null;
let QueryTypes = null;

// -----------------------------------------------------------------------------
// Схема и сид-данные (одинаковые для всех трёх стеков)
// -----------------------------------------------------------------------------

const SEED_USERS = [
  { id: 1, name: 'alice', role: 'user', email: 'alice@corp.tld', password: 'alice-pw' },
  { id: 2, name: 'bob', role: 'admin', email: 'bob@corp.tld', password: 's3cr3t-bob' },
  { id: 3, name: 'carol', role: 'user', email: 'carol@corp.tld', password: 'carol-pw' },
];

const SEED_SECRETS = [
  { id: 1, name: 'flag', value: 'FLAG{n0de_sql1_lab}' },
  { id: 2, name: 'db_root_token', value: 'root-1a2b3c4d5e' },
];

const DDL = `
  DROP TABLE IF EXISTS users;
  DROP TABLE IF EXISTS secrets;
  DROP TABLE IF EXISTS profiles;
  CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT,
    role TEXT,
    email TEXT,
    password TEXT
  );
  CREATE TABLE secrets (
    id INTEGER PRIMARY KEY,
    name TEXT,
    value TEXT
  );
  CREATE TABLE profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nickname TEXT
  );
`;

function seedRaw() {
  rawDb.exec(DDL);

  const u = rawDb.prepare(
    'INSERT INTO users(id, name, role, email, password) VALUES(?, ?, ?, ?, ?)',
  );
  for (const r of SEED_USERS) u.run(r.id, r.name, r.role, r.email, r.password);

  const s = rawDb.prepare('INSERT INTO secrets(id, name, value) VALUES(?, ?, ?)');
  for (const r of SEED_SECRETS) s.run(r.id, r.name, r.value);
}

async function seedKnex() {
  await knex.raw('DROP TABLE IF EXISTS users');
  await knex.raw('DROP TABLE IF EXISTS secrets');
  await knex.raw('DROP TABLE IF EXISTS profiles');
  await knex.raw(`CREATE TABLE users (
    id INTEGER PRIMARY KEY, name TEXT, role TEXT, email TEXT, password TEXT)`);
  await knex.raw('CREATE TABLE secrets (id INTEGER PRIMARY KEY, name TEXT, value TEXT)');
  await knex.raw(`CREATE TABLE profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT, nickname TEXT)`);
  await knex('users').insert(SEED_USERS);
  await knex('secrets').insert(SEED_SECRETS);
}

async function seedSequelize() {
  await sequelize.query('DROP TABLE IF EXISTS users');
  await sequelize.query('DROP TABLE IF EXISTS secrets');
  await sequelize.query(`CREATE TABLE users (
    id INTEGER PRIMARY KEY, name TEXT, role TEXT, email TEXT, password TEXT)`);
  await sequelize.query('CREATE TABLE secrets (id INTEGER PRIMARY KEY, name TEXT, value TEXT)');
  for (const r of SEED_USERS) {
    await sequelize.query(
      'INSERT INTO users(id, name, role, email, password) VALUES($id, $name, $role, $email, $password)',
      { bind: r },
    );
  }
  for (const r of SEED_SECRETS) {
    await sequelize.query('INSERT INTO secrets(id, name, value) VALUES($id, $name, $value)', { bind: r });
  }
}

async function seedAll() {
  seedRaw();
  if (knex) await seedKnex();
  if (sequelize) await seedSequelize();
}

// -----------------------------------------------------------------------------
// Логирование запросов (как в Go-лабе — печатаем итоговый SQL)
// -----------------------------------------------------------------------------

function logQuery(tag, sql, params) {
  console.log('--------------------------------------------------');
  console.log(`[${tag}] ${String(sql).trim().replace(/\s+/g, ' ')}`);
  if (params !== undefined) console.log(`[${tag}] params:`, params);
}

// -----------------------------------------------------------------------------
// HTTP helpers
// -----------------------------------------------------------------------------

function sendRows(res, rows) {
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(rows, null, 2) + '\n');
}

function sendText(res, text, code = 200) {
  res.statusCode = code;
  res.setHeader('content-type', 'text/plain; charset=utf-8');
  res.end(text + '\n');
}

function sendErr(res, e) {
  // Ошибки БД показываем целиком — это часть лабы (error-based SQLi).
  sendText(res, 'ERROR: ' + (e && e.message ? e.message : String(e)), 500);
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => { data += c; });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); }
      catch { resolve({}); }
    });
    req.on('error', () => resolve({}));
  });
}

// -----------------------------------------------------------------------------
// Реестр роутов
// -----------------------------------------------------------------------------

const ROUTES = [];

function route(method, path, meta, handler) {
  ROUTES.push({ method, path, group: meta.group, desc: meta.desc, example: meta.example, handler });
}

function unavailable(mod) {
  return async ({ res }) => sendText(res, `Модуль "${mod}" не установлен. Запусти:  npm install`, 503);
}

// =============================================================================
// СЕКЦИЯ 1. Сырой драйвер: node:sqlite
// =============================================================================

function registerRaw() {
  const G = 'raw driver (node:sqlite)';

  // ---- 1.1 конкатенация строк ------------------------------------------------
  route('GET', '/unsafe-concat', {
    group: G,
    desc: 'Классика: имя вклеено в строку запроса через конкатенацию.',
    example: `curl -G --data-urlencode "name=' UNION SELECT id, name, value FROM secrets -- " http://localhost:${PORT}/unsafe-concat`,
  }, async ({ q, res }) => {
    const name = q.get('name') || '';
    const sql = "SELECT id, name, role FROM users WHERE name = '" + name + "'";
    logQuery('unsafe-concat', sql);
    sendRows(res, rawDb.prepare(sql).all());
  });

  route('GET', '/safe-concat', {
    group: G,
    desc: 'То же самое, но значение уходит параметром (?).',
    example: `curl -G --data-urlencode "name=alice" http://localhost:${PORT}/safe-concat`,
  }, async ({ q, res }) => {
    const name = q.get('name') || '';
    const sql = 'SELECT id, name, role FROM users WHERE name = ?';
    logQuery('safe-concat', sql, [name]);
    sendRows(res, rawDb.prepare(sql).all(name));
  });

  // ---- 1.2 шаблонная строка (самая частая ошибка в Node) -------------------
  route('GET', '/unsafe-template', {
    group: G,
    desc: 'Template literal `... ${name} ...` — визуально «не конкатенация», но ровно она.',
    example: `curl -G --data-urlencode "name=' OR 1=1 -- " http://localhost:${PORT}/unsafe-template`,
  }, async ({ q, res }) => {
    const name = q.get('name') || '';
    const sql = `SELECT id, name, role FROM users WHERE name = '${name}'`;
    logQuery('unsafe-template', sql);
    sendRows(res, rawDb.prepare(sql).all());
  });

  route('GET', '/safe-template', {
    group: G,
    desc: 'Template literal используется ТОЛЬКО для статического текста запроса, значение — параметр.',
    example: `curl -G --data-urlencode "name=bob" http://localhost:${PORT}/safe-template`,
  }, async ({ q, res }) => {
    const name = q.get('name') || '';
    const sql = `SELECT id, name, role FROM users WHERE name = ${'?'}`;
    logQuery('safe-template', sql, [name]);
    sendRows(res, rawDb.prepare(sql).all(name));
  });

  // ---- 1.3 числовой контекст (без кавычек) --------------------------------
  route('GET', '/unsafe-numeric', {
    group: G,
    desc: 'id подставляется без кавычек: `WHERE id = ${id}`. Инъекция без единой кавычки.',
    example: `curl -G --data-urlencode "id=0 UNION SELECT id, name, value FROM secrets" http://localhost:${PORT}/unsafe-numeric`,
  }, async ({ q, res }) => {
    const id = q.get('id') || '';
    const sql = `SELECT id, name, role FROM users WHERE id = ${id}`;
    logQuery('unsafe-numeric', sql);
    sendRows(res, rawDb.prepare(sql).all());
  });

  route('GET', '/safe-numeric', {
    group: G,
    desc: 'Число валидируется (целое) и уходит параметром.',
    example: `curl -G --data-urlencode "id=2" http://localhost:${PORT}/safe-numeric`,
  }, async ({ q, res }) => {
    const raw = q.get('id') || '';
    if (!/^\d+$/.test(raw)) return sendText(res, 'id must be a non-negative integer', 400);
    const sql = 'SELECT id, name, role FROM users WHERE id = ?';
    logQuery('safe-numeric', sql, [raw]);
    sendRows(res, rawDb.prepare(sql).all(Number(raw)));
  });

  // ---- 1.4 LIKE -----------------------------------------------------------
  route('GET', '/unsafe-like', {
    group: G,
    desc: "Поиск: `LIKE '%${q}%'` — инъекция + бонусом wildcard-инъекция (%, _).",
    example: `curl -G --data-urlencode "q=%' UNION SELECT id, name, value FROM secrets -- " http://localhost:${PORT}/unsafe-like`,
  }, async ({ q, res }) => {
    const term = q.get('q') || '';
    const sql = `SELECT id, name, role FROM users WHERE name LIKE '%${term}%'`;
    logQuery('unsafe-like', sql);
    sendRows(res, rawDb.prepare(sql).all());
  });

  route('GET', '/safe-like', {
    group: G,
    desc: "Паттерн — параметр; спецсимволы LIKE экранируются через ESCAPE.",
    example: `curl -G --data-urlencode "q=ali" http://localhost:${PORT}/safe-like`,
  }, async ({ q, res }) => {
    const term = q.get('q') || '';
    const escaped = term.replace(/[\\%_]/g, (c) => '\\' + c);
    const sql = "SELECT id, name, role FROM users WHERE name LIKE ? ESCAPE '\\'";
    const pattern = `%${escaped}%`;
    logQuery('safe-like', sql, [pattern]);
    sendRows(res, rawDb.prepare(sql).all(pattern));
  });

  // ---- 1.5 IN (...) -----------------------------------------------------
  route('GET', '/unsafe-in', {
    group: G,
    desc: "IN-список склеен из массива: `IN ('${names.join(\"','\")}')`.",
    example: `curl -G --data-urlencode "name=alice" --data-urlencode "name=x') UNION SELECT id, name, value FROM secrets -- " http://localhost:${PORT}/unsafe-in`,
  }, async ({ q, res }) => {
    const names = q.getAll('name');
    if (names.length === 0) return sendText(res, 'name required', 400);
    const sql = `SELECT id, name, role FROM users WHERE name IN ('${names.join("','")}')`;
    logQuery('unsafe-in', sql);
    sendRows(res, rawDb.prepare(sql).all());
  });

  route('GET', '/safe-in', {
    group: G,
    desc: 'Под каждый элемент генерится свой ? — плейсхолдеров ровно столько же.',
    example: `curl -G --data-urlencode "name=alice" --data-urlencode "name=bob" http://localhost:${PORT}/safe-in`,
  }, async ({ q, res }) => {
    const names = q.getAll('name');
    if (names.length === 0) return sendText(res, 'name required', 400);
    const holders = names.map(() => '?').join(',');
    const sql = `SELECT id, name, role FROM users WHERE name IN (${holders})`;
    logQuery('safe-in', sql, names);
    sendRows(res, rawDb.prepare(sql).all(...names));
  });

  // ---- 1.6 ORDER BY (инъекция в имя столбца) ---------------------------
  route('GET', '/unsafe-order', {
    group: G,
    desc: 'ORDER BY ${sort} — плейсхолдером не закрыть, значит склейка. Годится для blind-инъекции.',
    example: `curl -G --data-urlencode "sort=(CASE WHEN (SELECT value FROM secrets WHERE id=1) LIKE 'FLAG%' THEN 1 ELSE 2 END)" http://localhost:${PORT}/unsafe-order`,
  }, async ({ q, res }) => {
    const sort = q.get('sort') || 'id';
    const sql = `SELECT id, name, role FROM users ORDER BY ${sort}`;
    logQuery('unsafe-order', sql);
    sendRows(res, rawDb.prepare(sql).all());
  });

  route('GET', '/safe-order', {
    group: G,
    desc: 'Столбец и направление — из allow-list, в SQL уходят только известные литералы.',
    example: `curl -G --data-urlencode "sort=name" --data-urlencode "dir=desc" http://localhost:${PORT}/safe-order`,
  }, async ({ q, res }) => {
    const cols = { id: 'id', name: 'name', role: 'role' };
    const dirs = { asc: 'ASC', desc: 'DESC' };
    const col = cols[q.get('sort')];
    const dir = dirs[(q.get('dir') || 'asc').toLowerCase()];
    if (!col || !dir) return sendText(res, 'invalid sort/dir', 400);
    const sql = `SELECT id, name, role FROM users ORDER BY ${col} ${dir}`;
    logQuery('safe-order', sql);
    sendRows(res, rawDb.prepare(sql).all());
  });

  // ---- 1.7 LIMIT --------------------------------------------------------
  route('GET', '/unsafe-limit', {
    group: G,
    desc: 'LIMIT ${limit} — числовой контекст в конце запроса, инъекция подзапросом/UNION.',
    example: `curl -G --data-urlencode "limit=1-1 UNION SELECT id, name, value FROM secrets" http://localhost:${PORT}/unsafe-limit`,
  }, async ({ q, res }) => {
    const limit = q.get('limit') || '10';
    const sql = `SELECT id, name, role FROM users LIMIT ${limit}`;
    logQuery('unsafe-limit', sql);
    sendRows(res, rawDb.prepare(sql).all());
  });

  route('GET', '/safe-limit', {
    group: G,
    desc: 'parseInt + зажим диапазона, дальше параметр.',
    example: `curl -G --data-urlencode "limit=2" http://localhost:${PORT}/safe-limit`,
  }, async ({ q, res }) => {
    let limit = Number.parseInt(q.get('limit'), 10);
    if (!Number.isFinite(limit)) limit = 10;
    limit = Math.min(Math.max(limit, 0), 100);
    const sql = 'SELECT id, name, role FROM users LIMIT ?';
    logQuery('safe-limit', sql, [limit]);
    sendRows(res, rawDb.prepare(sql).all(limit));
  });

  // ---- 1.8 «мы же используем prepared statements» ---------------------
  route('GET', '/unsafe-prepare-late', {
    group: G,
    desc: 'НЕОЧЕВИДНО: строка склеена ДО prepare(). prepare/parametrize защищают значения, а не уже испорченный текст.',
    example: `curl -G --data-urlencode "name=' UNION SELECT id, name, value FROM secrets -- " http://localhost:${PORT}/unsafe-prepare-late`,
  }, async ({ q, res }) => {
    const name = q.get('name') || '';
    // Уязвимость уже произошла на этой строке:
    const sql = `SELECT id, name, role FROM users WHERE name = '${name}'`;
    logQuery('unsafe-prepare-late', sql);
    const stmt = rawDb.prepare(sql); // "подготовленный", но текст уже под контролем атакующего
    sendRows(res, stmt.all());
  });

  route('GET', '/safe-prepare', {
    group: G,
    desc: 'prepare() один раз со статическим текстом и ?, затем повторные вызовы .all(value).',
    example: `curl -G --data-urlencode "name=carol" http://localhost:${PORT}/safe-prepare`,
  }, async ({ q, res }) => {
    const name = q.get('name') || '';
    const sql = 'SELECT id, name, role FROM users WHERE name = ?';
    logQuery('safe-prepare', sql, [name]);
    const stmt = rawDb.prepare(sql);
    sendRows(res, stmt.all(name));
  });

  // ---- 1.9 stacked queries через .exec() ----------------------------
  route('POST', '/unsafe-exec-stacked', {
    group: G,
    desc: 'НЕОЧЕВИДНО: .prepare() выполнит только 1-й стейтмент, а .exec() — все. Склейка в .exec() => DROP/DELETE.',
    example: `curl -X POST -H 'content-type: application/json' -d '{"name":"x'"'"'; DROP TABLE secrets; -- "}' http://localhost:${PORT}/unsafe-exec-stacked   (после — вызови /reset)`,
  }, async ({ body, q, res }) => {
    const name = (body && body.name) || q.get('name') || '';
    const sql = `SELECT id, name, role FROM users WHERE name = '${name}'`;
    logQuery('unsafe-exec-stacked', sql);
    rawDb.exec(sql); // exec глотает несколько операторов, разделённых ;
    sendText(res, 'executed via exec() — проверь схему, при необходимости GET /reset');
  });

  route('POST', '/safe-exec', {
    group: G,
    desc: 'Никаких данных в .exec(). Для запросов с параметрами — только prepare()+?.',
    example: `curl -X POST -H 'content-type: application/json' -d '{"name":"alice"}' http://localhost:${PORT}/safe-exec`,
  }, async ({ body, q, res }) => {
    const name = (body && body.name) || q.get('name') || '';
    const sql = 'SELECT id, name, role FROM users WHERE name = ?';
    logQuery('safe-exec', sql, [name]);
    sendRows(res, rawDb.prepare(sql).all(name));
  });

  // ---- 1.10 second-order --------------------------------------------
  route('GET', '/unsafe-second-order-store', {
    group: G,
    desc: 'Шаг 1: сохраняем никнейм ПАРАМЕТРИЗОВАННО (выглядит безопасно).',
    example: `curl -G --data-urlencode "nickname=' UNION SELECT id, name, value FROM secrets -- " http://localhost:${PORT}/unsafe-second-order-store`,
  }, async ({ q, res }) => {
    const nickname = q.get('nickname') || '';
    rawDb.prepare('INSERT INTO profiles(nickname) VALUES(?)').run(nickname);
    logQuery('second-order-store', 'INSERT INTO profiles(nickname) VALUES(?)', [nickname]);
    sendText(res, 'nickname stored — теперь GET /unsafe-second-order-use');
  });

  route('GET', '/unsafe-second-order-use', {
    group: G,
    desc: 'НЕОЧЕВИДНО: шаг 2 берёт «доверенные» данные из БД и склеивает их в новый запрос. Инъекция сработала при чтении.',
    example: `curl http://localhost:${PORT}/unsafe-second-order-use`,
  }, async ({ res }) => {
    const row = rawDb.prepare('SELECT nickname FROM profiles ORDER BY id DESC LIMIT 1').get();
    const nick = row ? row.nickname : '';
    const sql = `SELECT id, name, role FROM users WHERE name = '${nick}'`; // stored value -> SQL
    logQuery('unsafe-second-order-use', sql);
    sendRows(res, rawDb.prepare(sql).all());
  });

  route('GET', '/safe-second-order-use', {
    group: G,
    desc: 'Данные из своей же БД — всё равно параметр. «Доверенных» источников для конкатенации нет.',
    example: `curl http://localhost:${PORT}/safe-second-order-use`,
  }, async ({ res }) => {
    const row = rawDb.prepare('SELECT nickname FROM profiles ORDER BY id DESC LIMIT 1').get();
    const nick = row ? row.nickname : '';
    const sql = 'SELECT id, name, role FROM users WHERE name = ?';
    logQuery('safe-second-order-use', sql, [nick]);
    sendRows(res, rawDb.prepare(sql).all(nick));
  });

  // ---- 1.11 инъекция в ИДЕНТИФИКАТОР (значение параметризовано!) -----
  route('GET', '/unsafe-identifier', {
    group: G,
    desc: 'НЕОЧЕВИДНО: значение уходит через ?, но имя столбца склеено. Даёт oracle/выкачку (напр. col=password).',
    example: `curl -G --data-urlencode "col=password" --data-urlencode "val=s3cr3t-bob" http://localhost:${PORT}/unsafe-identifier`,
  }, async ({ q, res }) => {
    const col = q.get('col') || 'name';
    const val = q.get('val') || '';
    const sql = `SELECT id, name, role FROM users WHERE ${col} = ?`;
    logQuery('unsafe-identifier', sql, [val]);
    sendRows(res, rawDb.prepare(sql).all(val));
  });

  route('GET', '/safe-identifier', {
    group: G,
    desc: 'Имя столбца — только из allow-list.',
    example: `curl -G --data-urlencode "col=email" --data-urlencode "val=bob@corp.tld" http://localhost:${PORT}/safe-identifier`,
  }, async ({ q, res }) => {
    const allowed = { name: 'name', email: 'email', role: 'role', id: 'id' };
    const col = allowed[q.get('col')];
    const val = q.get('val') || '';
    if (!col) return sendText(res, 'invalid col', 400);
    const sql = `SELECT id, name, role FROM users WHERE ${col} = ?`;
    logQuery('safe-identifier', sql, [val]);
    sendRows(res, rawDb.prepare(sql).all(val));
  });

  // ---- 1.12 обход аутентификации ----------------------------------
  route('GET', '/unsafe-login', {
    group: G,
    desc: "Логин: `WHERE name='${u}' AND password='${p}'` — комментарий `-- ` отрезает проверку пароля.",
    example: `curl -G --data-urlencode "user=bob'-- " --data-urlencode "pass=whatever" http://localhost:${PORT}/unsafe-login`,
  }, async ({ q, res }) => {
    const user = q.get('user') || '';
    const pass = q.get('pass') || '';
    const sql = `SELECT id, name, role FROM users WHERE name = '${user}' AND password = '${pass}'`;
    logQuery('unsafe-login', sql);
    const row = rawDb.prepare(sql).get();
    sendText(res, row ? `AUTH OK as ${row.name} (${row.role})` : 'AUTH FAILED', row ? 200 : 401);
  });

  route('GET', '/safe-login', {
    group: G,
    desc: 'Оба поля — параметры.',
    example: `curl -G --data-urlencode "user=bob" --data-urlencode "pass=s3cr3t-bob" http://localhost:${PORT}/safe-login`,
  }, async ({ q, res }) => {
    const user = q.get('user') || '';
    const pass = q.get('pass') || '';
    const sql = 'SELECT id, name, role FROM users WHERE name = ? AND password = ?';
    logQuery('safe-login', sql, [user, pass]);
    const row = rawDb.prepare(sql).get(user, pass);
    sendText(res, row ? `AUTH OK as ${row.name} (${row.role})` : 'AUTH FAILED', row ? 200 : 401);
  });

  // ---- 1.13 неожиданный тип из фреймворка ------------------------
  route('POST', '/unsafe-type-juggling', {
    group: G,
    desc: 'НЕОЧЕВИДНО: код ждёт строку/число, а JSON-тело даёт объект/массив. `${value}` от массива = "1,2,3" -> ломает WHERE.',
    example: `curl -X POST -H 'content-type: application/json' -d '{"id":["1","2","3"]}' http://localhost:${PORT}/unsafe-type-juggling`,
  }, async ({ body, res }) => {
    const id = body && body.id; // ожидали строку/число
    const sql = `SELECT id, name, role FROM users WHERE id IN (${id})`;
    logQuery('unsafe-type-juggling', sql);
    sendRows(res, rawDb.prepare(sql).all());
  });

  route('POST', '/safe-type-juggling', {
    group: G,
    desc: 'Приводим к массиву строк, валидируем каждый элемент, генерим ? под каждый.',
    example: `curl -X POST -H 'content-type: application/json' -d '{"id":["1","2"]}' http://localhost:${PORT}/safe-type-juggling`,
  }, async ({ body, res }) => {
    let ids = body && body.id;
    if (!Array.isArray(ids)) ids = [ids];
    ids = ids.map((x) => String(x));
    if (!ids.every((x) => /^\d+$/.test(x))) return sendText(res, 'ids must be integers', 400);
    const holders = ids.map(() => '?').join(',');
    const sql = `SELECT id, name, role FROM users WHERE id IN (${holders})`;
    logQuery('safe-type-juggling', sql, ids);
    sendRows(res, rawDb.prepare(sql).all(...ids.map(Number)));
  });
}

// =============================================================================
// СЕКЦИЯ 2. Query builder: Knex
// =============================================================================

function registerKnex() {
  const G = 'query builder (knex)';
  const has = Boolean(knex);

  route('GET', '/unsafe-knex-whereraw', {
    group: G,
    desc: 'whereRaw со склейкой строки — билдер тут ничем не помогает.',
    example: `curl -G --data-urlencode "name=' OR 1=1 -- " http://localhost:${PORT}/unsafe-knex-whereraw`,
  }, has ? async ({ q, res }) => {
    const name = q.get('name') || '';
    const rows = await knex('users').select('id', 'name', 'role').whereRaw("name = '" + name + "'");
    sendRows(res, rows);
  } : unavailable('knex'));

  route('GET', '/safe-knex-where', {
    group: G,
    desc: '.where({ name }) — knex сам параметризует; либо whereRaw(\'name = ?\', [name]).',
    example: `curl -G --data-urlencode "name=alice" http://localhost:${PORT}/safe-knex-where`,
  }, has ? async ({ q, res }) => {
    const name = q.get('name') || '';
    const rows = await knex('users').select('id', 'name', 'role').where({ name });
    sendRows(res, rows);
  } : unavailable('knex'));

  route('GET', '/unsafe-knex-orderby', {
    group: G,
    desc: 'orderByRaw(userInput) — сырой фрагмент, инъекция в ORDER BY.',
    example: `curl -G --data-urlencode "sort=(SELECT CASE WHEN 1=1 THEN 1 ELSE 2 END)" http://localhost:${PORT}/unsafe-knex-orderby`,
  }, has ? async ({ q, res }) => {
    const sort = q.get('sort') || 'id';
    const rows = await knex('users').select('id', 'name', 'role').orderByRaw(sort);
    sendRows(res, rows);
  } : unavailable('knex'));

  route('GET', '/safe-knex-orderby', {
    group: G,
    desc: '.orderBy(col, dir) с allow-list; knex экранирует идентификатор и проверяет направление.',
    example: `curl -G --data-urlencode "sort=name" --data-urlencode "dir=desc" http://localhost:${PORT}/safe-knex-orderby`,
  }, has ? async ({ q, res }) => {
    const allowed = ['id', 'name', 'role'];
    const col = allowed.includes(q.get('sort')) ? q.get('sort') : 'id';
    const dir = (q.get('dir') || 'asc').toLowerCase() === 'desc' ? 'desc' : 'asc';
    const rows = await knex('users').select('id', 'name', 'role').orderBy(col, dir);
    sendRows(res, rows);
  } : unavailable('knex'));

  route('GET', '/unsafe-knex-raw', {
    group: G,
    desc: 'knex.raw(`... ${name} ...`) — тот же template literal, просто через билдер.',
    example: `curl -G --data-urlencode "name=' UNION SELECT id, name, value FROM secrets -- " http://localhost:${PORT}/unsafe-knex-raw`,
  }, has ? async ({ q, res }) => {
    const name = q.get('name') || '';
    const rows = await knex.raw(`SELECT id, name, role FROM users WHERE name = '${name}'`);
    sendRows(res, rows);
  } : unavailable('knex'));

  route('GET', '/safe-knex-raw', {
    group: G,
    desc: 'knex.raw(sql, [bindings]) — позиционные ? или :named биндинги.',
    example: `curl -G --data-urlencode "name=bob" http://localhost:${PORT}/safe-knex-raw`,
  }, has ? async ({ q, res }) => {
    const name = q.get('name') || '';
    const rows = await knex.raw('SELECT id, name, role FROM users WHERE name = ?', [name]);
    sendRows(res, rows);
  } : unavailable('knex'));
}

// =============================================================================
// СЕКЦИЯ 3. ORM: Sequelize
// =============================================================================

function registerSequelize() {
  const G = 'ORM (sequelize)';
  const has = Boolean(sequelize);

  route('GET', '/unsafe-sequelize-query', {
    group: G,
    desc: 'sequelize.query(`... ${name} ...`) — сырой SQL со склейкой.',
    example: `curl -G --data-urlencode "name=' UNION SELECT id, name, value FROM secrets -- " http://localhost:${PORT}/unsafe-sequelize-query`,
  }, has ? async ({ q, res }) => {
    const name = q.get('name') || '';
    const rows = await sequelize.query(
      `SELECT id, name, role FROM users WHERE name = '${name}'`,
      { type: QueryTypes.SELECT },
    );
    sendRows(res, rows);
  } : unavailable('sequelize'));

  route('GET', '/safe-sequelize-replacements', {
    group: G,
    desc: 'sequelize.query(sql, { replacements }) — :name экранируется как значение.',
    example: `curl -G --data-urlencode "name=alice" http://localhost:${PORT}/safe-sequelize-replacements`,
  }, has ? async ({ q, res }) => {
    const name = q.get('name') || '';
    const rows = await sequelize.query(
      'SELECT id, name, role FROM users WHERE name = :name',
      { replacements: { name }, type: QueryTypes.SELECT },
    );
    sendRows(res, rows);
  } : unavailable('sequelize'));

  route('GET', '/safe-sequelize-bind', {
    group: G,
    desc: 'sequelize.query(sql, { bind }) — $1 уходит настоящим bind-параметром драйвера.',
    example: `curl -G --data-urlencode "name=carol" http://localhost:${PORT}/safe-sequelize-bind`,
  }, has ? async ({ q, res }) => {
    const name = q.get('name') || '';
    const rows = await sequelize.query(
      'SELECT id, name, role FROM users WHERE name = $1',
      { bind: [name], type: QueryTypes.SELECT },
    );
    sendRows(res, rows);
  } : unavailable('sequelize'));

  route('GET', '/unsafe-sequelize-order', {
    group: G,
    desc: 'НЕОЧЕВИДНО: replacements НЕ умеют идентификаторы (:col стал бы строкой-литералом), и разработчик склеивает ORDER BY.',
    example: `curl -G --data-urlencode "sort=(CASE WHEN (SELECT value FROM secrets WHERE id=1) LIKE 'FLAG%' THEN 1 ELSE 2 END)" http://localhost:${PORT}/unsafe-sequelize-order`,
  }, has ? async ({ q, res }) => {
    const sort = q.get('sort') || 'id';
    const rows = await sequelize.query(
      `SELECT id, name, role FROM users ORDER BY ${sort}`,
      { type: QueryTypes.SELECT },
    );
    sendRows(res, rows);
  } : unavailable('sequelize'));

  route('GET', '/safe-sequelize-order', {
    group: G,
    desc: 'Столбец/направление из allow-list.',
    example: `curl -G --data-urlencode "sort=name" --data-urlencode "dir=desc" http://localhost:${PORT}/safe-sequelize-order`,
  }, has ? async ({ q, res }) => {
    const cols = { id: 'id', name: 'name', role: 'role' };
    const col = cols[q.get('sort')] || 'id';
    const dir = (q.get('dir') || 'asc').toLowerCase() === 'desc' ? 'DESC' : 'ASC';
    const rows = await sequelize.query(
      `SELECT id, name, role FROM users ORDER BY ${col} ${dir}`,
      { type: QueryTypes.SELECT },
    );
    sendRows(res, rows);
  } : unavailable('sequelize'));

  route('GET', '/unsafe-sequelize-literal', {
    group: G,
    desc: 'where: Sequelize.literal(`name = \'${name}\'`) — literal() отключает всё экранирование.',
    example: `curl -G --data-urlencode "name=' OR 1=1 -- " http://localhost:${PORT}/unsafe-sequelize-literal`,
  }, has ? async ({ q, res }) => {
    const name = q.get('name') || '';
    const rows = await User.findAll({
      attributes: ['id', 'name', 'role'],
      where: SequelizeLib.literal(`name = '${name}'`),
    });
    sendRows(res, rows.map((r) => r.toJSON()));
  } : unavailable('sequelize'));

  route('POST', '/unsafe-sequelize-operator', {
    group: G,
    desc: 'НЕОЧЕВИДНО (ORM-эпоха): ключи из JSON маппятся в Op[...] — атакующий управляет СТРУКТУРОЙ условия (обход фильтра).',
    example: `curl -X POST -H 'content-type: application/json' -d '{"role":{"ne":"__none__"}}' http://localhost:${PORT}/unsafe-sequelize-operator`,
  }, has ? async ({ body, res }) => {
    const filter = body && typeof body === 'object' ? body : {};
    const where = {};
    for (const [field, cond] of Object.entries(filter)) {
      if (cond && typeof cond === 'object' && !Array.isArray(cond)) {
        for (const [opName, v] of Object.entries(cond)) {
          if (Op[opName]) {
            where[field] = { ...(where[field] || {}), [Op[opName]]: v };
          }
        }
      } else {
        where[field] = cond;
      }
    }
    logQuery('unsafe-sequelize-operator', 'User.findAll(where from user JSON)', filter);
    const rows = await User.findAll({ attributes: ['id', 'name', 'role'], where });
    sendRows(res, rows.map((r) => r.toJSON()));
  } : unavailable('sequelize'));

  route('POST', '/safe-sequelize-operator', {
    group: G,
    desc: 'Жёстко фиксированная структура where; из тела берём только скалярное значение нужного поля.',
    example: `curl -X POST -H 'content-type: application/json' -d '{"role":"admin"}' http://localhost:${PORT}/safe-sequelize-operator`,
  }, has ? async ({ body, res }) => {
    const role = body && body.role != null ? String(body.role) : '';
    const rows = await User.findAll({
      attributes: ['id', 'name', 'role'],
      where: { role: { [Op.eq]: role } },
    });
    sendRows(res, rows.map((r) => r.toJSON()));
  } : unavailable('sequelize'));
}

// =============================================================================
// Bootstrap
// =============================================================================

async function initKnex() {
  if (!KnexFactory) return;
  try {
    knex = KnexFactory({
      client: 'sqlite3',
      connection: { filename: ':memory:' },
      useNullAsDefault: true,
    });
    knex.on('query', (data) => {
      console.log('--------------------------------------------------');
      console.log('[knex]', String(data.sql).replace(/\s+/g, ' '), JSON.stringify(data.bindings || []));
    });
    await knex.raw('SELECT 1'); // проверка, что клиент реально ставится
  } catch (e) {
    console.warn('[knex] отключён:', e.message);
    knex = null;
  }
}

async function initSequelize() {
  if (!SequelizeLib) return;
  try {
    const { Sequelize, DataTypes } = SequelizeLib;
    Op = SequelizeLib.Op;
    QueryTypes = SequelizeLib.QueryTypes;
    sequelize = new Sequelize({
      dialect: 'sqlite',
      storage: ':memory:',
      logging: (msg) => {
        console.log('--------------------------------------------------');
        console.log('[sequelize]', msg);
      },
    });
    await sequelize.authenticate();
    User = sequelize.define('User', {
      id: { type: DataTypes.INTEGER, primaryKey: true },
      name: DataTypes.STRING,
      role: DataTypes.STRING,
      email: DataTypes.STRING,
      password: DataTypes.STRING,
    }, { tableName: 'users', timestamps: false });
  } catch (e) {
    console.warn('[sequelize] отключён:', e.message);
    sequelize = null;
  }
}

function sendIndex(res) {
  const groups = new Map();
  for (const r of ROUTES) {
    if (!groups.has(r.group)) groups.set(r.group, []);
    groups.get(r.group).push(r);
  }

  let out = '';
  out += 'Node.js SQL injection lab\n';
  out += '=========================\n\n';
  out += `GET  /        — этот список\n`;
  out += `GET  /reset   — пересоздать + перезаполнить все БД\n\n`;
  out += `knex:      ${knex ? 'ON' : 'OFF (npm install)'}\n`;
  out += `sequelize: ${sequelize ? 'ON' : 'OFF (npm install)'}\n\n`;
  out += 'Соглашение: /unsafe-* уязвимо, /safe-* — нет.\n';
  out += 'Пейлоады удобно слать через  curl -G --data-urlencode "k=v".\n\n';

  for (const [group, list] of groups) {
    out += `\n## ${group}\n\n`;
    for (const r of list) {
      out += `${r.method.padEnd(4)} ${r.path}\n`;
      out += `     ${r.desc}\n`;
      if (r.example) out += `     $ ${r.example}\n`;
      out += '\n';
    }
  }

  res.setHeader('content-type', 'text/plain; charset=utf-8');
  res.end(out);
}

async function main() {
  await initKnex();
  await initSequelize();

  registerRaw();
  registerKnex();
  registerSequelize();

  await seedAll();

  const server = http.createServer(async (req, res) => {
    let url;
    try {
      url = new URL(req.url, `http://localhost:${PORT}`);
    } catch {
      return sendText(res, 'bad url', 400);
    }

    const path = url.pathname;

    if (path === '/' || path === '') return sendIndex(res);

    if (path === '/reset') {
      try {
        await seedAll();
        return sendText(res, 'reset done');
      } catch (e) {
        return sendErr(res, e);
      }
    }

    const r = ROUTES.find((x) => x.path === path && x.method === req.method);
    if (!r) {
      const anyMethod = ROUTES.some((x) => x.path === path);
      return sendText(res, anyMethod ? 'method not allowed' : 'no such route — GET / for the list', anyMethod ? 405 : 404);
    }

    try {
      const body = req.method === 'POST' || req.method === 'PUT' ? await readBody(req) : {};
      await r.handler({ q: url.searchParams, body, res });
    } catch (e) {
      sendErr(res, e);
    }
  });

  server.listen(PORT, () => {
    console.log(`Node.js SQLi lab -> http://localhost:${PORT}/`);
    console.log(`knex: ${knex ? 'ON' : 'OFF'} | sequelize: ${sequelize ? 'ON' : 'OFF'}`);
  });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
