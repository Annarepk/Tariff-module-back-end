# Тарифный модуль на Go (back-end)

**Тарифный модуль на Go** — серверная часть системы расчёта комиссий, лимитов и обработки клиентских тарифов. 
Поддерживает REST, Kafka и ISO8583.

## Содержание

1. [Общее описание](#общее-описание)
2. [Функциональность](#функциональность)
3. [Технологии](#технологии)
4. [Протоколы](#протоколы)
5. [Структура проекта](#структура-проекта)
6. [Функциональность API](#функциональность-api)
7. [Таблицы БД (PostgreSQL)](#таблицы-бд-(postgresql))
8. [Сборка и запуск](#сборка-и-запуск)

---

## Общее описание

Сервис предназначен для расчета комиссий и учета лимитов по операциям клиентов.
Поддерживает:

- тарифы и пороговые правила,
- авторизацию и разграничение прав,
- сбор метрик,
- поддержку REST, Kafka (JSON/XML) и ISO8583.

---

## Функциональность

- Расчёт комиссий:
  - фиксированная
  - процентная
  - сумма фиксированной и процентной
  - min/max между фиксированной и процентной
- Учет лимитов:
  - не более 100 операций в сутки
  - не более 100 000 в сутки
- Настраиваемые пороговые правила до 10 блоков
- Роли пользователей: `admin`, `user`
- JWT-аутентификация
- Метрики Prometheus
- Поддержка протоколов:
  - REST/JSON
  - Kafka/JSON
  - Kafka/XML
  - ISO8583
- Загрузка клиентов из CSV-файла

---

## Технологии

- Go 1.22+
- PostgreSQL (через `pgx`)
- Kafka
- Prometheus
- JWT (HMAC)
- Gorilla Mux
- ISO8583: `github.com/moov-io/iso8583`

---

## Протоколы

- **REST/JSON** — основной API.
- **Kafka/JSON** — запросы читаются из топика `calc-json`, отправляются в `calc-json-resp`.
- **Kafka/XML** — поддержка XML-сообщений.
- **ISO8583** — работает на `:8583`, отвечает на MTI 0200 (код тестовый, может быть расширен).

---

## Структура проекта

```
.
├── cmd/                  # main.go (запуск сервера)
├── internal/
│   ├── db/               # Взаимодействие с базой данных
│   ├── model/            # Типы данных
│   ├── service/          # JWT, расчеты
│   ├── kafka/            # Kafka сервер
│   ├── iso/              # ISO8583 сервер
│   └── metrics/          # Prometheus метрики
├── go.mod
└── .env (локально)
```

---

## Функциональность API

| Метод  | Путь                   | Доступ       | Описание                         |
|--------|------------------------|--------------|----------------------------------|
| POST   | `/api/register`        | Все          | Регистрация пользователя         |
| POST   | `/api/login`           | Все          | Вход (JWT токен)                 |
| POST   | `/api/clients`         | Админ        | Создание клиента                 |
| GET    | `/api/clients`         | Админ        | Получение всех клиентов          |
| PUT    | `/api/clients/{id}`    | Пользователь | Обновление своего клиента        |
| DELETE | `/api/clients/{id}`    | Пользователь | Удаление своего клиента          |
| POST   | `/api/tariffs`         | Админ        | Создание тарифа                  |
| GET    | `/api/tariffs`         | Все          | Получение тарифов                |
| GET    | `/api/tariffs/{id}`    | Все          | Получение тарифа по ID           |
| PUT    | `/api/tariffs/{id}`    | Админ        | Обновление тарифа                |
| DELETE | `/api/tariffs/{id}`    | Админ        | Удаление тарифа                  |
| POST   | `/api/rules`           | Админ        | Добавление порогового правила    |
| GET    | `/api/rules`           | Все          | Получение всех правил            |
| PUT    | `/api/rules/{id}`      | Админ        | Обновление правила               |
| DELETE | `/api/rules/{id}`      | Админ        | Удаление правила                 |
| POST   | `/api/calculate`       | Пользователь | Расчет комиссии                  |
| GET    | `/api/operations/{id}` | Пользователь | История операций                 |
| GET    | `/api/metrics/custom`  | Все          | Метрики (секунда, минута и т.д.) |
| GET    | `/metrics`             | Все          | Стандартные метрики Prometheus   |


---

## Таблицы БД (PostgreSQL)

```sql
-- users
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user'
);

-- clients
CREATE TABLE clients (
  id SERIAL PRIMARY KEY,
  client_id TEXT UNIQUE NOT NULL,
  tariff_id INT NOT NULL,
  client_type TEXT,
  account_type TEXT,
  user_id INT REFERENCES users(id)
);

-- tariffs
CREATE TABLE tariffs (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  fixed_fee NUMERIC,
  percent_fee NUMERIC,
  min_fee NUMERIC,
  max_fee NUMERIC,
  calc_mode TEXT
);

-- threshold_rules
CREATE TABLE threshold_rules (
  id SERIAL PRIMARY KEY,
  tariff_id INT REFERENCES tariffs(id),
  from_count INT,
  to_count INT,
  percent_fee NUMERIC,
  fixed_fee NUMERIC,
  min_fee NUMERIC,
  max_fee NUMERIC,
  calc_mode TEXT,
  mcc TEXT,
  client_type TEXT,
  account_type TEXT,
  op_type TEXT
);

-- operations
CREATE TABLE operations (
  id SERIAL PRIMARY KEY,
  client_id TEXT,
  amount NUMERIC,
  created_at TIMESTAMP DEFAULT NOW()
);
```
---

## Сборка и запуск

```bash
# Установка зависимостей
go mod download

# Запуск проекта
go run cmd/main.go

# (опционально) запуск Kafka + Zookeeper
docker compose up -d
````







