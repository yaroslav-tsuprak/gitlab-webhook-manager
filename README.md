# GitLab Webhook Manager

## 📘 Описание

**GitLab Webhook Manager** — это лёгкий сервис на Go, который принимает вебхуки от GitLab при успешном выполнении pipeline и запускает соответствующий bash-скрипт из директории `scripts/`.

Сервис также поддерживает отправку уведомлений в Telegram — как глобально, так и индивидуально для каждого проекта.

📦 Теперь имя bash-скрипта для запуска формируется по схеме:
**<project.name>-<project.id>.sh**
(например: `frontend-53.sh`), где `53` — это значение поля `project.id` из GitLab webhook.

В уведомления Telegram добавлены:
- идентификатор проекта (project.id);
- номер pipeline;
- ветка (ref);
- коммит (ссылка и сообщение);
- автор коммита и пользователь, запустивший pipeline;
- ссылки на commit и pipeline в GitLab.

---

## 🚀 Возможности

- Принимает вебхуки от GitLab (pipeline success);
- Выполняет bash-скрипт, соответствующий схеме `<project.name>-<project.id>.sh`;
  (например: `frontend-53.sh`);
- Поддерживает персональные Telegram-настройки для каждого проекта;
- Гибкая конфигурация через YAML и переменные окружения;
- Возможность перезагрузки конфигурации без перезапуска (/reload);
- Защита вебхуков через секретный токен (X-Gitlab-Token);
- Поддержка гибких путей (CONFIG_PATH, SCRIPTS_DIR);
- Полностью контейнеризирован (Docker + Compose);
- Уведомления о запуске и результате выполнения в Telegram
- Поддерживает healthcheck-эндпоинт `/healthz` (возвращает HTTP 200 и текст `ok`);

---

## 📂 Структура проекта

```
gitlab-webhook-manager/
├── main.go
├── go.mod
├── Dockerfile
├── docker-compose.yml
├── README.md
├── config/
│   └── config.yaml
└── scripts/
    ├── project-a.sh
    └── project-b.sh
```

---

## ⚙️ Конфигурация

Файл: `/app/config/config.yaml`

```yaml
# Порт, на котором слушает сервис
port: 8080

# 🔒 Секретный токен — защита от несанкционированных запросов
# Укажите тот же токен в GitLab Webhook (в поле "Secret Token")
secret_token: "very-secret-token"

# Глобальные настройки Telegram
telegram:
  enabled: true
  token: "123456789:ABCDEF123456789abcdef"
  chat_id: "987654321"

# Настройки отдельных проектов
projects:
  project-example:
    telegram:
      enabled: true
      chat_id: "111111111" # переопределение чата

  project-b:
    telegram:
      enabled: false # Telegram отключён для этого проекта
```

🧠 **Приоритет настроек**:
1. Для конкретного проекта (если указано);
2. Глобальные настройки Telegram.

---

## 🐳 Установка и запуск

### 1. Склонируйте репозиторий

```bash
git clone https://github.com/your-org/gitlab-webhook-manager.git
cd gitlab-webhook-manager
```

### 2. Создайте внешние директории (если они отсутствуют)

```bash
mkdir -p /srv/gitlab-webhook-manager/{config,scripts}
cp config/config.yaml /srv/gitlab-webhook-manager/config/
cp scripts/* /srv/gitlab-webhook-manager/scripts/
```

### 3. Соберите Docker-образ

```bash
docker build -t gitlab-webhook-manager .
```

### 4. Запустите через Docker Compose

```bash
docker compose up -d
```

---

## 🧩 Docker Compose

```yaml
services:
  gitlab-webhook-manager:
    image: gitlab-webhook-manager:latest
    container_name: gitlab-webhook-manager
    restart: always

    volumes:
      - ./config:/app/config:ro
      - ./scripts:/app/scripts:ro

    ports:
      - "8080:8080"

    environment:
      CONFIG_PATH: /app/config/config.yaml
      SCRIPTS_DIR: /app/scripts
      SHOW_SECRET: true
```

---

## 🔗 Интеграция с GitLab

1. В GitLab откройте ваш проект → **Settings → Webhooks**
2. Укажите URL вашего сервиса:

   ```
   http://<your-server>:8080/
   ```

3. Отметьте галочку **“Pipeline events”**
4. Нажмите **“Add webhook”**
5. Укажите ваш **Secret Token**, совпадающий с полем `secret_token` в config.yaml

Теперь при каждом успешном пайплайне GitLab отправит POST-запрос в Runner.

⚙️ Сервис определяет имя скрипта на основе поля `project.id` из webhook.
Пример: если GitLab прислал `"name": "frontend"` и `"id": 53`, то будет
запущен скрипт `scripts/frontend-53.sh`.

---

## 🧪 Тестирование вручную

Эмуляция GitLab webhook:

```bash
# 🧪 Пример вызова webhook с секретным токеном
curl -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -H "X-Gitlab-Token: very-secret-token" \
  -d '{
    "object_kind":"pipeline",
    "object_attributes":{"status":"success","id":54,"ref":"dev","url":"https://git.rusit-po.ru/.../pipelines/54"},
    "project":{"id":53,"name":"frontend","path_with_namespace":"ballons/kriogen/frontend"},
    "commit":{"id":"85fe88f7e84637...","message":"msg","url":"https://git.rusit-po.ru/.../commit/85fe88f7","author":{"name":"Alex"}},
    "user":{"name":"Alex"}
  }
```

✅ Ожидается:
- Запуск скрипта `scripts/frontend-53.sh` (имя формируется из <project.name>-<project.id>);
- Лог в консоли;
- Telegram-уведомление о старте и завершении деплоя.

```bash
# 🆕 Пример перезагрузки конфига во время работы
curl -X POST http://localhost:8080/reload -H "X-Gitlab-Token: very-secret-token"
```
✅ Ожидается:
Config reloaded successfully

---

## 📜 Пример скрипта

`scripts/frontend-53.sh`:

⚠️ Имя скрипта должно строго соответствовать шаблону `<project.name>-<project.id>.sh`.
Например, если проект называется `frontend`, а его ID в GitLab — `53`,
то файл должен называться `frontend-53.sh`.

```bash
#!/bin/bash
set -e
echo "[INFO] Deploying Project Example..."
sleep 1
echo "[INFO] Done!"
```

Не забудьте выдать права:
```bash
chmod +x scripts/*.sh
```

---

## ⚙️ Переменные окружения

| Переменная    | Описание                                                 | Значение по умолчанию     |
| ------------- | -------------------------------------------------------- | ------------------------- |
| `CONFIG_PATH` | Путь до файла конфигурации                               | `/app/config/config.yaml` |
| `SCRIPTS_DIR` | Каталог, где хранятся скрипты                            | `/app/scripts`            |
| `SHOW_SECRET` | Если `true`, при старте логирует значение `secret_token` | `false`                   |
| `PORT`        | Порт сервера (если не указан в конфиге)                  | `8080`                    |


---

## 🧰 Разработка

### Локальный запуск (без Docker)
```bash
export CONFIG_PATH=./config/config.yaml
export SCRIPTS_DIR=./scripts
export SHOW_SECRET=true
go run main.go
```

Конфиг должен находиться в `./config/config.yaml`.

### Форматирование и проверка кода
```bash
go fmt ./...
go vet ./...
```

---

## 📦 Сборка бинарника
```bash
go build -o gitlab-webhook-manager main.go
```

---

## 🔒 Безопасность

- Все запросы (/ и /reload) проверяются по заголовку X-Gitlab-Token.
- Если токен неверный или отсутствует — возвращается 401 Unauthorized.
- Значение токена скрыто в логах по умолчанию, но может быть показано при SHOW_SECRET=true.
- Сервис не требует авторизации, поэтому рекомендуется ограничить доступ по IP (например, только GitLab).

---

## 🧾 Лицензия

MIT License
Автор: Yaroslav Tsuprak (@netvirus)
© 2025

---

## ❤️ Благодарности

Проект вдохновлён идеей простого DevOps-автоматизатора:
“Успешный pipeline → автоматическое действие”.
Подходит для интеграций, CI/CD-триггеров и лёгких деплоев без тяжёлых GitLab Runner’ов.
