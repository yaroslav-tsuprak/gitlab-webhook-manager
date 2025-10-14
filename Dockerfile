# ===== Stage 1: Build =====
FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o gitlab-webhook-manager main.go


# ===== Stage 2: Runtime =====
FROM alpine:3.20

RUN apk add --no-cache bash

WORKDIR /app

# Только бинарник — всё остальное монтируем снаружи
COPY --from=builder /app/gitlab-webhook-manager /app/gitlab-webhook-manager

# Создаём папки, куда будем монтировать конфиг и скрипты
VOLUME ["/app/config", "/app/scripts"]

EXPOSE 8080

# Запуск с внешним конфигом
CMD ["/app/gitlab-webhook-manager"]
