# Мультистадийный билд
FROM golang:1.25.4-alpine AS builder

WORKDIR /app

# Копируем файлы модулей
COPY go.mod go.sum ./
RUN go mod download

# Копируем исходный код
COPY . .

# Билдим статический бинарник
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-w -s -extldflags "-static"' -a -o main ./cmd

# Используем distroless для безопасности
FROM gcr.io/distroless/static-debian12

WORKDIR /app

# Копируем бинарник
COPY --from=builder /app/main .

# Пользователь без привилегий
USER nonroot:nonroot

EXPOSE 3000

CMD ["./main"]