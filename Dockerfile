FROM golang:1.26-alpine AS builder
WORKDIR /app

# Copiar todo el espacio de trabajo
COPY . .

WORKDIR /app/backend
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /messenger-backend main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /
COPY --from=builder /messenger-backend /messenger-backend
# Exponer puerto dinámico de Render
ENV PORT=8080
EXPOSE 8080
CMD ["/messenger-backend"]
