FROM golang:1.22-alpine AS build

WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN go build -o /out/backend .

FROM alpine:3.20

WORKDIR /app
COPY --from=build /out/backend /app/backend
EXPOSE 8080
CMD ["/app/backend"]
