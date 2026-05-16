FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/test-web-ui .

FROM alpine:3.22

RUN adduser -D -H -u 10001 appuser
WORKDIR /app

COPY --from=build /out/test-web-ui /usr/local/bin/test-web-ui

USER appuser
EXPOSE 8090

ENTRYPOINT ["test-web-ui"]
