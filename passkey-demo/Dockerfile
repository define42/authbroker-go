FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/passkey-demo .

FROM alpine:3.22

RUN adduser -D -H -u 10001 appuser
WORKDIR /app

COPY --from=build /out/passkey-demo /usr/local/bin/passkey-demo

USER appuser
EXPOSE 8091

ENTRYPOINT ["passkey-demo"]
