FROM golang:1.13.11-alpine3.10 AS build
RUN apk add --no-cache curl git build-base
WORKDIR $GOPATH/src/github.com/go-ocf/step-ca
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /go/bin/service ./cmd/service

FROM smallstep/step-cli:latest as service
ENV CONFIGPATH="/home/step/config/ca.json"
ENV PWDPATH="/home/step/secrets/password"

COPY --from=build /go/bin/service /usr/local/bin/step-ca

VOLUME ["/home/step"]
STOPSIGNAL SIGTERM

CMD exec /bin/sh -c "/usr/local/bin/step-ca --password-file $PWDPATH $CONFIGPATH"
