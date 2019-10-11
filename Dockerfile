FROM golang:1.13.1-alpine3.10 AS build
RUN apk add --no-cache curl git build-base && \
	curl -SL -o /usr/bin/dep https://github.com/golang/dep/releases/download/v0.5.0/dep-linux-amd64 && \
	chmod +x /usr/bin/dep
WORKDIR $GOPATH/src/github.com/go-ocf/step-ca
COPY . .

RUN dep ensure -v --vendor-only
RUN go build -o /go/bin/service ./cmd/service

FROM smallstep/step-cli:latest as service
ENV CONFIGPATH="/home/step/config/ca.json"
ENV PWDPATH="/home/step/secrets/password"

COPY --from=build /go/bin/service /usr/local/bin/service

VOLUME ["/home/step"]
STOPSIGNAL SIGTERM

CMD exec /bin/sh -c "/usr/local/bin/service --password-file $PWDPATH $CONFIGPATH"