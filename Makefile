SHELL = /bin/bash
SERVICE_NAME = $(notdir $(CURDIR))
LATEST_TAG = vnext
VERSION_TAG = vnext-$(shell git rev-parse --short=7 --verify HEAD)

default: build

define build-docker-image
	docker build \
		--network=host \
		--tag ocfcloud/$(SERVICE_NAME):$(VERSION_TAG) \
		--tag ocfcloud/$(SERVICE_NAME):$(LATEST_TAG) \
		--target $(1) \
		.
endef

build-testcontainer:
	$(call build-docker-image,build)

build-servicecontainer:
	$(call build-docker-image,service)

build: build-testcontainer build-servicecontainer

make-ca:
	#docker pull smallstep/step-ca
	mkdir -p ./test/step-ca/data/secrets
	echo "password" > ./test/step-ca/data/secrets/password
	docker run \
		-it \
		-v "$(shell pwd)"/test/step-ca/data:/home/step --user $(shell id -u):$(shell id -g) \
		ocf-step-ca:latest \
		/bin/bash -c "step ca init -dns localhost -address=:10443 -provisioner=test@localhost -name test -password-file ./secrets/password && step ca provisioner add acme --type ACME"

run-ca:
    #docker rm -f ocf-step-ca || true
	docker rm -f ocf-step-ca || true
	docker run \
		-d \
		--network=host \
		--name=ocf-step-ca \
		-v /etc/nsswitch.conf:/etc/nsswitch.conf \
		-v "$(shell pwd)"/test/step-ca/data:/home/step --user $(shell id -u):$(shell id -g) \
		ocf-step-ca:latest

test: clean build-testcontainer
	docker run \
		--network=host \
		--mount type=bind,source="$(shell pwd)",target=/shared \
		ocfcloud/$(SERVICE_NAME):$(VERSION_TAG) \
		go test -v ./... -covermode=atomic -coverprofile=/shared/coverage.txt

push: build-servicecontainer
	docker push ocfcloud/$(SERVICE_NAME):$(VERSION_TAG)
	docker push ocfcloud/$(SERVICE_NAME):$(LATEST_TAG)

clean:

.PHONY: build-testcontainer build-servicecontainer build test push clean proto/generate make-ca
