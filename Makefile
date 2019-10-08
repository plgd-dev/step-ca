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
