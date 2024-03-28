MOCKGEN ?= mockgen
MOCKS_DIR := $(CURDIR)/test_helpers/mocks
BUILD_DIR ?= ./build

mocks: $(MOCKS_DIR)/gen_backend.go
.PHONY: mocks

$(MOCKS_DIR)/gen_backend.go:
	$(MOCKGEN) --package mocks --destination $@ \
		github.com/openrelayxyz/plugeth-utils/core Backend,Downloader

docker-image: mocks
	docker build . -t "cerc/plugeth-statediff:local" \
		--build-arg GIT_VDBTO_TOKEN
.PHONY: docker-image

# Local build
BUILD_FLAGS := --trimpath

plugin: $(BUILD_DIR)/lib/statediff.so
.PHONY: plugin

$(BUILD_DIR)/lib/statediff.so: ./**/*.go
	go build --tags linkgeth --buildmode=plugin -o $@ $(BUILD_FLAGS) ./main
