MOCKGEN ?= mockgen
MOCKS_DIR := $(CURDIR)/test_helpers/mocks

mocks: $(MOCKS_DIR)/gen_backend.go
.PHONY: mocks

$(MOCKS_DIR)/gen_backend.go:
	$(MOCKGEN) --package mocks --destination $@ \
		github.com/openrelayxyz/plugeth-utils/core Backend,Downloader

docker: mocks
	docker build . -t "cerc/plugeth-statediff:local"
.PHONY: docker
