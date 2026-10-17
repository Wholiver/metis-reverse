GO ?= go
BIN_DIR = bin
TARGET_UNSTRIPPED = $(BIN_DIR)/go_pipeline_unstripped
TARGET_STRIPPED = $(BIN_DIR)/go_pipeline_stripped

all: $(TARGET_UNSTRIPPED) $(TARGET_STRIPPED)

$(TARGET_UNSTRIPPED): cmd/pipeline/main.go pkg/*/*.go
	mkdir -p $(BIN_DIR)
	$(GO) build -o $@ ./cmd/pipeline

$(TARGET_STRIPPED): cmd/pipeline/main.go pkg/*/*.go
	mkdir -p $(BIN_DIR)
	$(GO) build -ldflags="-s -w" -trimpath -o $@ ./cmd/pipeline

clean:
	rm -rf $(BIN_DIR)

.PHONY: all clean
