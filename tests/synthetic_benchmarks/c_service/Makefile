CC ?= clang
CFLAGS ?= -O2 -Wall -Wextra -std=c11 -fno-ident
STRIP ?= /usr/bin/strip

SRC = src/main.c src/config.c src/parser.c
BIN_DIR = bin
TARGET_UNSTRIPPED = $(BIN_DIR)/c_service_unstripped
TARGET_STRIPPED = $(BIN_DIR)/c_service_stripped

all: $(TARGET_UNSTRIPPED) $(TARGET_STRIPPED)

$(TARGET_UNSTRIPPED): $(SRC)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC)

$(TARGET_STRIPPED): $(TARGET_UNSTRIPPED)
	mkdir -p $(BIN_DIR)
	cp $(TARGET_UNSTRIPPED) $@
	$(STRIP) $@ || $(STRIP) -x $@

clean:
	rm -rf $(BIN_DIR)

.PHONY: all clean
