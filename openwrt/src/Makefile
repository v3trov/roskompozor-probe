CC ?= cc
PKG_CONFIG ?= pkg-config
CFLAGS ?= -Os
CFLAGS += -std=c11 -Wall -Wextra -Werror -Wno-misleading-indentation -ffunction-sections -fdata-sections
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags openssl json-c libcurl libidn)
LDLIBS += $(shell $(PKG_CONFIG) --libs openssl json-c libcurl libidn) -lpthread -lm
LDFLAGS += -Wl,--gc-sections

all: roskompozor-probe
roskompozor-probe: probe.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) $(LDLIBS) -o $@
clean:
	rm -f roskompozor-probe
.PHONY: all clean
