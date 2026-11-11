MAIN := ../../main
IDF_PATH ?= $(HOME)/esp/esp-idf
MBEDTLS := $(IDF_PATH)/components/mbedtls/mbedtls
CFLAGS := -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror -g -fsanitize=address,undefined -I$(MAIN) -Istub -I$(MBEDTLS)/include
SRCS := test_main.c $(MAIN)/fido/cbor.c $(MAIN)/apdu/apdu.c $(MAIN)/core/crypto.c $(MAIN)/core/vault.c $(MAIN)/core/devpin.c $(MAIN)/core/pinstore.c $(MAIN)/apps/pwd_rec.c stub/store_mem.c stub/partition_mem.c stub/chipkey_soft.c \
        $(MAIN)/third_party/monocypher/monocypher.c $(MAIN)/third_party/monocypher/monocypher-ed25519.c
# The OTP application with the real APDU helpers, vault and device PIN.
OATH_SRCS := test_oath.c $(MAIN)/apps/oath.c $(MAIN)/apdu/apdu.c $(MAIN)/core/crypto.c $(MAIN)/core/vault.c $(MAIN)/core/devpin.c $(MAIN)/core/pinstore.c stub/store_mem.c stub/partition_mem.c stub/chipkey_soft.c \
        $(MAIN)/third_party/monocypher/monocypher.c $(MAIN)/third_party/monocypher/monocypher-ed25519.c

# mbedTLS from ESP-IDF with its default config, built once without sanitizers.
MBEDTLS_OBJS := $(patsubst $(MBEDTLS)/library/%.c,mbedtls/%.o,$(wildcard $(MBEDTLS)/library/*.c))

test: $(SRCS) mbedtls.a test_oath
	$(CC) $(CFLAGS) -o $@ $(SRCS) mbedtls.a
	./test
	./test_oath

test_oath: $(OATH_SRCS) mbedtls.a
	$(CC) $(CFLAGS) -o $@ $^

mbedtls.a: $(MBEDTLS_OBJS)
	$(AR) rcs $@ $^

mbedtls/%.o: $(MBEDTLS)/library/%.c
	@mkdir -p mbedtls
	$(CC) -O2 -I$(MBEDTLS)/include -I$(MBEDTLS)/library -c -o $@ $<

# Draws every screen into PPM files for a look: make ui_preview && ./ui_preview DIR
ui_preview: ui_preview.c $(MAIN)/ui/ui_draw.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf test test.dSYM test_oath test_oath.dSYM ui_preview ui_preview.dSYM mbedtls mbedtls.a
