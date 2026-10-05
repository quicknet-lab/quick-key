MAIN := ../../main
IDF_PATH ?= $(HOME)/esp/esp-idf
MBEDTLS := $(IDF_PATH)/components/mbedtls/mbedtls
CFLAGS := -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror -g -fsanitize=address,undefined -I$(MAIN) -Istub -I$(MBEDTLS)/include
SRCS := test_main.c $(MAIN)/fido/cbor.c $(MAIN)/apdu/apdu.c $(MAIN)/core/crypto.c $(MAIN)/core/vault.c $(MAIN)/core/devpin.c $(MAIN)/core/pinstore.c $(MAIN)/apps/pwd_rec.c stub/store_mem.c stub/partition_mem.c stub/chipkey_soft.c \
        $(MAIN)/third_party/monocypher/monocypher.c $(MAIN)/third_party/monocypher/monocypher-ed25519.c

# mbedTLS from ESP-IDF with its default config, built once without sanitizers.
MBEDTLS_OBJS := $(patsubst $(MBEDTLS)/library/%.c,mbedtls/%.o,$(wildcard $(MBEDTLS)/library/*.c))

test: $(SRCS) mbedtls.a
	$(CC) $(CFLAGS) -o $@ $^
	./test

mbedtls.a: $(MBEDTLS_OBJS)
	$(AR) rcs $@ $^

mbedtls/%.o: $(MBEDTLS)/library/%.c
	@mkdir -p mbedtls
	$(CC) -O2 -I$(MBEDTLS)/include -I$(MBEDTLS)/library -c -o $@ $<

clean:
	rm -rf test mbedtls mbedtls.a
