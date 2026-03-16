BIN = curly.exe
SRC = curly.c
COSMO_DIR = cosmo
TMP_DIR = tmp

COSMO_URL = https://cosmo.zip/pub/cosmo/cosmopolitan-4.0.2.tar.gz
COSMOCC_URL = https://cosmo.zip/pub/cosmocc/cosmocc.zip

COSMO_TAR = $(TMP_DIR)/cosmopolitan.tar.gz
COSMOCC_ZIP = $(TMP_DIR)/cosmocc.zip

COSMOCC = $(COSMO_DIR)/bin/cosmocc

# Cosmopolitan & MbedTLS configuration
# -Wno-prio-ctor-dtor: Suppresses warnings about reserved constructor priorities
# -Wa,-W: Suppresses all assembler warnings
CFLAGS = -I$(COSMO_DIR) \
         -D_COSMO_SOURCE \
         -DMBEDTLS_USER_CONFIG_FILE="<third_party/mbedtls/config.h>" \
         -include stdbool.h \
         -include libc/integral/normalize.inc \
         -include libc/serialize.h \
         -Wno-prio-ctor-dtor \
         -Wa,-W

.PHONY: all setup download extract clean distclean test

all: $(BIN)

# Only download if files are missing
download:
	@mkdir -p $(TMP_DIR)
	@if [ ! -f "$(COSMO_TAR)" ]; then \
		echo "Downloading Cosmopolitan source..."; \
		curl -L $(COSMO_URL) -o $(COSMO_TAR); \
	fi
	@if [ ! -f "$(COSMOCC_ZIP)" ]; then \
		echo "Downloading cosmocc toolchain..."; \
		curl -L $(COSMOCC_URL) -o $(COSMOCC_ZIP); \
	fi

# Only extract if cosmo directory is missing
extract: download
	@if [ ! -d "$(COSMO_DIR)" ]; then \
		mkdir -p $(COSMO_DIR); \
		echo "Extracting source..."; \
		tar -xz -C $(COSMO_DIR) --strip-components=1 -f $(COSMO_TAR); \
		echo "Extracting toolchain..."; \
		unzip -q -o $(COSMOCC_ZIP) -d $(COSMO_DIR); \
	fi

setup: extract

$(BIN): setup $(SRC)
	@echo "Building $(BIN)..."
	@$(COSMOCC) -o $@ $(SRC) $(CFLAGS) \
		$$(find $(COSMO_DIR)/third_party/mbedtls -maxdepth 1 -name "*.c" | grep -vE "test|programs|main\.c")
	@-cp -f $(BIN) curly
	@echo "Build complete. Run with ./$(BIN) or ./curly"

test: $(BIN)
	./curly https://www.google.com | head -n 20

clean:
	rm -f $(BIN) curly

distclean: clean
	rm -rf $(COSMO_DIR) $(TMP_DIR)
