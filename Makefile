# ==== Paths ====
BIN_DIR := bin
APP     := $(BIN_DIR)/syncLauperDongleMaker

KEY_ROOT := $(BIN_DIR)/keys
PROV_DIR := $(KEY_ROOT)/provisioning
RP_DIR   := $(KEY_ROOT)/rp
ART_DIR  := $(BIN_DIR)/artifacts

# ==== Defaults for run targets (override at call time) ====
DEVICE   ?= /dev/sdX
MOUNT    ?= /media/usb
LICENSEE ?= ACME Inc.
README   ?=
YES      ?= --yes
PRIV     ?= keys/provisioning/privkey.pem   # bin을 CWD로 잡으므로 keys/...가 bin/keys/...를 가리킴
PUB      ?= keys/provisioning/pubkey.pem
PORT     ?= /dev/ttyACM0

.PHONY: all build rebuild run run-bake run-verify run-probe keygen-prov keygen-rp sanity clean help
all: build

## Build binary to bin/
build:
	@mkdir -p $(BIN_DIR)
	@go build -o $(APP) ./cmd/syncLauperDongleMaker
	@echo "built: $(APP)"

## Rebuild from scratch
rebuild:
	@go clean -cache
	@$(MAKE) -s clean
	@$(MAKE) -s build

## Quick run (prints usage)
run: build
	@cd $(BIN_DIR) && ./$(notdir $(APP)) -h || true

## Bake USB (DEVICE, LICENSEE, PRIV, README, YES)
run-bake: build
	@mkdir -p $(PROV_DIR)
	@cd $(BIN_DIR) && ./$(notdir $(APP)) bake \
		--device "$(DEVICE)" \
		--licensee "$(LICENSEE)" \
		--priv "$(PRIV)" \
		$(if $(README),--readme "$(README)",) \
		$(YES)

## Verify USB (MOUNT, PUB)
run-verify: build
	@cd $(BIN_DIR) && ./$(notdir $(APP)) verify \
		--mount "$(MOUNT)" \
		--pub   "$(PUB)" \
		--detail

## Probe (pick one of DEVICE / MOUNT / PORT)
run-probe: build
	@cd $(BIN_DIR) && ( \
		if [ -n "$(DEVICE)" ]; then \
			./$(notdir $(APP)) probe --device "$(DEVICE)" --detail; \
		elif [ -n "$(MOUNT)" ]; then \
			./$(notdir $(APP)) probe --mount  "$(MOUNT)"  --detail; \
		elif [ -n "$(PORT)" ]; then \
			./$(notdir $(APP)) probe --port   "$(PORT)"   --detail; \
		else \
			echo "Set one of DEVICE/MOUNT/PORT"; exit 2; \
		fi )

## Generate provisioning keypair under bin/keys/provisioning
keygen-prov: build
	@mkdir -p $(PROV_DIR)
	@cd $(BIN_DIR) && ./$(notdir $(APP)) keygen \
		--out-priv keys/provisioning/privkey.pem \
		--out-pub  keys/provisioning/pubkey.pem
	@chmod 600 $(PROV_DIR)/privkey.pem
	@echo "keys: $(PROV_DIR)/{privkey.pem,pubkey.pem}"

## Generate RP keypair under bin/keys/rp
keygen-rp: build
	@mkdir -p $(RP_DIR)
	@cd $(BIN_DIR) && ./$(notdir $(APP)) keygen \
		--out-priv keys/rp/privkey.pem \
		--out-pub  keys/rp/pubkey.pem
	@chmod 600 $(RP_DIR)/privkey.pem
	@echo "keys: $(RP_DIR)/{privkey.pem,pubkey.pem}"

## E2E sanity via loopback (Linux; requires sudo, mkfs.vfat, losetup)
sanity: build
	@mkdir -p $(ART_DIR) $(PROV_DIR)
	@bash -eu -o pipefail -c '\
		IMG=$$(mktemp $(ART_DIR)/dongle-XXXX.img); \
		truncate -s 64M $$IMG; \
		LOOP=$$(sudo losetup --find --show -P $$IMG); \
		trap "sudo losetup -d $$LOOP || true" EXIT; \
		cd $(BIN_DIR); \
		[ -f keys/provisioning/privkey.pem ] || ./$(notdir $(APP)) keygen --out-priv keys/provisioning/privkey.pem --out-pub keys/provisioning/pubkey.pem; \
		chmod 600 keys/provisioning/privkey.pem; \
		sudo ./$(notdir $(APP)) bake --device $$LOOP --licensee "SANITY" --priv keys/provisioning/privkey.pem --yes; \
		PART="$${LOOP}p1"; [ -b "$$PART" ] || PART="$$LOOP"; \
		MP=$$(mktemp -d); \
		trap "sudo umount $$MP || true; rmdir $$MP || true; sudo losetup -d $$LOOP || true" EXIT; \
		sudo mount -o ro $$PART $$MP; \
		./$(notdir $(APP)) verify --mount $$MP --pub keys/provisioning/pubkey.pem --detail; \
		echo "sanity OK" \
	'

clean:
	@rm -rf $(BIN_DIR)

help:
	@echo "Targets:"
	@echo "  build         - Build to $(APP)"
	@echo "  rebuild       - Clean cache and rebuild"
	@echo "  run           - Show usage"
	@echo "  run-bake      - Bake USB (override DEVICE, LICENSEE, PRIV, README, YES)"
	@echo "  run-verify    - Verify USB (override MOUNT, PUB)"
	@echo "  run-probe     - Probe (uses DEVICE/MOUNT/PORT)"
	@echo "  keygen-prov   - Generate provisioning keypair in $(PROV_DIR)"
	@echo "  keygen-rp     - Generate RP keypair in $(RP_DIR)"
	@echo "  sanity        - Loopback end-to-end test (Linux)"
	@echo "  clean         - Remove bin"
