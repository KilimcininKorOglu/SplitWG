.PHONY: build build-amd64 build-arm64 build-universal \
        bundle bundle-universal bundle-intel bundle-arm \
        dmg dmg-intel dmg-arm release release-unsigned install clean \
        notarize sign-minisign

APP        = SplitWG.app
APP_INTEL  = SplitWG-intel.app
APP_ARM    = SplitWG-arm.app
BIN        = splitwg
BIN_INTEL  = splitwg-amd64
BIN_ARM    = splitwg-arm64
HELPER        = splitwg-helper
HELPER_INTEL  = splitwg-helper-amd64
HELPER_ARM    = splitwg-helper-arm64
DMG        = dist/SplitWG.dmg
DMG_INTEL  = dist/SplitWG-intel.dmg
DMG_ARM    = dist/SplitWG-arm.dmg

TARGET_AMD64 = x86_64-apple-darwin
TARGET_ARM64 = aarch64-apple-darwin

VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# ─── Signing configuration ─────────────────────────────────────────────────────
#
# DEV_ID is auto-detected from the keychain. On machines without a Developer ID
# certificate installed the value is empty and we fall back to ad-hoc signing,
# which keeps local development functional. CI injects the certificate before
# invoking make.
DEV_ID            ?= $(shell security find-identity -v -p codesigning 2>/dev/null | \
                       awk -F'"' '/Developer ID Application/{print $$2; exit}')
ENTITLEMENTS      = splitwg.entitlements
NOTARY_PROFILE    ?= splitwg-notary
MINISIGN_KEY      ?= $(HOME)/.minisign/splitwg.key

# Emits the codesign invocation used by every bundle target. Defined once so
# hardened-runtime flags stay in sync across single-arch, universal, intel and
# arm bundles.
define CODESIGN_APP
	@if [ -n "$(DEV_ID)" ]; then \
	    echo "codesign: Developer ID — $(DEV_ID)"; \
	    codesign --sign "$(DEV_ID)" --options runtime \
	             --entitlements $(ENTITLEMENTS) \
	             --force --timestamp --deep $(1); \
	else \
	    echo "codesign: ad-hoc (no Developer ID in keychain)"; \
	    codesign --sign - --force --deep $(1); \
	fi
endef

# ─── Build ─────────────────────────────────────────────────────────────────────

build:
	cargo build --release --bin splitwg --bin splitwg-helper
	cp target/release/splitwg $(BIN)
	cp target/release/splitwg-helper $(HELPER)

build-amd64:
	MACOSX_DEPLOYMENT_TARGET=10.15 cargo build --release --target $(TARGET_AMD64) \
	    --bin splitwg --bin splitwg-helper
	cp target/$(TARGET_AMD64)/release/splitwg $(BIN_INTEL)
	cp target/$(TARGET_AMD64)/release/splitwg-helper $(HELPER_INTEL)

build-arm64:
	MACOSX_DEPLOYMENT_TARGET=11.0 cargo build --release --target $(TARGET_ARM64) \
	    --bin splitwg --bin splitwg-helper
	cp target/$(TARGET_ARM64)/release/splitwg $(BIN_ARM)
	cp target/$(TARGET_ARM64)/release/splitwg-helper $(HELPER_ARM)

build-universal: build-amd64 build-arm64
	lipo -create -output $(BIN) $(BIN_INTEL) $(BIN_ARM)
	lipo -create -output $(HELPER) $(HELPER_INTEL) $(HELPER_ARM)
	@lipo -info $(BIN)
	@lipo -info $(HELPER)

# ─── Bundle ────────────────────────────────────────────────────────────────────

bundle: build
	rm -rf $(APP)
	mkdir -p $(APP)/Contents/MacOS $(APP)/Contents/Resources
	cp $(BIN) $(APP)/Contents/MacOS/splitwg
	cp $(HELPER) $(APP)/Contents/MacOS/splitwg-helper
	cp icon/splitwg.icns $(APP)/Contents/Resources/AppIcon.icns
	cp Info.plist $(APP)/Contents/
	$(call CODESIGN_APP,$(APP))

bundle-universal: build-universal
	rm -rf $(APP)
	mkdir -p $(APP)/Contents/MacOS $(APP)/Contents/Resources
	cp $(BIN) $(APP)/Contents/MacOS/splitwg
	cp $(HELPER) $(APP)/Contents/MacOS/splitwg-helper
	cp icon/splitwg.icns $(APP)/Contents/Resources/AppIcon.icns
	cp Info.plist $(APP)/Contents/
	$(call CODESIGN_APP,$(APP))

bundle-intel: build-amd64
	rm -rf $(APP_INTEL)
	mkdir -p $(APP_INTEL)/Contents/MacOS $(APP_INTEL)/Contents/Resources
	cp $(BIN_INTEL) $(APP_INTEL)/Contents/MacOS/splitwg
	cp $(HELPER_INTEL) $(APP_INTEL)/Contents/MacOS/splitwg-helper
	cp icon/splitwg.icns $(APP_INTEL)/Contents/Resources/AppIcon.icns
	cp Info.plist $(APP_INTEL)/Contents/
	$(call CODESIGN_APP,$(APP_INTEL))

bundle-arm: build-arm64
	rm -rf $(APP_ARM)
	mkdir -p $(APP_ARM)/Contents/MacOS $(APP_ARM)/Contents/Resources
	cp $(BIN_ARM) $(APP_ARM)/Contents/MacOS/splitwg
	cp $(HELPER_ARM) $(APP_ARM)/Contents/MacOS/splitwg-helper
	cp icon/splitwg.icns $(APP_ARM)/Contents/Resources/AppIcon.icns
	cp Info.plist $(APP_ARM)/Contents/
	$(call CODESIGN_APP,$(APP_ARM))

# ─── DMG ───────────────────────────────────────────────────────────────────────

# Universal Binary DMG — one file for both Intel and Apple Silicon (primary artifact).
dmg: bundle-universal
	mkdir -p dist
	bash scripts/make-dmg.sh "$(APP)" "$(DMG)" "SplitWG"

# Intel-only DMG (smaller download for x86_64 users).
dmg-intel: bundle-intel
	mkdir -p dist
	bash scripts/make-dmg.sh "$(APP_INTEL)" "$(DMG_INTEL)" "SplitWG"

# Apple Silicon-only DMG (smaller download for arm64 users).
dmg-arm: bundle-arm
	mkdir -p dist
	bash scripts/make-dmg.sh "$(APP_ARM)" "$(DMG_ARM)" "SplitWG"

# ─── Notarization + minisign ──────────────────────────────────────────────────
#
# notarize uploads each produced DMG to Apple and waits (typically 2–10 min),
# then staples the ticket. The notary profile must be pre-seeded via
# `xcrun notarytool store-credentials $(NOTARY_PROFILE) …`. See README.
notarize:
	@for img in $(DMG) $(DMG_INTEL) $(DMG_ARM); do \
	    if [ -f "$$img" ]; then \
	        echo "notarize: $$img"; \
	        xcrun notarytool submit "$$img" \
	            --keychain-profile "$(NOTARY_PROFILE)" --wait; \
	        xcrun stapler staple "$$img"; \
	    fi; \
	done

# sign-minisign produces `<dmg>.minisig` sibling files. The private key is read
# from MINISIGN_KEY (default ~/.minisign/splitwg.key); minisign prompts for the
# passphrase interactively unless MINISIGN_PASSWORD is exported.
sign-minisign:
	@for img in $(DMG) $(DMG_INTEL) $(DMG_ARM); do \
	    if [ -f "$$img" ]; then \
	        echo "minisign: $$img"; \
	        minisign -S -s "$(MINISIGN_KEY)" -m "$$img"; \
	    fi; \
	done

# Full release: build all three DMGs, notarize + staple, and produce minisign
# sidecars. Intended for CI; locally requires Developer ID + notary profile +
# minisign key.
release: dmg dmg-intel dmg-arm notarize sign-minisign
	@echo ""
	@echo "Release artifacts ($(VERSION)):"
	@ls -lh dist/*.dmg dist/*.minisig 2>/dev/null || true

# release-unsigned skips notarize + minisign for quick local smoke tests.
release-unsigned: dmg dmg-intel dmg-arm
	@echo ""
	@echo "Unsigned release artifacts ($(VERSION)):"
	@ls -lh dist/*.dmg

# ─── Misc ──────────────────────────────────────────────────────────────────────

install: bundle
	cp -r $(APP) /Applications/

clean:
	cargo clean
	rm -rf $(BIN) $(BIN_INTEL) $(BIN_ARM) \
	       $(HELPER) $(HELPER_INTEL) $(HELPER_ARM) \
	       $(APP) $(APP_INTEL) $(APP_ARM) \
	       dist/
