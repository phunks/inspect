set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

RAMA_REPO := "https://github.com/plabayo/rama.git"
RAMA_TAG := "rama-0.3.0-alpha.4"
RAMA_DIR := "ext/rama"
RAMA_PATCH := "patches/rama-0.3.0-alpha.4-tls-fix.patch"

TUIE_REPO := "https://github.com/phunks/tuie.git"
TUIE_REV := "665f2b223ec237a1eb51ccf562d004ce888affaf"
TUIE_DIR := "ext/tuie"
TUIE_PATCH := "patches/tuie-0.2.3-scroll-fix.patch"

# Show available commands
default:
    @just --list

# Clone rama into ext/rama and apply local TLS patch.
setup-rama:
    mkdir -p ext
    if [ ! -d "{{RAMA_DIR}}/.git" ]; then \
      git clone --depth 1 --branch "{{RAMA_TAG}}" "{{RAMA_REPO}}" "{{RAMA_DIR}}"; \
    else \
      echo "{{RAMA_DIR}} already exists; skipping clone"; \
    fi
    cd "{{RAMA_DIR}}" && git apply --check "../../{{RAMA_PATCH}}"
    cd "{{RAMA_DIR}}" && git apply "../../{{RAMA_PATCH}}"

# Reset ext/rama to the target tag and re-apply local TLS patch.
reset-rama:
    test -d "{{RAMA_DIR}}/.git"
    cd "{{RAMA_DIR}}" && git fetch --depth 1 origin tag "{{RAMA_TAG}}"
    cd "{{RAMA_DIR}}" && git reset --hard "{{RAMA_TAG}}"
    cd "{{RAMA_DIR}}" && git clean -fd
    cd "{{RAMA_DIR}}" && git apply --check "../../{{RAMA_PATCH}}"
    cd "{{RAMA_DIR}}" && git apply "../../{{RAMA_PATCH}}"

# Remove ext/rama completely.
clean-rama:
    rm -rf "{{RAMA_DIR}}"

# Recreate ext/rama from scratch.
recreate-rama: clean-rama setup-rama

# Check whether the rama patch can be applied cleanly.
check-rama-patch:
    test -d "{{RAMA_DIR}}/.git"
    cd "{{RAMA_DIR}}" && git apply --check "../../{{RAMA_PATCH}}"

# Update the rama patch file from current ext/rama local changes.
update-rama-patch:
    test -d "{{RAMA_DIR}}/.git"
    cd "{{RAMA_DIR}}" && git diff > "../../{{RAMA_PATCH}}"

# Clone tuie into ext/tuie and apply local scroll patch.
setup-tuie:
    mkdir -p ext
    if [ ! -d "{{TUIE_DIR}}/.git" ]; then \
      mkdir -p "{{TUIE_DIR}}"; \
      git -C "{{TUIE_DIR}}" init; \
      git -C "{{TUIE_DIR}}" remote add origin "{{TUIE_REPO}}"; \
    else \
      echo "{{TUIE_DIR}} already exists; skipping init"; \
    fi
    git -C "{{TUIE_DIR}}" fetch --depth 1 origin "{{TUIE_REV}}"
    git -C "{{TUIE_DIR}}" checkout --detach FETCH_HEAD
    if git apply --directory="{{TUIE_DIR}}" --check "{{TUIE_PATCH}}"; then \
      git apply --directory="{{TUIE_DIR}}" "{{TUIE_PATCH}}"; \
    elif git apply --directory="{{TUIE_DIR}}" -R --check "{{TUIE_PATCH}}"; then \
      echo "{{TUIE_PATCH}} already applied; skipping"; \
    else \
      echo "ERROR: {{TUIE_PATCH}} does not apply cleanly to {{TUIE_DIR}} at {{TUIE_REV}}" >&2; \
      exit 1; \
    fi

# Reset ext/tuie to the target revision and re-apply local scroll patch.
reset-tuie:
    test -d "{{TUIE_DIR}}/.git"
    git -C "{{TUIE_DIR}}" fetch --depth 1 origin "{{TUIE_REV}}"
    git -C "{{TUIE_DIR}}" checkout --detach FETCH_HEAD
    git -C "{{TUIE_DIR}}" reset --hard HEAD
    git -C "{{TUIE_DIR}}" clean -fd
    if git apply --directory="{{TUIE_DIR}}" --check "{{TUIE_PATCH}}"; then \
      git apply --directory="{{TUIE_DIR}}" "{{TUIE_PATCH}}"; \
    elif git apply --directory="{{TUIE_DIR}}" -R --check "{{TUIE_PATCH}}"; then \
      echo "{{TUIE_PATCH}} already applied; skipping"; \
    else \
      echo "ERROR: {{TUIE_PATCH}} does not apply cleanly to {{TUIE_DIR}} at {{TUIE_REV}}" >&2; \
      exit 1; \
    fi

# Remove ext/tuie completely.
clean-tuie:
    rm -rf "{{TUIE_DIR}}"

# Recreate ext/tuie from scratch.
recreate-tuie: clean-tuie setup-tuie

# Check whether the tuie patch can be applied cleanly.
check-tuie-patch:
    test -d "{{TUIE_DIR}}/.git"
    cd "{{TUIE_DIR}}" && git apply --check "../../{{TUIE_PATCH}}"

# Update the tuie patch file from current ext/tuie local changes.
update-tuie-patch:
    test -d "{{TUIE_DIR}}/.git"
    cd "{{TUIE_DIR}}" && git diff > "../../{{TUIE_PATCH}}"

# Setup all vendored dependencies.
setup-ext: setup-rama setup-tuie

# Reset all vendored dependencies and re-apply patches.
reset-ext: reset-rama reset-tuie

# Recreate all vendored dependencies from scratch.
recreate-ext: recreate-rama recreate-tuie

# Check all patches.
check-patches: check-rama-patch check-tuie-patch