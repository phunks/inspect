set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

TUIE_REPO := "https://github.com/jake-stewart/tuie.git"
TUIE_REV := "baa1f8726692f161a99ec5405fce929f4a142a30"
TUIE_DIR := "ext/tuie"
TUIE_PATCH := "patches/tuie-0.2.4-scroll-fix.patch"

# Show available commands
default:
    @just --list

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
setup-ext: setup-tuie

# Reset all vendored dependencies and re-apply patches.
reset-ext: reset-tuie

# Recreate all vendored dependencies from scratch.
recreate-ext: recreate-tuie

# Check all patches.
check-patches: check-tuie-patch
