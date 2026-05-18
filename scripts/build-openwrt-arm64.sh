#!/usr/bin/env bash
set -euo pipefail

TARGET="${TARGET:-aarch64-unknown-linux-musl}"
PROFILE="${PROFILE:-release}"
BIN_NAME="${BIN_NAME:-zapret-checker}"
OPENWRT_SDK="${OPENWRT_SDK:-}"
DEFAULT_OPENWRT_SDK_URL="https://downloads.openwrt.org/releases/24.10.4/targets/mediatek/filogic/openwrt-sdk-24.10.4-mediatek-filogic_gcc-13.3.0_musl.Linux-x86_64.tar.zst"
OPENWRT_SDK_URL="${OPENWRT_SDK_URL:-${DEFAULT_OPENWRT_SDK_URL}}"
OPENWRT_CC="${OPENWRT_CC:-}"
INSTALL_RUST_TARGET="${INSTALL_RUST_TARGET:-0}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist/openwrt-arm64"
TMP_DIR="${ROOT_DIR}/tmp"
SDK_EXTRACT_DIR="${TMP_DIR}/openwrt-sdk"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

target_env_name() {
  printf '%s' "$1" | tr '[:lower:]-' '[:upper:]_'
}

find_openwrt_cc() {
  if [[ -n "${OPENWRT_CC}" ]]; then
    [[ -x "${OPENWRT_CC}" ]] || die "OPENWRT_CC is not executable: ${OPENWRT_CC}"
    printf '%s\n' "${OPENWRT_CC}"
    return
  fi

  for cc in aarch64-openwrt-linux-musl-gcc aarch64-openwrt-linux-gcc; do
    if command -v "${cc}" >/dev/null 2>&1; then
      command -v "${cc}"
      return
    fi
  done

  if [[ -n "${OPENWRT_SDK}" ]]; then
    [[ -d "${OPENWRT_SDK}" ]] || die "OPENWRT_SDK does not exist: ${OPENWRT_SDK}"
    local cc
    cc="$(
      find "${OPENWRT_SDK}/staging_dir" -type f \
        \( -name 'aarch64-openwrt-linux-musl-gcc' -o -name 'aarch64-openwrt-linux-gcc' \) \
        2>/dev/null | head -n 1
    )"
    if [[ -n "${cc}" ]]; then
      printf '%s\n' "${cc}"
      return
    fi
  fi

  die "OpenWrt arm64 gcc not found. Set OPENWRT_SDK=/path/to/openwrt-sdk or OPENWRT_CC=/path/to/aarch64-openwrt-linux-musl-gcc"
}

download_openwrt_sdk() {
  [[ -n "${OPENWRT_SDK_URL}" ]] || die "OpenWrt SDK not found locally. Set OPENWRT_SDK_URL to an OpenWrt SDK .tar.zst/.tar.xz URL, or set OPENWRT_SDK/OPENWRT_CC"

  need_cmd tar
  mkdir -p "${TMP_DIR}"
  local archive_name
  archive_name="$(basename "${OPENWRT_SDK_URL%%\?*}")"
  local sdk_archive="${TMP_DIR}/${archive_name}"

  case "${sdk_archive}" in
    *.tar.zst)
      have_cmd zstd || die "zstd is required to extract .tar.zst SDK archives"
      ;;
    *.tar.xz)
      ;;
    *)
      die "unsupported SDK archive format: ${sdk_archive}. Expected .tar.zst or .tar.xz"
      ;;
  esac

  if [[ ! -f "${sdk_archive}" ]]; then
    printf 'Downloading OpenWrt SDK:\n  %s\n' "${OPENWRT_SDK_URL}"
    if have_cmd curl; then
      curl -L --fail --retry 3 -o "${sdk_archive}" "${OPENWRT_SDK_URL}"
    elif have_cmd wget; then
      wget -O "${sdk_archive}" "${OPENWRT_SDK_URL}"
    else
      die "curl or wget is required to download OPENWRT_SDK_URL"
    fi
  else
    printf 'Using cached SDK archive: %s\n' "${sdk_archive}"
  fi

  rm -rf "${SDK_EXTRACT_DIR}"
  mkdir -p "${SDK_EXTRACT_DIR}"
  tar -xf "${sdk_archive}" -C "${SDK_EXTRACT_DIR}" --strip-components=1
  OPENWRT_SDK="${SDK_EXTRACT_DIR}"
  export OPENWRT_SDK
}

tool_from_cc() {
  local cc="$1"
  local tool="$2"
  local candidate="${cc%-gcc}-${tool}"
  if [[ -x "${candidate}" ]]; then
    printf '%s\n' "${candidate}"
    return
  fi
  local dir
  dir="$(dirname "${cc}")"
  local prefixed
  prefixed="$(basename "${cc}")"
  prefixed="${prefixed%-gcc}-${tool}"
  if [[ -x "${dir}/${prefixed}" ]]; then
    printf '%s\n' "${dir}/${prefixed}"
    return
  fi
  if command -v "${tool}" >/dev/null 2>&1; then
    command -v "${tool}"
    return
  fi
  die "could not find ${tool} for ${cc}"
}

need_cmd cargo
need_cmd rustup

if [[ -z "${OPENWRT_CC}" && -z "${OPENWRT_SDK}" ]] \
  && ! have_cmd aarch64-openwrt-linux-musl-gcc \
  && ! have_cmd aarch64-openwrt-linux-gcc; then
  download_openwrt_sdk
fi

if ! rustup target list --installed | grep -qx "${TARGET}"; then
  if [[ "${INSTALL_RUST_TARGET}" == "1" ]]; then
    rustup target add "${TARGET}"
  else
    die "Rust target ${TARGET} is not installed. Run: rustup target add ${TARGET}"
  fi
fi

CC="$(find_openwrt_cc)"
AR="$(tool_from_cc "${CC}" ar)"
STRIP="$(tool_from_cc "${CC}" strip)"
CC_DIR="$(dirname "${CC}")"
TARGET_ENV="$(target_env_name "${TARGET}")"

export PATH="${CC_DIR}:${PATH}"
export "CARGO_TARGET_${TARGET_ENV}_LINKER=${CC}"
export "CC_${TARGET//-/_}=${CC}"
export "AR_${TARGET//-/_}=${AR}"
export "CXX_${TARGET//-/_}=${CC%-gcc}-g++"
export "RANLIB_${TARGET//-/_}=$(tool_from_cc "${CC}" ranlib)"

printf 'Building %s for %s\n' "${BIN_NAME}" "${TARGET}"
printf '  linker: %s\n' "${CC}"
printf '  ar:     %s\n' "${AR}"

cd "${ROOT_DIR}"
cargo build --locked --target "${TARGET}" --profile "${PROFILE}"

mkdir -p "${DIST_DIR}/config"
cp "target/${TARGET}/${PROFILE}/${BIN_NAME}" "${DIST_DIR}/${BIN_NAME}"
"${STRIP}" "${DIST_DIR}/${BIN_NAME}" || true
cp -R config/checker.toml config/standart config/custom "${DIST_DIR}/config/"

printf '\nOpenWrt arm64 build is ready:\n'
printf '  %s/%s\n' "${DIST_DIR}" "${BIN_NAME}"
printf '  %s/config\n' "${DIST_DIR}"
