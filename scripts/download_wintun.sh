#!/bin/bash

# 下载 Wintun DLL
# 用于 Windows 客户端嵌入

set -e

WINTUN_VERSION="0.14.1"
WINTUN_URL="https://www.wintun.net/builds/wintun-${WINTUN_VERSION}.zip"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
WINTUN_DIR="${PROJECT_DIR}/internal/wintun"
TEMP_DIR=$(mktemp -d)

echo "[INFO] Downloading Wintun ${WINTUN_VERSION}..."
curl -sSL -o "${TEMP_DIR}/wintun.zip" "${WINTUN_URL}"

echo "[INFO] Extracting..."
unzip -q "${TEMP_DIR}/wintun.zip" -d "${TEMP_DIR}"

echo "[INFO] Copying DLLs..."
mkdir -p "${WINTUN_DIR}"
cp "${TEMP_DIR}/wintun/bin/amd64/wintun.dll" "${WINTUN_DIR}/wintun_amd64.dll"
cp "${TEMP_DIR}/wintun/bin/arm64/wintun.dll" "${WINTUN_DIR}/wintun_arm64.dll"

echo "[INFO] Cleaning up..."
rm -rf "${TEMP_DIR}"

echo "[INFO] Wintun DLLs downloaded to ${WINTUN_DIR}"
ls -la "${WINTUN_DIR}"/*.dll
