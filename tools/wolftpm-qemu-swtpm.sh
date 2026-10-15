#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0+
#
# Run a qemu_arm64 U-Boot with an swtpm TPM 2.0 attached, for testing the
# wolfTPM tpm2 backend. Optionally provisions a self-signed X.509 certificate
# into an NV index first, for 'tpm2 nv_read_cert'.
#
# Usage: tools/wolftpm-qemu-swtpm.sh [u-boot.bin]
#
# Environment:
#   TPM_STATE_DIR       swtpm state directory (default: a temporary directory)
#   WOLFTPM_CERT_INDEX  NV index to provision (default: 0x01c00002)
#   WOLFTPM_CERT_SUBJ   certificate subject
#                       (default: /CN=wolfTPM QEMU Test/serialNumber=TEST0001)
#   WOLFTPM_NO_CERT     set to 1 to skip provisioning (no tpm2-tools needed)
#
# The script can also be used as u-boot-test-console for test/py.

set -euo pipefail

bios=${1:-u-boot.bin}
cert_index=${WOLFTPM_CERT_INDEX:-0x01c00002}
cert_subj=${WOLFTPM_CERT_SUBJ:-/CN=wolfTPM QEMU Test/serialNumber=TEST0001}
no_cert=${WOLFTPM_NO_CERT:-0}

tools=(swtpm qemu-system-aarch64)
if [[ "$no_cert" != 1 ]]; then
	tools+=(openssl tpm2_startup tpm2_nvreadpublic tpm2_nvdefine \
		tpm2_nvundefine tpm2_nvwrite)
fi
for tool in "${tools[@]}"; do
	if ! command -v "$tool" >/dev/null; then
		echo "Missing dependency: $tool" >&2
		echo "On Debian/Ubuntu: apt install swtpm qemu-system-arm openssl" \
			"tpm2-tools libtss2-tcti-swtpm0" >&2
		exit 1
	fi
done

if [[ ! -f "$bios" ]]; then
	echo "U-Boot image not found: $bios" >&2
	exit 1
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/wolftpm-qemu.XXXXXX")
state_dir=${TPM_STATE_DIR:-$work_dir/state}
mkdir -p "$state_dir"
swtpm_pid=

cleanup() {
	if [[ -n "$swtpm_pid" ]]; then
		kill "$swtpm_pid" 2>/dev/null || true
	fi
	rm -rf -- "$work_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# The data socket is only for tpm2-tools; QEMU passes its own over --ctrl
swtpm_args=()
if [[ "$no_cert" != 1 ]]; then
	swtpm_args+=(--server "type=unixio,path=$work_dir/tpm.sock")
fi
swtpm socket --tpm2 --tpmstate "dir=$state_dir" "${swtpm_args[@]}" \
	--ctrl "type=unixio,path=$work_dir/tpm.sock.ctrl" \
	--flags not-need-init --daemon --pid "file=$work_dir/swtpm.pid"
swtpm_pid=$(<"$work_dir/swtpm.pid")

if [[ "$no_cert" != 1 ]]; then
	export TPM2TOOLS_TCTI="swtpm:path=$work_dir/tpm.sock"
	tpm2_startup -c
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
		-nodes -sha256 -days 365 -subj "$cert_subj" \
		-keyout "$work_dir/cert.key" -outform DER \
		-out "$work_dir/cert.der" 2>/dev/null
	if tpm2_nvreadpublic "$cert_index" >/dev/null 2>&1; then
		tpm2_nvundefine "$cert_index" -C p
	fi
	tpm2_nvdefine "$cert_index" -C p -a 'platformcreate|ppwrite|authread' \
		-s "$(wc -c < "$work_dir/cert.der")"
	tpm2_nvwrite "$cert_index" -C p -i "$work_dir/cert.der"
	echo "Provisioned NV index $cert_index with subject '$cert_subj'" >&2
fi

qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 1024 -nographic \
	-bios "$bios" \
	-chardev "socket,id=chrtpm,path=$work_dir/tpm.sock.ctrl" \
	-tpmdev emulator,id=tpm0,chardev=chrtpm \
	-device tpm-tis-device,tpmdev=tpm0
