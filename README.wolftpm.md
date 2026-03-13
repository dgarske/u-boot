# wolfTPM Support for U-Boot

This fork adds [wolfTPM](https://github.com/wolfSSL/wolfTPM) support to U-Boot, providing full TPM 2.0 command support using wolfTPM APIs and the wolfTPM library.

## Overview

wolfTPM is a portable, open-source TPM 2.0 library that provides:

- **Native TPM 2.0 API** - Direct access to all TPM 2.0 commands
- **Wrapper API** - Simplified interface for common TPM operations
- **Hardware SPI Support** - Direct communication with TPM hardware via SPI
- **Firmware Update** - Support for Infineon SLB9672/SLB9673 firmware updates
- **No External Dependencies** - Standalone implementation without kernel TPM stack

## Why wolfTPM vs Standard U-Boot TPM?

| Feature | Standard U-Boot TPM | wolfTPM |
|---------|---------------------|---------|
| API | Basic TPM commands | Full TPM 2.0 + Wrapper API |
| PCR Operations | Basic read/extend | Full PCR management |
| Firmware Update | Not supported | Infineon SLB9672/9673 |
| Capabilities Query | Limited | Comprehensive `caps` command |
| SPI Communication | Via kernel driver | Native wolfTPM TIS layer |
| Library Integration | N/A | wolfSSL ecosystem compatible |

## Command: `tpm2`

When wolfTPM is enabled, the `tpm2` command uses wolfTPM APIs instead of the standard implementation. The command interface is compatible with the standard `tpm2` command, with additional wolfTPM-specific features.

### Basic Commands

```bash
tpm2 autostart          # Initialize TPM, startup, and self-test
tpm2 init               # Initialize TPM software stack
tpm2 info               # Show TPM device information
tpm2 caps               # Show TPM capabilities (wolfTPM enhanced)
tpm2 self_test full     # Run full self-test
```

### PCR Operations

```bash
tpm2 pcr_read <pcr> <addr> [algo]      # Read PCR value
tpm2 pcr_extend <pcr> <addr> [algo]    # Extend PCR with digest
tpm2 pcr_print                          # Print all PCR values
tpm2 pcr_allocate <algo> <on|off>       # Configure PCR banks
```

### Security Management

```bash
tpm2 clear <hierarchy>                           # Clear TPM
tpm2 change_auth <hierarchy> <new_pw> [old_pw]   # Change password
tpm2 dam_reset [password]                        # Reset DAM counter
tpm2 dam_parameters <tries> <recovery> <lockout> # Set DAM params
```

### Firmware Update (Infineon Only)

```bash
tpm2 firmware_update <manifest_addr> <size> <firmware_addr> <size>
tpm2 firmware_cancel
```

## Building

### For Raspberry Pi 4

```bash
git clone https://github.com/aidangarske/u-boot.git
cd u-boot
git checkout rpi4-wolftpm-uboot
git submodule update --init lib/wolftpm

export CROSS_COMPILE=aarch64-elf-
make rpi_4_defconfig
make -j$(nproc)
```

### Configuration Options

Enable in `menuconfig` or defconfig:

```
# Core TPM support
CONFIG_TPM=y
CONFIG_TPM_V2=y

# wolfTPM (replaces standard tpm2 command)
CONFIG_TPM_WOLF=y
CONFIG_CMD_TPM=y

# For Infineon hardware
CONFIG_WOLFTPM_SLB9672=y

# For QEMU/swtpm testing
# CONFIG_WOLFTPM_LINUX_DEV=y
```

**Note:** The `tpm2` command frontend (`cmd/tpm-v2.c`) is always compiled. The backend is selected at build time: when `CONFIG_TPM_WOLF` is enabled, `cmd/wolftpm.c` provides the wolfTPM backend; otherwise, `cmd/native_tpm2.c` provides the native U-Boot backend.

## Hardware Support

### Tested Hardware

- Raspberry Pi 4 Model B
- Infineon SLB9670 TPM (LetsTrust HAT)
- Infineon SLB9672 TPM (with firmware update support)

### SPI Configuration

The TPM is configured on SPI0 CE1 (GPIO7), matching the standard Raspberry Pi `tpm-slb9670` overlay:

```
SPI0 Pins:
- SCLK: GPIO11 (pin 23)
- MOSI: GPIO10 (pin 19)
- MISO: GPIO9  (pin 21)
- CE1:  GPIO7  (pin 26)
```

## Documentation

- **Full Guide**: [rpi4-wolftpm-uboot](https://github.com/aidangarske/rpi4-wolftpm-uboot)
- **Firmware Update**: See `doc/usage/cmd/wolftpm.rst`
- **wolfTPM Library**: [github.com/wolfSSL/wolfTPM](https://github.com/wolfSSL/wolfTPM)

## Files Modified/Added

```
cmd/tpm-v2.c                     # Shared tpm2 command frontend (dispatch table, help)
cmd/native_tpm2.c                # Native U-Boot backend (when wolfTPM is OFF)
cmd/wolftpm.c                    # wolfTPM backend (when wolfTPM is ON)
cmd/tpm2-backend.h               # Backend function declarations
lib/wolftpm/                     # wolfTPM library (submodule)
lib/wolftpm.c                    # wolfTPM library glue code
include/configs/user_settings.h  # wolfTPM configuration
include/wolftpm.h                # wolfTPM header
arch/arm/dts/bcm2711-rpi-4-b.dts # Device tree with SPI/TPM config
configs/rpi_4_defconfig          # RPi4 build configuration
drivers/spi/bcm2835_spi.c        # BCM2835 SPI driver
doc/usage/cmd/wolftpm.rst        # Command documentation
```

## License

- U-Boot: GPL-2.0
- wolfTPM: GPL-2.0
- This integration: GPL-2.0

## Author

Aidan Garske <aidan@wolfssl.com>
wolfSSL Inc.
