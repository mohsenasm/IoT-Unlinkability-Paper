# ESP32 Proof-of-Concept Implementation & Benchmark

This repo is based on a template by wolfSSL. For general information on wolfSSL examples for Espressif, see the
[README](https://github.com/wolfSSL/wolfssl/blob/master/IDE/Espressif/ESP-IDF/README.md) file.

### Prerequisites

It is assumed the [ESP-IDF environment](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/) has been installed.

## Usage

Here's an example using the command-line [idf.py](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/tools/idf-py.html).

Edit your `WRK_IDF_PATH`to point to your ESP-IDF install directory.

```
WRK_IDF_PATH=/mnt/c/SysGCC/esp32/esp-idf/v5.1

echo "Run export.sh from ${WRK_IDF_PATH}"
. ${WRK_IDF_PATH}/export.sh

# build the example:
idf.py build

# optionally erase the flash
idf.py erase-flash -p /dev/ttyS19 -b 115200

# flash the code onto the serial device at /dev/ttyS19
idf.py flash -p /dev/ttyS19 -b 115200

# build, flash, and view UART output with one command:
idf.py flash -p /dev/ttyS19 -b 115200 monitor
```

Press `Ctrl+]` to exit `idf.py monitor`. See [additional monitor keyboard commands](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/tools/idf-monitor.html).
