# White-Box Block Cipher Mode Library

[Chinese Version](./README.CN.md)

**Related paper: Protecting White-Box Block Ciphers with Galois/Counter Mode**

This white-box block cipher mode library provides Chow's white-box AES implementation, Xiao's white-box SM4 implementation, and various working modes, including: CBC, GCM, parallel GCM, white-box GCM (paper work), FPE (FF1 and FF3) interfaces, as well as application class APIs: FPE encryption interfaces for mobile phone numbers, Chinese ID numbers, and Chinese addresses.

## Overview

#### Supported algorithms

- sm3
- aes
- wbaes - Chow's white-box AES
- sm4
- wbsm4 - Xiao's white-box SM4

#### Supported mode of operation

- CBC mode
- GCM mode
- Parallel GCM mode
- White-box GCM mode - WBGCM-EE and WBGCM-Masking
- gcmfile mode - File encryption mode based on GCM mode
- FPE mode - FF1 and FF3 encryption formats

#### Other capabilities
- Supports FPE encryption for mobile phone numbers, ID numbers, names, and addresses

## Build && Install

### Prerequisites

**Make sure the compilation environment includes gcc and cmake, and that the openssl library is installed.**。

### Quick Start

Run the following command to compile the library:
```asm
$ mkdir build && cd build
$ cmake ..
$ make -j
```
After compilation, the header files, compiled library, and executable files can be found in the {project path}/build/out directory.

(Optional) Use the following command to install the header files and compiled library into the global system environment:

```asm
$ sudo make install
```


## Additional capabilities

### MySQL UDF

Located in the current directory's /udf.