# 白盒分组密码工作模式库

**相关论文：[Protecting White-Box Block Ciphers with Galois/Counter Mode](https://ieeexplore.ieee.org/abstract/document/9888845/)**

白盒分组密码工作模式库，提供Chow的白盒AES实现，肖来的白盒SM4实现，以及多种工作模式，包括：CBC、GCM、并行GCM、白盒GCM（论文工作）、FPE（FF1和FF3）、FPE认证（FF1-CMAC和FF3-GMAC）等各类API，以及应用类API：手机号、中国身份证号和中文字符的FPE加密接口。

## 概述

#### 目前支持算法

- sm3
- aes
- wbaes - Chow的白盒AES
- sm4
- wbsm4 - 肖来的白盒SM4

#### 目前支持加密模式

- CBC模式
- GCM模式
- 并行GCM模式
- 白盒GCM模式 - WBGCM-EE和WBGCM-Masking
- gcmfile模式 - 基于GCM模式加解密文件模式
- FPE模式 - FF1和FF3加密格式
- FPE认证加密模式 - FF1-CMAC和FF3-GMAC模式

#### 其他能力
- 支持手机号、身份证号、姓名、地址的FPE加密

## 构建 && 安装

### 预先

**请确保编译环境中含gcc和cmake环境，同时安装好openssl库**。

### 快速开始

运行下面命令编译库：
```asm
$ mkdir build && cd build
$ cmake ..
$ make -j
```
编译好后，{项目路径}/build/out目录下为头文件和编译库，和可执行文件。

（可选）使用下面命令将头文件和编译库安装至系统全局环境中：

```asm
$ sudo make install
```

假设创建测试文件test.c调用环境变量中的wbcrypto编译库，请指定动态库搜索路径，例如ubuntu环境下：

```asm
$ gcc test.c -o test -lwbcrypto -Wl,-rpath="/usr/local/lib"
```

## 文档

在当面目录下的/docs下

## 额外能力

### MySQL的UDF函数

在当面目录下的/udf下