# FPE密码库

该版本FPE密码算法库是设计FPE的加解密接口，包含黑盒SM3，黑盒SM4以及白盒SM4。目前提供CBC模式，GCM模式和FPE模式。



## 概述

#### 目前支持算法

- sm3
- sm4
- wbsm4 - 白盒SM4

#### 目前支持加密模式

- CBC模式
- GCM模式
- gcmfile模式 - 基于GCM模式加解密文件模式
- FPE模式 - FF1加密格式



## 构建 && 安装

### 快速开始

请确保编译环境中含gcc和cmake环境，同时安装[gmp库](https://gmplib.org/#DOWNLOAD)，使用以下命令编译gmp库：

```
$ ./configure
$ make
$ sudo make install
```

至项目目录下使用以下命令快速编译：

```
$ mkdir build && cd build
$ cmake ..
$ make
```

目录{项目路径}/build/out目录下为头文件和编译库。

（可选）使用下面命令将头文件和编译库安装至系统全局环境中：

```
$ sudo make install
```

假设创建测试文件test.c调用环境变量中的wbcrypto编译库，请指定动态库搜索路径，例如ubuntu环境下：

```
$ gcc test.c -o test -lwbcrypto -Wl,-rpath="/usr/local/lib"
```



## Java

本库基于JNA技术，提供java调用本白盒密码库的实例，具体可参考当前目录下的java文件夹，其中包含了相关配置文档和Java接口文档。

**注意：当使用Java调用c时不建议开启OpenSSL加密模式（因为无进行OpenSSL的适配）。**
