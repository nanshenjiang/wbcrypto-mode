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
- FPE模式 - FF1和FF3加密格式



## 构建 && 安装

### 快速开始

请确保编译环境中含gcc和cmake环境，同时安装openssl库：

目录{项目路径}/build/out目录下为头文件和编译库。

（可选）使用下面命令将头文件和编译库安装至系统全局环境中：

```
$ sudo make install
```

假设创建测试文件test.c调用环境变量中的wbcrypto编译库，请指定动态库搜索路径，例如ubuntu环境下：

```
$ gcc test.c -o test -lwbcrypto -Wl,-rpath="/usr/local/lib"
```

