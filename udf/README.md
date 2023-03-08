# MySQL-FPE

## 构建 && 安装

### 预备操作

先到前面目录wbcrypt-fpe编译系统

```
$ mkdir build && cd build
$ cmake ..
$ make -j
$ sudo make install
$ sudo cp -f ./out/libwbcrypto.so /usr/lib/
```

### 构建
到当前目录udf编译系统
```
$ mkdir build && cd build
$ cmake ..
$ make -j
$ sudo make install
```

```
## 创建udf函数
> CREATE FUNCTION fpe RETURNS string SONAME 'udf.so';

## 移除udf函数
> DROP FUNCTION fpe;

## 使用udf函数
> fpe('13912345678','phone', '134xxxx5678')
> SELECT cast(fpe('13912345678','phone', '134xxxx5678') as char);

## 查询安装列表
> select * from mysql.func;
```

