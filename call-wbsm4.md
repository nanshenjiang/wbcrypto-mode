## 调用WBSM4

该版本为白盒SM4（简称：WBSM4），以下是调用白盒SM4接口样例，也可以参考test文件中有关WBSM4中测试样例：

### 引入头文件

```c
#include <wbcrypto/wbsm4.h>
```

### 初始化

```c
//声明wbsm4指针对象
WBCRYPTO_wbsm4_context *wbsm4_ctx_enc;
//初始化wbsm4指针对象，此时对象未计算轮密钥
//WBCRYPTO_ENCRYPT_MODE指定预生成为加密密钥（即为1）,1为dummyround轮数(选择1-4均可)，不建议太大，速度会有所下降
wbsm4_ctx_enc=WBCRYPTO_wbsm4_context_init(WBCRYPTO_ENCRYPT_MODE, 1);

//由于加密和解密的wbsm4结构体不同，需单独定义
WBCRYPTO_wbsm4_context *wbsm4_ctx_dec;
//WBCRYPTO_DECRYPT_MODE指定预生成为解密密钥（即为0）,1为dummyround轮数(选择1-4均可)
wbsm4_ctx_dec=WBCRYPTO_wbsm4_context_init(WBCRYPTO_DECRYPT_MODE, 1);
```

### 预生成表

在进行初始化操作后，需要对结构体进行生成加/解密表的预操作

```c
//密钥可非16bit长度，若短于16bit长度会进行pkcs7扩充，若长于16bit会进行裁减
unsigned char key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

//加密预生成操作
//其中key是密钥，sizeofkey是密钥长度
WBCRYPTO_wbsm4_gen_table(wbsm4_ctx_enc, key, sizeof(key));

//解密预生成操作
WBCRYPTO_wbsm4_gen_table(wbsm4_ctx_dec, key, sizeof(key));
```

### CBC模式调用

模式调用前，密钥结构体需进行预生成表操作

```c
//以下是假设的数据，用户调用时自行定义iv和msg值，定义与msg相同大小空间的cipher存储加密后密文，定义与cipher相同大小空间的plain存储解密后的明文
unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};   //iv值：初始化向量
unsigned char msg_cbc[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};  //需要加密的消息
unsigned char cipher_cbc[32] = {0};         //加密后存储密文的空间
unsigned char plain_cbc[32] = {0};          //解密后存储明文的空间
size_t use_len;                             //实际使用的空间

//cbc模式加密(注意加解密的结构体不同)，其中参数分为：
//需要加密的消息，消息长度，创建存储密文的空间，密文空间大小，实际使用空间大小，wbsm4结构体，初始值
WBCRYPTO_wbsm4_cbc_encrypt(msg1024, sizeof(msg1024), cipher1024, sizeof(cipher1024), &use_len, wbsm4_ctx_enc, iv);
//cbc模式解密(注意加解密的结构体不同)，其中参数分为：
//需要解密的密文，密文长度，创建存储明文的空间，明文空间大小，实际使用空间大小，wbsm4结构体，初始值
WBCRYPTO_wbsm4_cbc_decrypt(cipher1024, use_len, plain1024, sizeof(plain1024), &use_len, wbsm4_ctx_dec, iv);
```

### GCM模式调用

模式调用前，密钥结构体需进行预生成表操作

```c
//以下是假设的数据
unsigned char iv_gcm[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};   //iv值：初始化向量
unsigned char aad_gcm[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};   //aad：附加消息
unsigned char msg_gcm[33] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};  //需要加密的消息
unsigned char tag_gcm[16] = {0};        //tag：身份验证标签
unsigned char cipher_gcm[33] = {0};     //加密后存储密文的空间
unsigned char plain_gcm[33] = {0};      //解密后存储明文的空间

//由于gcm模式下加密和解密的gcm结构体不同，需要各自定义
WBCRYPTO_gcm_context *gcm_enc,*gcm_dec;

//加密
//使用wbsm4结构体初始化gcm结构体
//**注意**：gcm模式类似于流密码，gcm加解密时候使用同一密钥结构体即可，一般选择加密密钥结构体
gcm_enc=WBCRYPTO_wbsm4_gcm_init(wbsm4_ctx_enc);
//导入初始化向量iv值
WBCRYPTO_gcm_setiv(gcm_enc,iv_gcm,sizeof(iv_gcm));
//导入附加信息aad（长度不限）
WBCRYPTO_gcm_aad(gcm_enc,aad_gcm,sizeof(aad_gcm));
//gcm模式加密
WBCRYPTO_gcm_encrypt(gcm_enc,msg_gcm,sizeof(msg_gcm),cipher_gcm,sizeof(cipher_gcm));
//求出gcm模式后的身份验证标签tag（类似于用于判断信息完整性的mac值）
WBCRYPTO_gcm_finish(gcm_enc,tag_gcm,sizeof(tag_gcm));
//释放gcm结构体
WBCRYPTO_gcm_free(gcm_enc);

//解密（和加密类似，注意要重新声明该结构体）
//**注意**：此时声明的结构体也为加密密钥结构体，即wbsm4_ctx_enc!!!!
gcm_dec=WBCRYPTO_wbsm4_gcm_init(wbsm4_ctx_enc);
WBCRYPTO_gcm_setiv(gcm_dec,iv_gcm,sizeof(iv_gcm));
WBCRYPTO_gcm_aad(gcm_dec,aad_gcm,sizeof(aad_gcm));
WBCRYPTO_gcm_decrypt(gcm_dec,cipher_gcm,sizeof(cipher_gcm),plain_gcm,sizeof(plain_gcm));
WBCRYPTO_gcm_finish(gcm_dec,tag_gcm,sizeof(tag_gcm)); //tag值应该与加密进行比较
WBCRYPTO_gcm_free(gcm_dec);
```

### gcmfile模式调用

模式调用前，密钥结构体需进行预生成表操作

```c
//以下是假设的数据
unsigned char iv_gcmfile[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};   //iv值：初始化向量
unsigned char add_gcmfile[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};   //aad：附加消息
char *infpath="/home/xie/test.txt";          //需要加密的文件
char *encfpath="/home/xie/test.enc.txt";     //加密后文件存储位置及名字
char *decfpath="/home/xie/test.dec.txt";     //解密后文件存储位置及名字

//由于gcmfile模式下加密和解密的gcmfile结构体不同，需要各自定义
WBCRYPTO_gcmfile_context *gcmfile_enc,*gcmfile_dec;

//加密文件
//使用wbsm4结构体初始化gcmfile结构体
//**注意**：gcmfile模式类似于流密码，gcmfile加解密时候使用同一密钥结构体即可，一遍选择加密密钥结构体
gcmfile_enc=WBCRYPTO_wbsm4_gcmfile_init(wbsm4_ctx_enc);
//导入初始化向量iv值
WBCRYPTO_gcmfile_setiv(gcmfile_enc,iv_gcmfile,sizeof(iv_gcmfile));
//导入附加信息aad（长度不限）
WBCRYPTO_gcmfile_aad(gcmfile_enc,add_gcmfile,sizeof(add_gcmfile));
//加密文件
WBCRYPTO_gcmfile_encrypt(gcmfile_enc,infpath,encfpath);
//释放gcmfile结构体
WBCRYPTO_gcmfile_free(gcmfile_enc);

//解密文件（与加密类似）
//**注意**：此时声明的结构体也为加密密钥结构体，即wbsm4_ctx_enc!!!!
gcmfile_dec=WBCRYPTO_wbsm4_gcmfile_init(wbsm4_ctx_enc);
WBCRYPTO_gcmfile_setiv(gcmfile_dec,iv_gcmfile,sizeof(iv_gcmfile));
WBCRYPTO_gcmfile_aad(gcmfile_dec,add_gcmfile,sizeof(add_gcmfile));
WBCRYPTO_gcmfile_decrypt(gcmfile_dec,encfpath,decfpath);
WBCRYPTO_gcmfile_free(gcmfile_dec);
```

### 释放结构体

在定义结构体并使用完后一定要进行释放操作

```c
WBCRYPTO_wbsm4_context_free(wbsm4_ctx_enc);
WBCRYPTO_wbsm4_context_free(wbsm4_ctx_dec);
```



**<u>以下函数用于密钥协商交换阶段，是将已预生成表操作的WBSM4结构体进行转换为字符流或文件进行传输操作</u>**

### 导出密钥文件

```c
char *encfilepath="/home/xie/enckey.whibox";  //加密密钥文件位置
char *decfilepath="/home/xie/deckey.whibox";  //解密密钥文件位置
//进行密钥导入前需对结构体进行初始化操作，并进行预生成表操作，这里省略
//转换为文件
WBCRYPTO_wbsm4_key2file(wbsm4_ctx_enc, encfilepath);
WBCRYPTO_wbsm4_key2file(wbsm4_ctx_dec, decfilepath);
```

### 导入密钥文件

```c
char *encfilepath="/home/xie/enckey.whibox";  //加密密钥文件位置
char *decfilepath="/home/xie/deckey.whibox";  //解密密钥文件位置
//结构体初始化
WBCRYPTO_wbsm4_context *wbsm4_ctx_enc_file, *wbsm4_ctx_dec_file;
//此次初始化的参数不影响
wbsm4_ctx_enc_file=WBCRYPTO_wbsm4_context_init(WBCRYPTO_ENCRYPT_MODE, 1);
wbsm4_ctx_dec_file=WBCRYPTO_wbsm4_context_init(WBCRYPTO_DECRYPT_MODE, 1);
//密钥通过文件导入结构体
WBCRYPTO_wbsm4_file2key(wbsm4_ctx_enc_file, encfilepath);
WBCRYPTO_wbsm4_file2key(wbsm4_ctx_dec_file, decfilepath);
```

### 导出字符流

```c
char *bytes_enc, *bytes_dec;
//进行密钥导入前需对结构体进行初始化操作，并进行预生成表操作，这里省略
//转换为字符流
WBCRYPTO_wbsm4_key2bytes(wbsm4_ctx_enc, &bytes_enc);
WBCRYPTO_wbsm4_key2bytes(wbsm4_ctx_dec, &bytes_dec);
```

### 导入字符流

```c
//结构体初始化
WBCRYPTO_wbsm4_context *wbsm4_ctx_enc_str, *wbsm4_ctx_dec_str;
//此次初始化的参数不影响
wbsm4_ctx_enc_str=WBCRYPTO_wbsm4_context_init(WBCRYPTO_ENCRYPT_MODE, 1);
wbsm4_ctx_dec_str=WBCRYPTO_wbsm4_context_init(WBCRYPTO_DECRYPT_MODE, 1);
//密钥通过字符流导入结构体
WBCRYPTO_wbsm4_bytes2key(wbsm4_ctx_enc_str, bytes_enc);
WBCRYPTO_wbsm4_bytes2key(wbsm4_ctx_dec_str, bytes_dec);
```

随后可进行不同模式的加解密操作