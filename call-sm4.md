## 调用SM4

该版本SM4为黑盒版本SM4，提供CBC，GCM，gcmfile模式的调用

#### 引入头文件

```c
#include <wbcrypto/sm4.h>
```

#### 初始化

```c
//密钥可非16bit长度，若短于16bit长度会进行pkcs7扩充，若长于16bit会进行裁减
unsigned char key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

//声明sm4指针对象
WBCRYPTO_sm4_context *sm4_ctx;
//初始化sm4指针对象，此时对象未计算轮密钥
sm4_ctx=WBCRYPTO_sm4_context_init();
//使用密钥初始化sm4，通过密钥计算轮密钥
WBCRYPTO_sm4_init_key(sm4_ctx, key, sizeof(key));
```

#### CBC模式调用

```c
//以下是假设的数据，用户调用时自行定义iv和msg值，定义与msg相同大小空间的cipher存储加密后密文，定义与cipher相同大小空间的plain存储解密后的明文
unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};   //iv值：初始化向量
unsigned char msg_cbc[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};  //需要加密的消息
unsigned char cipher_cbc[32] = {0};         //加密后存储密文的空间
unsigned char plain_cbc[32] = {0};          //解密后存储明文的空间
size_t use_len;                             //实际使用的空间

//cbc模式加密，其中参数分为：
//需要加密的消息，消息长度，创建存储密文的空间，密文空间大小，实际使用空间大小，sm4结构体，初始值
WBCRYPTO_sm4_cbc_encrypt(msg1024, sizeof(msg1024), cipher1024, sizeof(cipher1024), &use_len, sm4_ctx, iv);
//cbc模式解密，其中参数分为：
//需要解密的密文，密文长度，创建存储明文的空间，明文空间大小，实际使用空间大小，sm4结构体，初始值
WBCRYPTO_sm4_cbc_decrypt(cipher1024, use_len, plain1024, sizeof(plain1024), &use_len, sm4_ctx, iv);
```

#### GCM模式调用

```c
//以下是假设的数据
unsigned char iv_gcm[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};   //iv值：初始化向量
unsigned char aad_gcm[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};   //aad：附加消息
unsigned char msg_gcm[33] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};  //需要加密的消息
unsigned char tag_gcm[16] = {0};     //tag：身份验证标签
unsigned char cipher_gcm[33] = {0};  //加密后存储密文的空间
unsigned char plain_gcm[33] = {0};   //解密后存储明文的空间

//由于gcm模式下加密和解密的gcm结构体不同，需要各自定义
WBCRYPTO_gcm_context *gcm_enc,*gcm_dec;

//加密
//使用sm4结构体初始化gcm结构体
gcm_enc=WBCRYPTO_sm4_gcm_init(sm4_ctx);
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
gcm_dec=WBCRYPTO_sm4_gcm_init(sm4_ctx);
WBCRYPTO_gcm_setiv(gcm_dec,iv_gcm,sizeof(iv_gcm));
WBCRYPTO_gcm_aad(gcm_dec,aad_gcm,sizeof(aad_gcm));
WBCRYPTO_gcm_decrypt(gcm_dec,cipher_gcm,sizeof(cipher_gcm),plain_gcm,sizeof(plain_gcm));
WBCRYPTO_gcm_finish(gcm_dec,tag_gcm,sizeof(tag_gcm)); //tag值应该与加密进行比较
WBCRYPTO_gcm_free(gcm_dec);
```

#### gcmfile模式调用

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
//使用sm4结构体初始化gcmfile结构体
gcmfile_enc=WBCRYPTO_sm4_gcmfile_init(sm4_ctx);
//导入初始化向量iv值
WBCRYPTO_gcmfile_setiv(gcmfile_enc,iv_gcmfile,sizeof(iv_gcmfile));
//导入附加信息aad（长度不限）
WBCRYPTO_gcmfile_aad(gcmfile_enc,add_gcmfile,sizeof(add_gcmfile));
//加密文件
WBCRYPTO_gcmfile_encrypt(gcmfile_enc,infpath,encfpath);
//释放gcmfile结构体
WBCRYPTO_gcmfile_free(gcmfile_enc);

//解密文件（与加密类似）
gcmfile_dec=WBCRYPTO_sm4_gcmfile_init(sm4_ctx);
WBCRYPTO_gcmfile_setiv(gcmfile_dec,iv_gcmfile,sizeof(iv_gcmfile));
WBCRYPTO_gcmfile_aad(gcmfile_dec,add_gcmfile,sizeof(add_gcmfile));
WBCRYPTO_gcmfile_decrypt(gcmfile_dec,encfpath,decfpath);
WBCRYPTO_gcmfile_free(gcmfile_dec);
```

#### 释放结构体

```c
WBCRYPTO_sm4_context_free(sm4_ctx);
```

