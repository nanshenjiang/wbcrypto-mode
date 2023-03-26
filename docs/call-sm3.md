## 调用SM3

sm3的调用规则与对称密码有所区别，请注意：

#### 引入头文件

```c
#include <wbcrypto/sm3.h>
```

#### 调用样例

```c
//进行哈希操作的消息无长度限制
const unsigned char msg[3]={0x01, 0x02, 0x03};  
//digest用于存储计算出的哈希值，请保证数组长度为32
unsigned char digest[32]={0};

//调用sm3（其中msg为输入信息，hash为获取经过hash后的值）
WBCRYPTO_sm3(msg, sizeof(msg), hash);
```

或
```c
//进行哈希操作的消息无长度限制
const unsigned char msg[3]={0x01, 0x02, 0x03};  
//digest用于存储计算出的哈希值，请保证数组长度为32
unsigned char digest[32]={0};

//声明sm3结构体
WBCRYPTO_sm3_context ctx;
//初始化sm3结构体
WBCRYPTO_sm3_init(&ctx);
//进行hash操作
WBCRYPTO_sm3_update(&ctx, msg, sizeof(msg));
//得到hash后的哈希值
WBCRYPTO_sm3_final(&ctx, digest);
```

**注意**：若要反复进行hash操作，请重新进行初始化操作后进行hash（即对结构体重新调用WBCRYPTO_sm3_init()函数），否则结果不正确。