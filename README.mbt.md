# crypto-lab

国密 SM3 密码杂凑算法与 SM4 分组密码算法的 MoonBit 语言实现。

## 1 规范依据

| 项目 | 规范 |
|---|---|
| SM3 杂凑算法 | GB/T 32905-2016《信息安全技术 SM3密码杂凑算法》 |
| SM4 分组密码 | GB/T 32907-2016《信息安全技术 SM4分组密码算法》 |
| 分组工作模式 ECB、CBC | NIST SP 800-38A |
| PKCS#7 填充 | RFC 5652 §6.3 |

## 2 构建与测试

```sh
moon check                                        # 类型检查
moon test                                         # 运行全部测试
moon fmt                                          # 源码格式化
moon info                                         # 更新包接口文件（.mbti）
python3 tests/gen_vectors.py --check --with-sm4   # 校验金标准向量可复现
sh tests/verify_openssl.sh                        # OpenSSL 命令行独立对拍
```

工具链版本：moon 0.1.20261020 / moonc v0.10.16。本模块不依赖第三方包。

## 3 包结构与接口定义

### 3.1 src/util（共享编码原语）

| 函数 | 语义与约束 |
|---|---|
| `be32_load(b : Bytes, offset : Int) -> UInt32` | 读取大端 32 位字；要求 `offset + 4 ≤ b.length()` |
| `be32_store(buf : FixedArray[Byte], offset : Int, w : UInt32) -> Unit` | 写入大端 32 位字 |
| `be32_push(buf : Array[Byte], w : UInt32) -> Unit` | 追加大端 32 位字 |
| `rotl32(x : UInt32, n : Int) -> UInt32` | 32 位循环左移，`n ∈ [1, 31]` |
| `hex_encode(b : Bytes) -> String` | 输出小写十六进制 |
| `hex_decode(s : String) -> Bytes raise` | 输入须为偶数长度、仅含十六进制数字，否则抛出 `Failure` |
| `pkcs7_pad(msg : Bytes, block : Int) -> Bytes` | PKCS#7 填充，整块时补充完整分组 |
| `pkcs7_unpad(msg : Bytes, block : Int) -> Bytes raise` | 校验并去除填充；非法填充抛出 `Failure` |

### 3.2 src/sm3（GB/T 32905-2016）

| 接口 | 语义与约束 |
|---|---|
| `hash(msg : Bytes) -> Bytes` | 一次性杂凑，输出 32 字节 |
| `hash_hex(msg : Bytes) -> String` | 一次性杂凑，输出 64 字符小写十六进制 |
| `Sm3::new() -> Sm3` | 构造初始状态（IV、零计数）的上下文 |
| `Sm3::update(self, msg : Bytes) -> Unit` | 吸收消息片段，可多次调用，次序即字节次序 |
| `Sm3::finalize(self) -> Bytes` | 执行填充并终结，输出 32 字节杂凑值 |

### 3.3 src/sm4（GB/T 32907-2016）

| 接口 | 语义与约束 |
|---|---|
| `Sm4Key::new(key : Bytes) -> Sm4Key raise` | 密钥扩展；密钥长度须为 16 字节，否则抛出 `Failure` |
| `Sm4Key::from_hex(s : String) -> Sm4Key raise` | 由 32 字符十六进制字符串构造 |
| `Sm4Key::encrypt_block(self, block : Bytes) -> Bytes raise` | 单块加密；块长度须为 16 字节 |
| `Sm4Key::decrypt_block(self, block : Bytes) -> Bytes raise` | 单块解密（轮密钥逆序复用轮函数） |
| `ecb_encrypt(key : Sm4Key, msg : Bytes) -> Bytes` | SM4-ECB 加密，PKCS#7 填充 |
| `ecb_decrypt(key : Sm4Key, ct : Bytes) -> Bytes raise` | 密文须为 16 的非零整数倍，填充校验失败抛出 `Failure` |
| `cbc_encrypt(key : Sm4Key, iv : Bytes, msg : Bytes) -> Bytes raise` | SM4-CBC 加密；`iv` 长度须为 16 字节 |
| `cbc_decrypt(key : Sm4Key, iv : Bytes, ct : Bytes) -> Bytes raise` | 兼有 `iv` 长度与密文整块两项约束 |

## 4 验证方法

正确性验证采用三个相互独立的期望值来源：

1. 规范附录 A 的标准向量，硬编码断言于各包黑盒测试；
2. python-gmssl 3.2.2 生成的确定性向量（`tests/gen_vectors.py`，
   SHA-256 计数器模式 DRBG 固定种子）：SM3 覆盖长度 0–256 全部取值
   及 512/1024/8192 字节多块输入共 260 组，SM4 覆盖明文长度 0–128
   全部取值的 ECB 与 CBC 共 129 组；生成的 MoonBit 测试文件入库，
   `--check` 模式依据字面量序列校验可复现性；
3. OpenSSL 3.0.17 命令行工具独立重算（`tests/verify_openssl.sh`，
   共 12 项检查）。

规范示例值：

| 向量 | 输入 | 输出 |
|---|---|---|
| GB/T 32905-2016 A.1 | ASCII `abc` | `66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0` |
| GB/T 32905-2016 A.2 | `abcd` 重复 16 次（64 字节） | `debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732` |
| GB/T 32907-2016 A.1 | 密钥与明文均为 `01234567 89ABCDEF FEDCBA98 76543210` | 密文 `681edf34 d206965e 86b3e94f 536e4246` |

另设一致性测试：SM3 流式计算在 16 种分块长度、6 个相位起点下与一次性
计算等价；SM4 各模式加解密互逆并覆盖全部边界长度。

## 5 实现说明

- 数据布局：SM3 消息扩展采用 W[0..67] 与 W′[0..64] 数组（GmSSL 布局），
  压缩函数以 A–H 八个字寄存器展开；SM4 密钥扩展一次完成，
  32 个轮密钥存储于 `FixedArray[UInt32]`，轮输出按
  (X₃₅, X₃₄, X₃₃, X₃₂) 逆序组装。
- 运算语义：字运算依赖 MoonBit `UInt32` 模 2³² 回绕语义，
  该语义由 `src/util` 白盒测试显式锁定。
- 优化：SM4 合成置换 T 采用四张 256 项查找表——利用 L 的 GF(2) 线性
  将 S 盒替换与线性变换融合（同 GmSSL 手段），与直接计算 L(τ(x)) 的
  等价性经 2¹⁶ 采样点测试锁定。
- 错误处理：参数约束违反时以 `Failure` 抛出，消息包含实际长度。
- 实现限制：软件实现，未包含侧信道对抗措施；运行于垃圾回收运行时，
  密钥材料在释放后无法可靠清零。

## 6 参考文献

[1] GB/T 32905-2016. 信息安全技术 SM3密码杂凑算法[S]. 北京: 中国标准出版社, 2016.

[2] GB/T 32907-2016. 信息安全技术 SM4分组密码算法[S]. 北京: 中国标准出版社, 2016.

[3] Dworkin M. Recommendation for Block Cipher Modes of Operation: SP 800-38A[R]. NIST, 2001.

[4] Housley R. Cryptographic Message Syntax (CMS): RFC 5652[S]. IETF, 2009.

[5] 国家密码管理局. SM3密码杂凑算法[EB/OL]. 2010.

[6] Chen L, Jiang Z. The SM3 Cryptographic Hash Function: draft-sca-cfrg-sm3[I]. IETF, 2022.

[7] GmSSL 项目. https://github.com/guanzhi/GmSSL

[8] OpenSSL 3.x 源码，crypto/sm3、crypto/sm4 目录.
