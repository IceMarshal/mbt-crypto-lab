///|
// SM4 分组密码算法，依据 GB/T 32907-2016。
//
// 实现结构参考 GmSSL 与 OpenSSL crypto/sm4：密钥扩展一次完成，
// 32 个轮密钥存储于上下文；解密以轮密钥逆序复用同一轮函数；
// 轮输出按 (X35, X34, X33, X32) 逆序组装。字运算依赖 MoonBit
// UInt32 模 2^32 回绕语义（该语义由 src/util 白盒测试锁定）。

///|
/// S 盒 SBOX，GB/T 32907-2016 第 5.3.1 节。
let sm4_sbox : FixedArray[Byte] = [
  0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB,
  0x2C, 0x05, 0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26,
  0x49, 0x86, 0x06, 0x99, 0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54,
  0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62, 0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95,
  0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6, 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73,
  0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8, 0x68, 0x6B, 0x81, 0xB2,
  0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35, 0x1E, 0x24,
  0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
  0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4,
  0xC8, 0x9E, 0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE,
  0xF9, 0x61, 0x15, 0xA1, 0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93,
  0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3, 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
  0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F, 0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD,
  0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51, 0x8D, 0x1B, 0xAF, 0x92,
  0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8, 0x0A, 0xC1,
  0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
  0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E,
  0xC6, 0x84, 0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E,
  0xD7, 0xCB, 0x39, 0x48,
]

///|
/// 系统参数 FK，GB/T 32907-2016 第 5.3.2 节。
let sm4_fk : FixedArray[UInt32] = [
  0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC,
]

///| 固定参数 CK，GB/T 32907-2016 第 5.3.2 节；

///|
/// 生成规则 ck(i,j) = (4i + j)·7 mod 256 由白盒测试静态断言。
let sm4_ck : FixedArray[UInt32] = [
  0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269, 0x70777E85, 0x8C939AA1, 0xA8AFB6BD,
  0xC4CBD2D9, 0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249, 0x50575E65, 0x6C737A81,
  0x888F969D, 0xA4ABB2B9, 0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229, 0x30373E45,
  0x4C535A61, 0x686F767D, 0x848B9299, 0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
  0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
]

///|
/// 合成置换 τ：32 位字按字节经 S 盒替换。
fn sm4_tau(x : UInt32) -> UInt32 {
  let b0 = sm4_sbox[((x >> 24) & 0xFF).reinterpret_as_int()].to_uint()
  let b1 = sm4_sbox[((x >> 16) & 0xFF).reinterpret_as_int()].to_uint()
  let b2 = sm4_sbox[((x >> 8) & 0xFF).reinterpret_as_int()].to_uint()
  let b3 = sm4_sbox[(x & 0xFF).reinterpret_as_int()].to_uint()
  (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

///|
/// 线性变换 L(B) = B ⊕ (B <<< 2) ⊕ (B <<< 10) ⊕ (B <<< 18) ⊕ (B <<< 24)。
fn sm4_l(b : UInt32) -> UInt32 {
  b ^
  @util.rotl32(b, 2) ^
  @util.rotl32(b, 10) ^
  @util.rotl32(b, 18) ^
  @util.rotl32(b, 24)
}

///|
/// 线性变换 L′(B) = B ⊕ (B <<< 13) ⊕ (B <<< 23)。
fn sm4_l_prime(b : UInt32) -> UInt32 {
  b ^ @util.rotl32(b, 13) ^ @util.rotl32(b, 23)
}

///|
/// 轮函数中的合成置换 T = L ∘ τ（经由 T 表计算，见 sm4_t_fast）。
/// 密钥扩展使用 T′ = L′ ∘ τ。
fn sm4_t_prime(x : UInt32) -> UInt32 {
  sm4_l_prime(sm4_tau(x))
}

///|
/// 构造 T 表：table[b] = L(SBOX[b] <<< (8·shift_bytes))。
/// L 为 GF(2) 线性变换，故 T(x) 可按字节分解为四个 T 表查找结果的异或；
/// 该优化手段与 GmSSL 的 SM4 实现一致。
fn sm4_build_t_table(byte_position : Int32) -> FixedArray[UInt32] {
  let table : FixedArray[UInt32] = FixedArray::make(256, 0)
  for b = 0; b < 256; b = b + 1 {
    let word = sm4_sbox[b].to_uint() << (byte_position * 8)
    table[b] = sm4_l(word)
  }
  table
}

///|
/// T 查找表：T(x) = T0[x₀] ⊕ T1[x₁] ⊕ T2[x₂] ⊕ T3[x₃]，
/// x₀..x₃ 为 x 自高至低的四个字节。
let sm4_t0 : FixedArray[UInt32] = sm4_build_t_table(3)

///|
let sm4_t1 : FixedArray[UInt32] = sm4_build_t_table(2)

///|
let sm4_t2 : FixedArray[UInt32] = sm4_build_t_table(1)

///|
let sm4_t3 : FixedArray[UInt32] = sm4_build_t_table(0)

///|
/// 经 T 表计算的合成置换 T(x)，与直接计算 L(τ(x)) 等价
/// （等价性由白盒测试锁定）。
fn sm4_t_fast(x : UInt32) -> UInt32 {
  sm4_t0[((x >> 24) & 0xFF).reinterpret_as_int()] ^
  sm4_t1[((x >> 16) & 0xFF).reinterpret_as_int()] ^
  sm4_t2[((x >> 8) & 0xFF).reinterpret_as_int()] ^
  sm4_t3[(x & 0xFF).reinterpret_as_int()]
}

///|
/// SM4 密钥上下文：持有 32 个轮密钥（加密次序）。
pub struct Sm4Key {
  priv rk : FixedArray[UInt32]
}

///| 由 16 字节密钥经密钥扩展构造上下文；长度不为 16 时抛出 `Failure`。

///|
/// GB/T 32907-2016 第 7.3 节：K[i+4] = K[i] ⊕ T′(K[i+1] ⊕ K[i+2] ⊕ K[i+3] ⊕ CK[i])。
pub fn Sm4Key::new(key : Bytes) -> Sm4Key raise Error {
  if key.length() != 16 {
    raise Failure("Sm4Key::new: key must be 16 bytes, got \{key.length()}")
  }
  let k : FixedArray[UInt32] = FixedArray::make(36, 0)
  for i = 0; i < 4; i = i + 1 {
    k[i] = @util.be32_load(key, i * 4) ^ sm4_fk[i]
  }
  let rk : FixedArray[UInt32] = FixedArray::make(32, 0)
  for i = 0; i < 32; i = i + 1 {
    k[i + 4] = k[i] ^ sm4_t_prime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ sm4_ck[i])
    rk[i] = k[i + 4]
  }
  { rk, }
}

///|
/// 由 32 字符十六进制字符串构造密钥上下文。
pub fn Sm4Key::from_hex(s : String) -> Sm4Key raise Error {
  Sm4Key::new(@util.hex_decode(s))
}

///| 字级轮函数核心：输入四个 32 位字，32 轮迭代

///| X[i+4] = X[i] ⊕ T(X[i+1] ⊕ X[i+2] ⊕ X[i+3] ⊕ rk_i)，

///| 以四个寄存器轮转实现；解密时轮密钥按逆序取用。

///|
/// 返回终态 (X35, X34, X33, X32)。
fn sm4_crypt_words(
  rk : FixedArray[UInt32],
  x0 : UInt32,
  x1 : UInt32,
  x2 : UInt32,
  x3 : UInt32,
  decrypt : Bool,
) -> (UInt32, UInt32, UInt32, UInt32) {
  let mut a = x0
  let mut b = x1
  let mut c = x2
  let mut d = x3
  for i = 0; i < 32; i = i + 1 {
    let r = if decrypt { rk[31 - i] } else { rk[i] }
    let nx = a ^ sm4_t_fast(b ^ c ^ d ^ r)
    a = b
    b = c
    c = d
    d = nx
  }
  (d, c, b, a)
}

///|
/// 内部分组处理（无长度校验）：经 `sm4_crypt_words` 加解密单个分组。
fn sm4_crypt_block(
  rk : FixedArray[UInt32],
  block : Bytes,
  decrypt : Bool,
) -> Bytes {
  let (y0, y1, y2, y3) = sm4_crypt_words(
    rk,
    @util.be32_load(block, 0),
    @util.be32_load(block, 4),
    @util.be32_load(block, 8),
    @util.be32_load(block, 12),
    decrypt,
  )
  let out : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  @util.be32_store(out, 0, y0)
  @util.be32_store(out, 4, y1)
  @util.be32_store(out, 8, y2)
  @util.be32_store(out, 12, y3)
  Bytes::from_array(out)
}

///|
/// 加密单个 16 字节分组；长度不为 16 时抛出 `Failure`。
pub fn Sm4Key::encrypt_block(self : Sm4Key, block : Bytes) -> Bytes raise Error {
  if block.length() != 16 {
    raise Failure(
      "encrypt_block: block must be 16 bytes, got \{block.length()}",
    )
  }
  sm4_crypt_block(self.rk, block, false)
}

///|
/// 解密单个 16 字节分组（轮密钥逆序）；长度不为 16 时抛出 `Failure`。
pub fn Sm4Key::decrypt_block(self : Sm4Key, block : Bytes) -> Bytes raise Error {
  if block.length() != 16 {
    raise Failure(
      "decrypt_block: block must be 16 bytes, got \{block.length()}",
    )
  }
  sm4_crypt_block(self.rk, block, true)
}
