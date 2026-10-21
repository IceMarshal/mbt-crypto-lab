///|
// 分组工作模式 ECB 与 CBC（NIST SP 800-38A 的模式定义），
// 填充采用 PKCS#7（RFC 5652 §6.3）。
//
// 模式层以字为单位运作：分组经 be32 装载为四个 32 位字，
// 直接调用字级轮函数核心 sm4_crypt_words，输出写入预分配的
// 定长数组，避免逐块构造中间 Bytes 与可增长数组的摊还开销。

///| SM4-ECB 加密（PKCS#7 填充）：C_i = E_K(P_i)。
pub fn ecb_encrypt(key : Sm4Key, msg : Bytes) -> Bytes {
  let padded = @util.pkcs7_pad(msg, 16)
  let n = padded.length()
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for off = 0; off < n; off = off + 16 {
    let (y0, y1, y2, y3) = sm4_crypt_words(
      key.rk,
      @util.be32_load(padded, off),
      @util.be32_load(padded, off + 4),
      @util.be32_load(padded, off + 8),
      @util.be32_load(padded, off + 12),
      false,
    )
    @util.be32_store(out, off, y0)
    @util.be32_store(out, off + 4, y1)
    @util.be32_store(out, off + 8, y2)
    @util.be32_store(out, off + 12, y3)
  }
  Bytes::from_array(out)
}

///| SM4-ECB 解密并校验去除 PKCS#7 填充；密文长度须为 16 的非零整数倍。
pub fn ecb_decrypt(key : Sm4Key, ct : Bytes) -> Bytes raise Error {
  let n = ct.length()
  if n == 0 || n % 16 != 0 {
    raise Failure(
      "ecb_decrypt: ciphertext length must be a positive multiple of 16, got \{n}",
    )
  }
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for off = 0; off < n; off = off + 16 {
    let (y0, y1, y2, y3) = sm4_crypt_words(
      key.rk,
      @util.be32_load(ct, off),
      @util.be32_load(ct, off + 4),
      @util.be32_load(ct, off + 8),
      @util.be32_load(ct, off + 12),
      true,
    )
    @util.be32_store(out, off, y0)
    @util.be32_store(out, off + 4, y1)
    @util.be32_store(out, off + 8, y2)
    @util.be32_store(out, off + 12, y3)
  }
  @util.pkcs7_unpad(Bytes::from_array(out), 16)
}

///| SM4-CBC 加密（PKCS#7 填充）：C_i = E_K(P_i ⊕ C_{i-1})，C_0 = IV。
///| `iv` 长度须为 16。
pub fn cbc_encrypt(key : Sm4Key, iv : Bytes, msg : Bytes) -> Bytes raise Error {
  if iv.length() != 16 {
    raise Failure("cbc_encrypt: iv must be 16 bytes, got \{iv.length()}")
  }
  let padded = @util.pkcs7_pad(msg, 16)
  let n = padded.length()
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  let mut p0 = @util.be32_load(iv, 0)
  let mut p1 = @util.be32_load(iv, 4)
  let mut p2 = @util.be32_load(iv, 8)
  let mut p3 = @util.be32_load(iv, 12)
  for off = 0; off < n; off = off + 16 {
    let (y0, y1, y2, y3) = sm4_crypt_words(
      key.rk,
      p0 ^ @util.be32_load(padded, off),
      p1 ^ @util.be32_load(padded, off + 4),
      p2 ^ @util.be32_load(padded, off + 8),
      p3 ^ @util.be32_load(padded, off + 12),
      false,
    )
    @util.be32_store(out, off, y0)
    @util.be32_store(out, off + 4, y1)
    @util.be32_store(out, off + 8, y2)
    @util.be32_store(out, off + 12, y3)
    p0 = y0
    p1 = y1
    p2 = y2
    p3 = y3
  }
  Bytes::from_array(out)
}

///| SM4-CBC 解密并校验去除 PKCS#7 填充：P_i = D_K(C_i) ⊕ C_{i-1}。
///| `iv` 长度须为 16，密文长度须为 16 的非零整数倍。
pub fn cbc_decrypt(key : Sm4Key, iv : Bytes, ct : Bytes) -> Bytes raise Error {
  if iv.length() != 16 {
    raise Failure("cbc_decrypt: iv must be 16 bytes, got \{iv.length()}")
  }
  let n = ct.length()
  if n == 0 || n % 16 != 0 {
    raise Failure(
      "cbc_decrypt: ciphertext length must be a positive multiple of 16, got \{n}",
    )
  }
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  let mut p0 = @util.be32_load(iv, 0)
  let mut p1 = @util.be32_load(iv, 4)
  let mut p2 = @util.be32_load(iv, 8)
  let mut p3 = @util.be32_load(iv, 12)
  for off = 0; off < n; off = off + 16 {
    let c0 = @util.be32_load(ct, off)
    let c1 = @util.be32_load(ct, off + 4)
    let c2 = @util.be32_load(ct, off + 8)
    let c3 = @util.be32_load(ct, off + 12)
    let (y0, y1, y2, y3) = sm4_crypt_words(key.rk, c0, c1, c2, c3, true)
    @util.be32_store(out, off, y0 ^ p0)
    @util.be32_store(out, off + 4, y1 ^ p1)
    @util.be32_store(out, off + 8, y2 ^ p2)
    @util.be32_store(out, off + 12, y3 ^ p3)
    p0 = c0
    p1 = c1
    p2 = c2
    p3 = c3
  }
  @util.pkcs7_unpad(Bytes::from_array(out), 16)
}
