///|
// 分组工作模式 ECB 与 CBC（NIST SP 800-38A 的模式定义），
// 填充采用 PKCS#7（RFC 5652 §6.3）。

///|
/// 取 `b` 从 `offset` 起的 16 字节分组。
fn block_at(b : Bytes, offset : Int32) -> Bytes {
  let out : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    out[i] = b[offset + i]
  }
  Bytes::from_array(out)
}

///|
/// 两个 16 字节分组按位异或。
fn xor_block(a : Bytes, b : Bytes) -> Bytes {
  let out : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    out[i] = (a[i].to_int() ^ b[i].to_int()).to_byte()
  }
  Bytes::from_array(out)
}

///|
/// 将 16 字节分组追加到 `dst`。
fn push_block(dst : Array[Byte], b : Bytes) -> Unit {
  for i = 0; i < 16; i = i + 1 {
    dst.push(b[i])
  }
}

///|
/// 可增长字节组转为 `Bytes`。
fn array_to_bytes(a : Array[Byte]) -> Bytes {
  let out : FixedArray[Byte] = FixedArray::make(a.length(), b'\x00')
  for i = 0; i < a.length(); i = i + 1 {
    out[i] = a[i]
  }
  Bytes::from_array(out)
}

///|
/// SM4-ECB 加密（PKCS#7 填充）：C_i = E_K(P_i)。
pub fn ecb_encrypt(key : Sm4Key, msg : Bytes) -> Bytes {
  let padded = @util.pkcs7_pad(msg, 16)
  let out : Array[Byte] = []
  for i = 0; i < padded.length() / 16; i = i + 1 {
    push_block(out, sm4_crypt_block(key.rk, block_at(padded, i * 16), false))
  }
  array_to_bytes(out)
}

///|
/// SM4-ECB 解密并校验去除 PKCS#7 填充；密文长度须为 16 的非零整数倍。
pub fn ecb_decrypt(key : Sm4Key, ct : Bytes) -> Bytes raise Error {
  if ct.length() == 0 || ct.length() % 16 != 0 {
    raise Failure(
      "ecb_decrypt: ciphertext length must be a positive multiple of 16, got \{ct.length()}",
    )
  }
  let out : Array[Byte] = []
  for i = 0; i < ct.length() / 16; i = i + 1 {
    push_block(out, sm4_crypt_block(key.rk, block_at(ct, i * 16), true))
  }
  @util.pkcs7_unpad(array_to_bytes(out), 16)
}

///| SM4-CBC 加密（PKCS#7 填充）：C_i = E_K(P_i ⊕ C_{i-1})，C_0 = IV。

///|
/// `iv` 长度须为 16。
pub fn cbc_encrypt(key : Sm4Key, iv : Bytes, msg : Bytes) -> Bytes raise Error {
  if iv.length() != 16 {
    raise Failure("cbc_encrypt: iv must be 16 bytes, got \{iv.length()}")
  }
  let padded = @util.pkcs7_pad(msg, 16)
  let out : Array[Byte] = []
  let mut prev = iv
  for i = 0; i < padded.length() / 16; i = i + 1 {
    let c = sm4_crypt_block(
      key.rk,
      xor_block(prev, block_at(padded, i * 16)),
      false,
    )
    push_block(out, c)
    prev = c
  }
  array_to_bytes(out)
}

///| SM4-CBC 解密并校验去除 PKCS#7 填充：P_i = D_K(C_i) ⊕ C_{i-1}。

///|
/// `iv` 长度须为 16，密文长度须为 16 的非零整数倍。
pub fn cbc_decrypt(key : Sm4Key, iv : Bytes, ct : Bytes) -> Bytes raise Error {
  if iv.length() != 16 {
    raise Failure("cbc_decrypt: iv must be 16 bytes, got \{iv.length()}")
  }
  if ct.length() == 0 || ct.length() % 16 != 0 {
    raise Failure(
      "cbc_decrypt: ciphertext length must be a positive multiple of 16, got \{ct.length()}",
    )
  }
  let out : Array[Byte] = []
  let mut prev = iv
  for i = 0; i < ct.length() / 16; i = i + 1 {
    let c = block_at(ct, i * 16)
    push_block(out, xor_block(sm4_crypt_block(key.rk, c, true), prev))
    prev = c
  }
  @util.pkcs7_unpad(array_to_bytes(out), 16)
}
