///|
// HMAC 消息认证码构造（RFC 2104），底层杂凑函数为 SM3，
// 分组长度 B = 64 字节，摘要长度 L = 32 字节。
//
// K0 为密钥的分组化形式：长于 B 的密钥先以 SM3 杂凑（结果 L < B），
// 再以零字节填充至 B；不长于 B 的密钥直接零填充。
// HMAC(K, m) = H((K0 ⊕ opad) ‖ H((K0 ⊕ ipad) ‖ m))，
// ipad = 0x36 重复 B 次，opad = 0x5C 重复 B 次。

///|
/// 计算 HMAC-SM3，返回 32 字节消息认证码。
pub fn hmac(key : Bytes, msg : Bytes) -> Bytes {
  let k0 : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  if key.length() > 64 {
    let kd = hash(key)
    for i = 0; i < 32; i = i + 1 {
      k0[i] = kd[i]
    }
  } else {
    for i = 0; i < key.length(); i = i + 1 {
      k0[i] = key[i]
    }
  }
  let k0b = Bytes::from_array(k0)
  let pad : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  let ictx = Sm3::new()
  for i = 0; i < 16; i = i + 1 {
    @util.be32_store(pad, i * 4, @util.be32_load(k0b, i * 4) ^ 0x36363636)
  }
  ictx.update(Bytes::from_array(pad))
  ictx.update(msg)
  let inner = ictx.finalize()
  let octx = Sm3::new()
  for i = 0; i < 16; i = i + 1 {
    @util.be32_store(pad, i * 4, @util.be32_load(k0b, i * 4) ^ 0x5C5C5C5C)
  }
  octx.update(Bytes::from_array(pad))
  octx.update(inner)
  octx.finalize()
}

///|
/// 计算 HMAC-SM3，返回 64 字符小写十六进制字符串。
pub fn hmac_hex(key : Bytes, msg : Bytes) -> String {
  @util.hex_encode(hmac(key, msg))
}
