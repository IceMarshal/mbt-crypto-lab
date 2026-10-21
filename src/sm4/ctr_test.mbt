///|
// 黑盒测试：SM4-CTR 的 openssl 对拍向量、自逆性、计数器进位与
// 短块截断。期望值由 OpenSSL 3.0.17 enc -sm4-ctr 独立计算
//（python-gmssl 未提供 CTR 模式，openssl 为该模式的独立期望值来源）。

///|
/// OpenSSL 对拍：32 字节消息（字节串 "0123456789abcdef" 重复两次）。
test "sm4 ctr openssl vector" {
  let key = @sm4.Sm4Key::new(
    b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10",
  )
  let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
  let msg = b"0123456789abcdef0123456789abcdef"
  let ct = @sm4.ctr_crypt(key, iv, msg)
  inspect(
    ct ==
    b"\x36\xA9\xAE\x52\x09\x93\x5E\x9A\x12\xB4\x96\xE0\x82\xCC\x9C\x0C\x5F\x36\x3F\x78\x74\x96\xCA\x36\xE2\xA8\x72\x87\xE2\x64\xC8\x7C",
    content="true",
  )
  inspect(@sm4.ctr_crypt(key, iv, ct) == msg, content="true")
}

///|
/// 构造确定性伪随机字节序列：(31·i + 13) mod 256。
fn ctr_det_bytes(n : Int32) -> Bytes {
  let a : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    a[i] = ((i * 31 + 13) % 256).to_byte()
  }
  Bytes::from_array(a)
}

///|
/// 自逆性：加密再解密恢复原文，覆盖边界长度（含空消息与整块）。
test "sm4 ctr involution over boundary lengths" {
  let key = @sm4.Sm4Key::new(ctr_det_bytes(16))
  let iv = ctr_iv(0)
  for len in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 128] {
    let msg = ctr_det_bytes(len)
    let ct = @sm4.ctr_crypt(key, iv, msg)
    inspect(ct.length() == len, content="true")
    inspect(@sm4.ctr_crypt(key, iv, ct) == msg, content="true")
  }
}

///|
/// 构造指定末字的 IV：前 12 字节 0x10 递增，末 4 字节由 `last` 决定。
fn ctr_iv(last32 : UInt32) -> Bytes {
  let a : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 12; i = i + 1 {
    a[i] = (0x10 + i).to_byte()
  }
  a[12] = ((last32 >> 24) & 0xFF).to_byte()
  a[13] = ((last32 >> 16) & 0xFF).to_byte()
  a[14] = ((last32 >> 8) & 0xFF).to_byte()
  a[15] = (last32 & 0xFF).to_byte()
  Bytes::from_array(a)
}

///| 计数器进位：IV 末字为 0xFFFFFFFF 时，跨块递增须向高位字进位。

///|
/// 期望密文经 OpenSSL 独立计算。
test "sm4 ctr counter carry" {
  let key = @sm4.Sm4Key::new(
    b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10",
  )
  // IV = 10111213141516171819 1A1B FFFFFFFF，48 字节消息触发两次末字进位
  let iv = ctr_iv(0xFFFFFFFF)
  let msg = ctr_det_bytes(48)
  let ct = @sm4.ctr_crypt(key, iv, msg)
  inspect(
    ct ==
    b"\x17\xA9\xC2\x02\x47\xFB\xAA\xC5\xD5\x19\x49\x96\x78\x60\x85\x46\x41\x7F\xF5\x5A\xD5\x64\x85\x88\x03\xD9\xE9\x04\x04\x48\x7A\xDE\x6B\x1B\x05\xF9\x1A\x40\xF2\xFA\x73\x58\x52\x39\xE8\x4E\xDB\x97",
    content="true",
  )
  inspect(@sm4.ctr_crypt(key, iv, ct) == msg, content="true")
}
