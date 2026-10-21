///|
// PKCS#7 填充白盒测试：编码性质、互逆性与非法输入错误路径。

///|
/// 填充长度恒为 [1, block]，空输入补满一个完整分组。
test "pkcs7_pad length property" {
  inspect(pkcs7_pad(b"", 16).length(), content="16")
  inspect(pkcs7_pad(b"0123456789ABCDEF", 16).length(), content="32")
  inspect(pkcs7_pad(b"0123456789ABCDE", 16).length(), content="16")
}

///|
/// 填充/去填充互逆，覆盖边界长度与整块情形。
test "pkcs7 roundtrip" {
  for len in [0, 1, 15, 16, 17, 31, 32, 100] {
    let msg : FixedArray[Byte] = FixedArray::make(len, b'\x00')
    for i = 0; i < len; i = i + 1 {
      msg[i] = ((i * 7 + 3) % 256).to_byte()
    }
    let original = Bytes::from_array(msg)
    inspect(
      pkcs7_unpad(pkcs7_pad(original, 16), 16) == original,
      content="true",
    )
  }
}

///|
fn unpad_fails(msg : Bytes) -> Bool {
  try {
    let _ : Bytes = pkcs7_unpad(msg, 16)
    false
  } catch {
    _ => true
  }
}

///|
/// 非法输入：空串、非整块长度、填充长度越界、填充字节不一致。
test "pkcs7_unpad rejects invalid padding" {
  inspect(unpad_fails(b""), content="true")
  inspect(unpad_fails(b"\x01\x02"), content="true")
  // 合法填充 1 字节 0x01 之后额外篡改：16 字节块末位 0x03 但倒数第三位不为 0x03
  let bad : FixedArray[Byte] = FixedArray::make(16, b'\x41')
  bad[15] = b'\x03'
  inspect(unpad_fails(Bytes::from_array(bad)), content="true")
  // 末字节为 0x00（非法填充长度）
  let zero : FixedArray[Byte] = FixedArray::make(16, b'\x41')
  zero[15] = b'\x00'
  inspect(unpad_fails(Bytes::from_array(zero)), content="true")
  // 末字节为 0x11（超过分组长度 16）
  let over : FixedArray[Byte] = FixedArray::make(16, b'\x41')
  over[15] = b'\x11'
  inspect(unpad_fails(Bytes::from_array(over)), content="true")
  // 合法填充
  let ok : FixedArray[Byte] = FixedArray::make(15, b'\x41')
  inspect(unpad_fails(pkcs7_pad(Bytes::from_array(ok), 16)), content="false")
}
