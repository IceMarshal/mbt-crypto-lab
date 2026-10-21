///|
// 白盒测试：锁定 32 位运算语义与编码原语的正确性。

///| 验证 UInt32 加法与乘法按模 2^32 回绕，UInt64 到 UInt32 截断取低 32 位。

///|
/// 该语义是 SM3/SM4 字运算正确性的前提。
test "uint32 wrap-around semantics" {
  let x : UInt32 = 0xFFFFFFFF
  inspect(x + 1, content="0")
  inspect(x * 2 + 3, content="1")
  let big : UInt64 = 0x100000001
  inspect(big.to_uint(), content="1")
}

///|
/// 循环左移性质：ROTL(ROTL(x, n), 32-n) == x。
test "rotl32 involution" {
  let x : UInt32 = 0xDEADBEEF
  inspect(rotl32(rotl32(x, 13), 19) == x, content="true")
  inspect(rotl32(x, 4) == 0xEADBEEFD, content="true")
}

///|
/// 大端字序存储、读取与追加互逆。
test "be32 store/load roundtrip" {
  let buf : FixedArray[Byte] = FixedArray::make(8, b'\x00')
  be32_store(buf, 0, 0xDEADBEEF)
  be32_store(buf, 4, 0x01020304)
  let bytes = Bytes::from_array(buf)
  inspect(hex_encode(bytes), content="deadbeef01020304")
  inspect(be32_load(bytes, 0) == 0xDEADBEEF, content="true")
  inspect(be32_load(bytes, 4) == 0x01020304, content="true")
  let acc : Array[Byte] = []
  be32_push(acc, 0xDEADBEEF)
  inspect(acc.length(), content="4")
  inspect(acc[0].to_int(), content="222")
  inspect(acc[3].to_int(), content="239")
}

///|
/// 十六进制编解码互逆，覆盖大小写混用输入。
test "hex encode/decode roundtrip" {
  let cases : Array[(String, String)] = [
    ("", ""),
    ("00", "00"),
    ("01", "01"),
    ("deadbeef", "deadbeef"),
    ("DEADBEEF", "deadbeef"),
    ("DeAdBeEf", "deadbeef"),
    ("0123456789abcdef", "0123456789abcdef"),
  ]
  for entry in cases {
    let (input, expected) = entry
    inspect(hex_encode(hex_decode(input)), content=expected)
  }
}

///|
fn hex_decode_fails(s : String) -> Bool {
  try {
    let _ : Bytes = hex_decode(s)
    false
  } catch {
    _ => true
  }
}

///|
/// 非法输入必须抛出异常：奇数长度与非法字符。
test "hex_decode rejects invalid input" {
  inspect(hex_decode_fails("abc"), content="true")
  inspect(hex_decode_fails("zz"), content="true")
  inspect(hex_decode_fails("0g"), content="true")
  inspect(hex_decode_fails("00"), content="false")
}
