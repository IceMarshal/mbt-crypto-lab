///|
// 黑盒测试：规范附录向量、填充边界长度。
// 期望值来源：GB/T 32905-2016 附录 A（A.1、A.2），
// 其余向量由 python-gmssl 与 OpenSSL 3.0.17 双源独立计算并核对一致。

///| GB/T 32905-2016 附录 A.1：SM3("abc")。
test "GB/T 32905-2016 A.1: sm3(\"abc\")" {
  inspect(@sm3.hash_hex(b"abc"), content="66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
}

///| GB/T 32905-2016 附录 A.2：64 字节消息 "abcd" 重复 16 次。
test "GB/T 32905-2016 A.2: sm3(\"abcd\" * 16)" {
  inspect(
    @sm3.hash_hex(
      b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
    ),
    content="debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
  )
}

///| 空消息。
test "sm3 empty message" {
  inspect(@sm3.hash_hex(b""), content="1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b")
}

///| 以 0x61 填充的消息，覆盖填充边界长度 55、56、64、128。
test "sm3 padding boundary lengths" {
  let expected : FixedArray[String] = [
    "288337eef51eec62e7544d7270424c8dbe656254c99852870a73b2453a6a7fb1",
    "ba00ebedaab54065a5fd4f9f56326016203166bcee3eed44ea868d59d67aa3c8",
    "616ec433c359e7c2b19f360e2b8f2a1b6e9ed76b8dc1a7d207b31a5341c611e9",
    "5fd947effbe82a5925faaee9123d43cea200cc257b28ed797505694b4bb020f6",
  ]
  let lengths : FixedArray[Int] = [55, 56, 64, 128]
  for k = 0; k < lengths.length(); k = k + 1 {
    let msg : FixedArray[Byte] = FixedArray::make(lengths[k], b'\x61')
    inspect(@sm3.hash_hex(Bytes::from_array(msg)), content=expected[k])
  }
}
