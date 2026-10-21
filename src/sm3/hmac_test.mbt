///|
// 黑盒测试：HMAC-SM3 的 RFC 2104 结构风格向量。
// 期望值由 python hmac（digestmod=sm3，hashlib 原生实现）计算，
// 并经 OpenSSL 3.0.17 dgst -sm3 -mac HMAC -macopt hexkey 独立核对一致。

///|
/// RFC 2104 结构风格向量：常规、短密钥、超长密钥（先杂凑）。
test "hmac-sm3 structural vectors" {
  // A：key = 0x0b × 20，msg = "Hi There"
  inspect(
    @sm3.hmac_hex(
      b"\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B",
      b"Hi There",
    ),
    content="51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70",
  )
  // B：key = "Jefe"，msg = "what do ya want for nothing?"
  inspect(
    @sm3.hmac_hex(b"Jefe", b"what do ya want for nothing?"),
    content="2e87f1d16862e6d964b50a5200bf2b10b764faa9680a296a2405f24bec39f882",
  )
  // C：key = 0xaa × 80（长于分组，先杂凑）
  let long_key : FixedArray[Byte] = FixedArray::make(80, b'\xAA')
  inspect(
    @sm3.hmac_hex(
      Bytes::from_array(long_key),
      b"Test Using Larger Than Block-Size Key - Hash Key First",
    ),
    content="c794651f5455f80546855f744ff50146d5286e1cb677d5088c059cd8b03bb9ce",
  )
  // D：key = 0xaa × 131，消息亦超过一个分组
  let key131 : FixedArray[Byte] = FixedArray::make(131, b'\xAA')
  inspect(
    @sm3.hmac_hex(
      Bytes::from_array(key131),
      b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
    ),
    content="dd4e79048895ea5707a66640404dab29c1528cb9ef65b44fb812db5bf5bfe623",
  )
  // E：key = 0x01..0x14，msg = "abc"（与 openssl hexkey 对拍用例一致）
  let key20 : FixedArray[Byte] = FixedArray::make(20, b'\x00')
  for i = 0; i < 20; i = i + 1 {
    key20[i] = (i + 1).to_byte()
  }
  inspect(
    @sm3.hmac_hex(Bytes::from_array(key20), b"abc"),
    content="aafb25809d554c2e1140806946f31b67a95a7cb8c86cf9f9c13e59bd065b6106",
  )
}
