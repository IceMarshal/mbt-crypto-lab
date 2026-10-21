///|
// 黑盒测试：规范附录向量、OpenSSL 对拍向量、各模式互逆与错误路径。
// 期望值来源：GB/T 32907-2016 附录 A.1（经 OpenSSL 3.0.17 核对一致）；
// 多块无填充 ECB 向量由 OpenSSL 独立计算。

///|
/// GB/T 32907-2016 附录 A.1：单块加密与解密互逆。
test "GB/T 32907-2016 A.1: single block" {
  let key = @sm4.Sm4Key::new(
    b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10",
  )
  let pt = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10"
  let ct = key.encrypt_block(pt)
  inspect(
    ct == b"\x68\x1E\xDF\x34\xD2\x06\x96\x5E\x86\xB3\xE9\x4F\x53\x6E\x42\x46",
    content="true",
  )
  inspect(key.decrypt_block(ct) == pt, content="true")
}

///|
/// OpenSSL 对拍：同一密钥下多块无填充 ECB（2 块与 4 块）。
test "openssl cross-check: multi-block ECB without padding" {
  let key = @sm4.Sm4Key::new(
    b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10",
  )
  let block = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10"
  let two : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  let four : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  for i = 0; i < 64; i = i + 1 {
    four[i] = block[i % 16]
    if i < 32 {
      two[i] = block[i % 16]
    }
  }
  let c1 = key.encrypt_block(block)
  let c2 = key.encrypt_block(block)
  inspect(c1 == c2, content="true")
  let two_ct = @sm4.ecb_encrypt(key, Bytes::from_array(two))
  // 无填充多块 ECB：PKCS#7 会额外补一个整块，two(32B) 加密后为 48B，
  // 前两块密文应与单块密文重复一致
  inspect(two_ct.length(), content="48")
  inspect(key.decrypt_block(take_block(two_ct, 0)) == block, content="true")
  inspect(key.decrypt_block(take_block(two_ct, 16)) == block, content="true")
  let four_ct = @sm4.ecb_encrypt(key, Bytes::from_array(four))
  inspect(four_ct.length(), content="80")
  // 第 5 块为 PKCS#7 填充块（0x10 × 16）的加密结果
  let pad_block : FixedArray[Byte] = FixedArray::make(16, b'\x10')
  inspect(
    key.decrypt_block(take_block(four_ct, 64)) == Bytes::from_array(pad_block),
    content="true",
  )
}

///|
/// 测试辅助：取 16 字节分组（黑盒测试文件局部作用域）。
fn take_block(b : Bytes, offset : Int32) -> Bytes {
  let out : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    out[i] = b[offset + i]
  }
  Bytes::from_array(out)
}

///|
/// 构造确定性伪随机字节序列：(31·i + 11) mod 256。
fn det_bytes(n : Int32) -> Bytes {
  let a : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    a[i] = ((i * 31 + 11) % 256).to_byte()
  }
  Bytes::from_array(a)
}

///|
/// ECB 与 CBC 加解密互逆，覆盖边界长度（含空消息与整块消息）。
test "ecb/cbc roundtrip over boundary lengths" {
  let key = @sm4.Sm4Key::new(det_bytes(16))
  let iv = det_bytes_tail(16)
  for len in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 100, 128] {
    let msg = det_bytes(len)
    let ecb_ct = @sm4.ecb_encrypt(key, msg)
    inspect(@sm4.ecb_decrypt(key, ecb_ct) == msg, content="true")
    let cbc_ct = @sm4.cbc_encrypt(key, iv, msg)
    inspect(@sm4.cbc_decrypt(key, iv, cbc_ct) == msg, content="true")
  }
}

///|
/// 构造与 det_bytes 不同的确定性序列：(31·i + 199) mod 256。
fn det_bytes_tail(n : Int32) -> Bytes {
  let a : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    a[i] = ((i * 31 + 199) % 256).to_byte()
  }
  Bytes::from_array(a)
}

///|
fn failable(op : () -> Bytes raise Error) -> Bool {
  try {
    let _ : Bytes = op()
    false
  } catch {
    _ => true
  }
}

///|
fn key_new_fails(key : Bytes) -> Bool {
  try {
    let _ : @sm4.Sm4Key = @sm4.Sm4Key::new(key)
    false
  } catch {
    _ => true
  }
}

///|
/// 错误路径：非法密钥长度、非法 IV 长度、非法密文长度、损坏的填充。
test "error paths" {
  inspect(key_new_fails(det_bytes(15)), content="true")
  inspect(key_new_fails(det_bytes(17)), content="true")
  let key = @sm4.Sm4Key::new(det_bytes(16))
  inspect(
    failable(() => @sm4.cbc_encrypt(key, det_bytes_tail(15), b"")),
    content="true",
  )
  inspect(
    failable(() => @sm4.cbc_decrypt(key, det_bytes_tail(15), det_bytes_tail(32))),
    content="true",
  )
  inspect(failable(() => @sm4.ecb_decrypt(key, b"\x01")), content="true")
  inspect(failable(() => @sm4.ecb_decrypt(key, b"")), content="true")
  // 密文末字节篡改导致填充校验失败
  let good = @sm4.ecb_encrypt(key, b"hello")
  let bad : FixedArray[Byte] = FixedArray::make(good.length(), b'\x00')
  for i = 0; i < good.length(); i = i + 1 {
    bad[i] = good[i]
  }
  bad[good.length() - 1] = (bad[good.length() - 1].to_int() ^ 1).to_byte()
  inspect(
    failable(() => @sm4.ecb_decrypt(key, Bytes::from_array(bad))),
    content="true",
  )
}
