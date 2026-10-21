///|
// 黑盒测试：规范附录向量与错误路径。
// 期望值来源：GB/T 32907-2016 附录 A.1（经 OpenSSL 3.0.17 核对一致）。

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
/// 构造确定性伪随机字节序列：(31·i + 11) mod 256。
fn det_bytes(n : Int32) -> Bytes {
  let a : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    a[i] = ((i * 31 + 11) % 256).to_byte()
  }
  Bytes::from_array(a)
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
