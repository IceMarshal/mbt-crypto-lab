///|
// PKCS#7 填充（RFC 5652 §6.3）：以 n 个取值为 n 的字节补齐到分组边界，
// n ∈ [1, block_size]，因此整块明文额外补充一个完整分组。

///|
/// 按 `block_size` 字节分组填充 `msg`。
pub fn pkcs7_pad(msg : Bytes, block_size : Int32) -> Bytes {
  let n = block_size - msg.length() % block_size
  let out : FixedArray[Byte] = FixedArray::make(msg.length() + n, b'\x00')
  for i = 0; i < msg.length(); i = i + 1 {
    out[i] = msg[i]
  }
  for i = msg.length(); i < out.length(); i = i + 1 {
    out[i] = n.to_byte()
  }
  Bytes::from_array(out)
}

///|
/// 校验并去除填充。输入长度须为 `block_size` 的非零整数倍，且末尾
/// 填充字节符合 PKCS#7 编码；否则抛出 `Failure`。
pub fn pkcs7_unpad(msg : Bytes, block_size : Int32) -> Bytes raise Error {
  let len = msg.length()
  if len == 0 || len % block_size != 0 {
    raise Failure(
      "pkcs7_unpad: length must be a positive multiple of \{block_size}, got \{len}",
    )
  }
  let n = msg[len - 1].to_int()
  if n < 1 || n > block_size {
    raise Failure("pkcs7_unpad: invalid padding length \{n}")
  }
  for i = len - n; i < len; i = i + 1 {
    if msg[i].to_int() != n {
      raise Failure("pkcs7_unpad: inconsistent padding byte at index \{i}")
    }
  }
  let out : FixedArray[Byte] = FixedArray::make(len - n, b'\x00')
  for i = 0; i < len - n; i = i + 1 {
    out[i] = msg[i]
  }
  Bytes::from_array(out)
}
