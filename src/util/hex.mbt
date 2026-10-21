///|
// 十六进制编解码。解码接受大小写混用的十六进制字符串；编码输出小写。

///|
/// 将 0..15 映射为十六进制数字字符。
fn hex_digit(v : Int32) -> Char {
  if v < 10 {
    ('0'.to_int() + v).to_char().unwrap()
  } else {
    ('a'.to_int() + (v - 10)).to_char().unwrap()
  }
}

///|
/// 将字节序列编码为小写十六进制字符串。
pub fn hex_encode(b : Bytes) -> String {
  let buf = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    buf.write_char(hex_digit(v >> 4))
    buf.write_char(hex_digit(v & 0xF))
  }
  buf.to_string()
}

///|
/// 将单个十六进制数字（UTF-16 代码单元）映射为 0..15，非法输入时抛出异常。
fn hex_val(u : UInt16) -> Int32 raise Error {
  let v = u.to_int()
  if v >= '0'.to_int() && v <= '9'.to_int() {
    v - '0'.to_int()
  } else if v >= 'a'.to_int() && v <= 'f'.to_int() {
    v - 'a'.to_int() + 10
  } else if v >= 'A'.to_int() && v <= 'F'.to_int() {
    v - 'A'.to_int() + 10
  } else {
    raise Failure(
      "hex_decode: invalid hexadecimal character U+\{v.to_string(radix=16)}",
    )
  }
}

///| 解码十六进制字符串。字符串长度须为偶数且仅含十六进制数字，

///|
/// 否则抛出 `Failure`。
pub fn hex_decode(s : String) -> Bytes raise Error {
  let len = s.length()
  if len % 2 != 0 {
    raise Failure("hex_decode: input length must be even, got \{len}")
  }
  let out : FixedArray[Byte] = FixedArray::make(len / 2, b'\x00')
  for i = 0; i < len / 2; i = i + 1 {
    let hi = hex_val(s[i * 2])
    let lo = hex_val(s[i * 2 + 1])
    out[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::from_array(out)
}
