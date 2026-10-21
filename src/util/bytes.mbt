///|
// 大端字序原语。GB/T 32905-2016 与 GB/T 32907-2016 均按大端序将字节序列
// 组织为 32 位字，此模块为两个算法包提供统一的转换入口。

///| 从 `b` 的 `offset` 起读取 4 字节，按大端序组成 32 位无符号整数。

///|
/// 调用方须保证 `offset + 4 <= b.length()`，越界行为遵循 `Bytes` 下标语义。
pub fn be32_load(b : Bytes, offset : Int32) -> UInt32 {
  (b[offset].to_uint() << 24) |
  (b[offset + 1].to_uint() << 16) |
  (b[offset + 2].to_uint() << 8) |
  b[offset + 3].to_uint()
}

///|
/// 将 `w` 按大端序写入 `buf` 的 `offset` 起 4 字节。
pub fn be32_store(buf : FixedArray[Byte], offset : Int32, w : UInt32) -> Unit {
  buf[offset] = ((w >> 24) & 0xFF).to_byte()
  buf[offset + 1] = ((w >> 16) & 0xFF).to_byte()
  buf[offset + 2] = ((w >> 8) & 0xFF).to_byte()
  buf[offset + 3] = (w & 0xFF).to_byte()
}

///|
/// 将 `w` 按大端序追加到可增长数组 `buf` 末尾。
pub fn be32_push(buf : Array[Byte], w : UInt32) -> Unit {
  buf.push(((w >> 24) & 0xFF).to_byte())
  buf.push(((w >> 16) & 0xFF).to_byte())
  buf.push(((w >> 8) & 0xFF).to_byte())
  buf.push((w & 0xFF).to_byte())
}

///|
/// 32 位循环左移：返回 ROTL(x, n)，n 取 1..31。
pub fn rotl32(x : UInt32, n : Int32) -> UInt32 {
  ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
}
