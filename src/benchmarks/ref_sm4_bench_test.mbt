///|
// 对照基准：T 表实现（产品）与直接计算实现（ref_sm4.mbt）在同一
// 分组序列上的吞吐对比，量化 T 表融合优化的收益。
// 两组用例的处理字节数与调用形态一致，仅合成置换 T 的计算方式不同。

///|
/// 取 16 字节分组的首个 32 位字（用于结果累积，防止计算被消除）。
fn first_word(b : Bytes) -> UInt32 {
  (b[0].to_uint() << 24) |
  (b[1].to_uint() << 16) |
  (b[2].to_uint() << 8) |
  b[3].to_uint()
}

///|
/// T 表实现：连续加密 4096 分组（64 KiB）。
test "sm4 4096 blocks (T-table)" (it : @bench.T) {
  let key = @sm4.Sm4Key::new(Bytes::make(16, 0x2A))
  let block = Bytes::make(16, 0xAB)
  it.bench(fn() {
    let mut acc : UInt32 = 0
    for i = 0; i < 4096; i = i + 1 {
      acc = acc ^ first_word(enc_block(key, block))
    }
    it.keep(acc)
  })
}

///|
/// 直接计算实现：连续加密 4096 分组（64 KiB）。
test "sm4 4096 blocks (direct T)" (it : @bench.T) {
  let rk = @benchmarks.ref_key_schedule(Bytes::make(16, 0x2A))
  let block = Bytes::make(16, 0xAB)
  it.bench(fn() {
    let mut acc : UInt32 = 0
    for i = 0; i < 4096; i = i + 1 {
      acc = acc ^ first_word(@benchmarks.ref_encrypt_block(rk, block))
    }
    it.keep(acc)
  })
}
