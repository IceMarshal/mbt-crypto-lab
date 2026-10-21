///|
// 对照正确性测试：直接计算参考实现与产品 T 表实现对同一分组序列
// 输出一致。该前提成立时，两组基准用例的吞吐差异才能归因于
// 合成置换 T 的计算方式。

test "ref_sm4 agrees with product implementation" {
  let rk = @benchmarks.ref_key_schedule(Bytes::make(16, 0x2A))
  let key = @sm4.Sm4Key::new(Bytes::make(16, 0x2A))
  for i = 0; i < 64; i = i + 1 {
    let block = Bytes::make(16, ((i * 7 + 1) % 256).to_byte())
    inspect(
      @benchmarks.ref_encrypt_block(rk, block) == key.encrypt_block(block),
      content="true",
    )
  }
}
