///|
// 性能基准：SM3 杂凑与 SM4 分组密码（产品实现）。
// 运行：moon bench -p icemarshal/crypto-lab/src/bench --release
// 对照组（非 T 表的直接计算参考实现）见 ref_sm4_bench_test.mbt。

///| 全包装：吸收异常分支以满足 bench 闭包类型。

///|
/// 基准输入恒满足长度约束，异常分支不可达，返回原值仅为满足类型。
fn enc_block(key : @sm4.Sm4Key, b : Bytes) -> Bytes {
  key.encrypt_block(b) catch {
    _ => b
  }
}

///|
fn cbc_enc(key : @sm4.Sm4Key, iv : Bytes, m : Bytes) -> Bytes {
  @sm4.cbc_encrypt(key, iv, m) catch {
    _ => m
  }
}

///|
/// SM3 一次性杂凑，64 字节输入。
test "sm3 hash 64B" (it : @bench.T) {
  let data = Bytes::make(64, 0xAB)
  it.bench(fn() { it.keep(@sm3.hash(data)) })
}

///|
/// SM3 一次性杂凑，1 KiB 输入。
test "sm3 hash 1KiB" (it : @bench.T) {
  let data = Bytes::make(1024, 0xAB)
  it.bench(fn() { it.keep(@sm3.hash(data)) })
}

///|
/// SM3 一次性杂凑，64 KiB 输入。
test "sm3 hash 64KiB" (it : @bench.T) {
  let data = Bytes::make(65536, 0xAB)
  it.bench(fn() { it.keep(@sm3.hash(data)) })
}

///|
/// SM3 流式杂凑，64 KiB 输入按 1 KiB 分块吸收。
test "sm3 streaming 64KiB (1KiB chunks)" (it : @bench.T) {
  let chunk = Bytes::make(1024, 0xAB)
  it.bench(fn() {
    let ctx = @sm3.Sm3::new()
    for i = 0; i < 64; i = i + 1 {
      ctx.update(chunk)
    }
    it.keep(ctx.finalize())
  })
}

///|
/// SM4 单块加密。
test "sm4 encrypt_block" (it : @bench.T) {
  let key = @sm4.Sm4Key::new(Bytes::make(16, 0x2A))
  let block = Bytes::make(16, 0xAB)
  it.bench(fn() { it.keep(enc_block(key, block)) })
}

///|
/// SM4-ECB 加密，64 KiB 输入（PKCS#7 填充）。
test "sm4 ecb_encrypt 64KiB" (it : @bench.T) {
  let key = @sm4.Sm4Key::new(Bytes::make(16, 0x2A))
  let data = Bytes::make(65536, 0xAB)
  it.bench(fn() { it.keep(@sm4.ecb_encrypt(key, data)) })
}

///|
/// SM4-CBC 加密，64 KiB 输入（PKCS#7 填充）。
test "sm4 cbc_encrypt 64KiB" (it : @bench.T) {
  let key = @sm4.Sm4Key::new(Bytes::make(16, 0x2A))
  let iv = Bytes::make(16, 0x55)
  let data = Bytes::make(65536, 0xAB)
  it.bench(fn() { it.keep(cbc_enc(key, iv, data)) })
}
