///|
// 白盒测试：T 表分解与直接计算 L(τ(x)) 的等价性，及 CK 参数生成规则。

///|
/// T 表优化等价性：确定性采样 2^16 个字，覆盖每张表的全部字节取值。
test "sm4_t_fast equivalence with direct computation" {
  let mut x : UInt32 = 0x07040109
  for i = 0; i < 65536; i = i + 1 {
    x = (x * 1103515245 + 12345) & 0xFFFFFFFF
    inspect(sm4_t_fast(x) == sm4_l(sm4_tau(x)), content="true")
  }
}

///|
/// 固定参数生成规则：ck(i, j) = (4i + j)·7 mod 256，GB/T 32907-2016 第 5.3.2 节。
test "sm4_ck generation rule" {
  for i = 0; i < 32; i = i + 1 {
    let expected = sm4_ck[i]
    let mut built : UInt32 = 0
    for j = 0; j < 4; j = j + 1 {
      let byte = (4 * i + j) * 7 % 256
      built = built | (byte.reinterpret_as_uint() << ((3 - j) * 8))
    }
    inspect(built == expected, content="true")
  }
}

///|
/// S 盒为 [0, 255] 的双射。
test "sm4_sbox is a permutation" {
  let seen : FixedArray[Bool] = FixedArray::make(256, false)
  for i = 0; i < 256; i = i + 1 {
    let v = sm4_sbox[i].to_int()
    inspect(seen[v], content="false")
    seen[v] = true
  }
  for i = 0; i < 256; i = i + 1 {
    inspect(seen[i], content="true")
  }
}
