///|
// SM3 密码杂凑算法，依据 GB/T 32905-2016。
//
// 实现结构参考 GmSSL 与 OpenSSL crypto/sm3：消息扩展采用 W[0..67] 与
// W'[0..63] 数组布局；压缩函数以八个局部字 A..H 展开；字运算依赖
// MoonBit UInt32 模 2^32 回绕语义（该语义由 src/util 白盒测试锁定）。

///|
/// 返回初始杂凑值 IV（GB/T 32905-2016 第 5.3 节）的新建数组。
fn sm3_iv() -> FixedArray[UInt32] {
  [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D,
    0xB0FB0E4E,
  ]
}

///| 布尔函数 FF_j，GB/T 32905-2016 第 5.2 节：

///| j ∈ [0,15] 时 FF_j(X,Y,Z) = X ⊕ Y ⊕ Z，

///|
/// j ∈ [16,63] 时 FF_j(X,Y,Z) = (X ∧ Y) ∨ (X ∧ Z) ∨ (Y ∧ Z)。
fn ff_j(j : Int32, x : UInt32, y : UInt32, z : UInt32) -> UInt32 {
  if j < 16 {
    x ^ y ^ z
  } else {
    (x & y) | (x & z) | (y & z)
  }
}

///| 布尔函数 GG_j，GB/T 32905-2016 第 5.2 节：

///| j ∈ [0,15] 时 GG_j(X,Y,Z) = X ⊕ Y ⊕ Z，

///|
/// j ∈ [16,63] 时 GG_j(X,Y,Z) = (X ∧ Y) ∨ (¬X ∧ Z)。
fn gg_j(j : Int32, x : UInt32, y : UInt32, z : UInt32) -> UInt32 {
  if j < 16 {
    x ^ y ^ z
  } else {
    (x & y) | ((x ^ 0xFFFFFFFF) & z)
  }
}

///|
/// 置换函数 P0(X) = X ⊕ (X <<< 9) ⊕ (X <<< 17)。
fn p0(x : UInt32) -> UInt32 {
  x ^ @util.rotl32(x, 9) ^ @util.rotl32(x, 17)
}

///|
/// 置换函数 P1(X) = X ⊕ (X <<< 15) ⊕ (X <<< 23)。
fn p1(x : UInt32) -> UInt32 {
  x ^ @util.rotl32(x, 15) ^ @util.rotl32(x, 23)
}

///| 常量 T_j：0x79CC4519（0 ≤ j ≤ 15），0x7A879D8A（16 ≤ j ≤ 63）。

///|
/// 压缩函数中按 ROTL(T_j, j mod 32) 参与第 j 轮 SS1 的计算。
fn t_j(j : Int32) -> UInt32 {
  if j < 16 {
    0x79CC4519
  } else {
    0x7A879D8A
  }
}

///|
/// 压缩函数 CF：以 512 位分组 `block` 更新 256 位杂凑值 `v`。
fn sm3_compress(v : FixedArray[UInt32], block : Bytes) -> Unit {
  let w : FixedArray[UInt32] = FixedArray::make(68, 0)
  let w1 : FixedArray[UInt32] = FixedArray::make(64, 0)
  for j = 0; j < 16; j = j + 1 {
    w[j] = @util.be32_load(block, j * 4)
  }
  for j = 16; j < 68; j = j + 1 {
    w[j] = p1(w[j - 16] ^ w[j - 9] ^ @util.rotl32(w[j - 3], 15)) ^
      @util.rotl32(w[j - 13], 7) ^
      w[j - 6]
  }
  for j = 0; j < 64; j = j + 1 {
    w1[j] = w[j] ^ w[j + 4]
  }
  let mut a = v[0]
  let mut b = v[1]
  let mut c = v[2]
  let mut d = v[3]
  let mut e = v[4]
  let mut f = v[5]
  let mut g = v[6]
  let mut h = v[7]
  for j = 0; j < 64; j = j + 1 {
    let a12 = @util.rotl32(a, 12)
    let ss1 = @util.rotl32(a12 + e + @util.rotl32(t_j(j), j % 32), 7)
    let ss2 = ss1 ^ a12
    let tt1 = ff_j(j, a, b, c) + d + ss2 + w1[j]
    let tt2 = gg_j(j, e, f, g) + h + ss1 + w[j]
    d = c
    c = @util.rotl32(b, 9)
    b = a
    a = tt1
    h = g
    g = @util.rotl32(f, 19)
    f = e
    e = p0(tt2)
  }
  v[0] = v[0] ^ a
  v[1] = v[1] ^ b
  v[2] = v[2] ^ c
  v[3] = v[3] ^ d
  v[4] = v[4] ^ e
  v[5] = v[5] ^ f
  v[6] = v[6] ^ g
  v[7] = v[7] ^ h
}
