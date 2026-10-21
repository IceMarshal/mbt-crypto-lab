///|
// 计数器工作模式 CTR（NIST SP 800-38A §6.5）。
//
// IV 即初始计数器分组，按 128 位大端整数逐块递增（SP 800-38A
// 附录 B.2 的标准递增规则，模 2¹²⁸ 回绕）；密钥流为 E_K(CTR_i)，
// 与消息按位异或，尾部短块截断密钥流。加密与解密为同一函数，
// 无填充，输出与输入等长。

///|
/// SM4-CTR 加解密：`iv` 长度须为 16，输出与 `msg` 等长。
pub fn ctr_crypt(key : Sm4Key, iv : Bytes, msg : Bytes) -> Bytes raise Error {
  if iv.length() != 16 {
    raise Failure("ctr_crypt: iv must be 16 bytes, got \{iv.length()}")
  }
  let n = msg.length()
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  let mut c0 = @util.be32_load(iv, 0)
  let mut c1 = @util.be32_load(iv, 4)
  let mut c2 = @util.be32_load(iv, 8)
  let mut c3 = @util.be32_load(iv, 12)
  let mut off = 0
  while n - off >= 16 {
    let (k0, k1, k2, k3) = sm4_crypt_words(key.rk, c0, c1, c2, c3, false)
    @util.be32_store(out, off, k0 ^ @util.be32_load(msg, off))
    @util.be32_store(out, off + 4, k1 ^ @util.be32_load(msg, off + 4))
    @util.be32_store(out, off + 8, k2 ^ @util.be32_load(msg, off + 8))
    @util.be32_store(out, off + 12, k3 ^ @util.be32_load(msg, off + 12))
    // 计数器按 128 位大端整数递增，进位逐字传播
    c3 = c3 + 1
    if c3 == 0 {
      c2 = c2 + 1
      if c2 == 0 {
        c1 = c1 + 1
        if c1 == 0 {
          c0 = c0 + 1
        }
      }
    }
    off = off + 16
  }
  let tail = n - off
  if tail > 0 {
    let (k0, k1, k2, k3) = sm4_crypt_words(key.rk, c0, c1, c2, c3, false)
    let ks : FixedArray[Byte] = FixedArray::make(16, b'\x00')
    @util.be32_store(ks, 0, k0)
    @util.be32_store(ks, 4, k1)
    @util.be32_store(ks, 8, k2)
    @util.be32_store(ks, 12, k3)
    for i = 0; i < tail; i = i + 1 {
      out[off + i] = (msg[off + i].to_int() ^ ks[i].to_int()).to_byte()
    }
  }
  Bytes::from_array(out)
}
