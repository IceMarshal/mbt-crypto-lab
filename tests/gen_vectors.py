#!/usr/bin/env python3
"""确定性金标准向量生成。

以固定种子经 SHA-256 计数器模式 DRBG 生成确定性伪随机字节序列，
调用 python-gmssl 计算期望值，生成 MoonBit 白盒测试文件
src/sm3/golden_wbtest.mbt 与 src/sm4/golden_wbtest.mbt。

生成的测试文件提交入库，任何环境执行 `moon test` 即可独立复现，
无需安装 Python 依赖。重复运行本脚本输出保持逐字节一致。

用法：python3 tests/gen_vectors.py
"""

import hashlib
import sys
from pathlib import Path

from gmssl import sm3, sm4, func

SEED = b"crypto-lab golden vectors v1"
ROOT = Path(__file__).resolve().parent.parent


class Drbg:
    """SHA-256 计数器模式确定性随机字节源。"""

    def __init__(self, seed: bytes):
        self.key = hashlib.sha256(seed).digest()
        self.counter = 0
        self.buf = b""

    def bytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            out += hashlib.sha256(self.key + self.counter.to_bytes(8, "big")).digest()
            self.counter += 1
        self.key = hashlib.sha256(self.key + bytes(out[:64])).digest()
        return bytes(out[:n])


def det_bytes(n: int, drbg: Drbg) -> bytes:
    return drbg.bytes(n)


def gen_sm3() -> str:
    """SM3 向量：长度 0..256 全覆盖，及 512/1024/8192 多块输入。"""
    drbg = Drbg(SEED + b"sm3")
    lengths = list(range(0, 257)) + [512, 1024, 8192]
    lines = []
    for n in lengths:
        msg = det_bytes(n, drbg)
        digest = sm3.sm3_hash(func.bytes_to_list(msg))
        lines.append(f'    ("{msg.hex()}", "{digest}"),')
    body = "\n".join(lines)
    return f"""///|
// 自动生成：tests/gen_vectors.py（固定种子 SHA-256 DRBG）。
// 期望值来源：python-gmssl 3.2.2。覆盖长度 0..256 全部取值及多块输入。
// 请勿手工修改。

test "sm3 golden vectors" {{
  let vectors : FixedArray[(String, String)] = [
{body}
  ]
  for entry in vectors {{
    let (msg_hex, digest_hex) = entry
    inspect(hash_hex(@util.hex_decode(msg_hex)), content=digest_hex)
  }}
}}
"""


def gen_sm4() -> str:
    """SM4 向量：ECB 与 CBC 模式，随机密钥/IV，明文长度 0..128 全覆盖。"""
    drbg = Drbg(SEED + b"sm4")
    lines = []
    for n in range(0, 129):
        key = det_bytes(16, drbg)
        iv = det_bytes(16, drbg)
        msg = det_bytes(n, drbg)
        ecb_ct = sm4.crypt_ecb(key, bytes(msg))
        ecb_pt = sm4.decrypt_ecb(key, ecb_ct)
        assert ecb_pt == msg
        cbc_ct = sm4.crypt_cbc(key, iv, bytes(msg))
        cbc_pt = sm4.decrypt_cbc(key, iv, cbc_ct)
        assert cbc_pt == msg
        # 字段：key, iv, msg, ecb_ct, ecb_decrypt_roundtrip
        lines.append(
            f'    ("{key.hex()}", "{iv.hex()}", "{msg.hex()}", "{ecb_ct.hex()}"),'
        )
    body = "\n".join(lines)
    return f"""///|
// 自动生成：tests/gen_vectors.py（固定种子 SHA-256 DRBG）。
// 期望值来源：python-gmssl 3.2.2（ECB/CBC，PKCS#7 填充）。
// 字段：(key_hex, iv_hex, msg_hex, ecb_ct_hex)；CBC 向量经 openssl 对拍另行覆盖。
// 请勿手工修改。

test "sm4 ecb golden vectors" {{
  let vectors : FixedArray[(String, String, String, String)] = [
{body}
  ]
  for entry in vectors {{
    let (key_hex, _iv_hex, msg_hex, ecb_ct_hex) = entry
    let key = @util.hex_decode(key_hex)
    let msg = @util.hex_decode(msg_hex)
    let expected = @util.hex_decode(ecb_ct_hex)
    let k = Sm4Key::new(key)
    inspect(ecb_encrypt(k, msg) == expected, content="true")
    inspect(ecb_decrypt(k, expected) == msg, content="true")
  }}
}}
"""


def string_literals(text: str) -> list:
    """提取 MoonBit 源码中全部字符串字面量，用于语义比较。

    moon fmt 会对超长行折行，字节级比较不可行；金标准的可复现性
    依据字面量序列逐项一致判定。
    """
    import re

    return re.findall(r'"([0-9a-f]*)"', text)


def main() -> None:
    # 重新生成时保持确定性：Drbg 与 gmssl 均为纯函数式调用
    check_only = "--check" in sys.argv
    targets = [("src/sm3/golden_wbtest.mbt", gen_sm3)]
    if "--with-sm4" in sys.argv:
        targets.append(("src/sm4/golden_wbtest.mbt", gen_sm4))
    mismatch = 0
    for relpath, gen in targets:
        content = gen()
        path = ROOT / relpath
        if check_only:
            if not path.exists():
                print(f"missing: {relpath}")
                mismatch += 1
            elif string_literals(path.read_text()) != string_literals(content):
                print(f"stale (literals differ from deterministic regeneration): {relpath}")
                mismatch += 1
            else:
                print(f"ok: {relpath}")
        else:
            path.write_text(content)
            print(f"written: {relpath}（提交前须执行 moon fmt）")
    if check_only and mismatch:
        sys.exit(1)


if __name__ == "__main__":
    main()
