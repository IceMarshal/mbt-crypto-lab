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
    """SM4 向量：ECB 与 CBC 模式（PKCS#7 填充），随机密钥/IV，明文长度 0..128 全覆盖。"""
    drbg = Drbg(SEED + b"sm4")
    enc = sm4.CryptSM4()
    lines = []
    for n in range(0, 129):
        key = det_bytes(16, drbg)
        iv = det_bytes(16, drbg)
        msg = det_bytes(n, drbg)
        enc.set_key(key, sm4.SM4_ENCRYPT)
        ecb_ct = enc.crypt_ecb(msg)
        cbc_ct = enc.crypt_cbc(iv, msg)
        dec = sm4.CryptSM4()
        dec.set_key(key, sm4.SM4_DECRYPT)
        assert dec.crypt_ecb(ecb_ct) == msg
        assert dec.crypt_cbc(iv, cbc_ct) == msg
        lines.append(
            f'    ("{key.hex()}", "{iv.hex()}", "{msg.hex()}", '
            f'"{ecb_ct.hex()}", "{cbc_ct.hex()}"),'
        )
    body = "\n".join(lines)
    return f"""///|
// 自动生成：tests/gen_vectors.py（固定种子 SHA-256 DRBG）。
// 期望值来源：python-gmssl 3.2.2（ECB/CBC，PKCS#7 填充），明文长度 0..128 全覆盖。
// 字段：(key_hex, iv_hex, msg_hex, ecb_ct_hex, cbc_ct_hex)。
// 请勿手工修改。

test "sm4 ecb/cbc golden vectors" {{
  let vectors : FixedArray[(String, String, String, String, String)] = [
{body}
  ]
  for entry in vectors {{
    let (key_hex, iv_hex, msg_hex, ecb_ct_hex, cbc_ct_hex) = entry
    let key = Sm4Key::new(@util.hex_decode(key_hex))
    let iv = @util.hex_decode(iv_hex)
    let msg = @util.hex_decode(msg_hex)
    let ecb_ct = @util.hex_decode(ecb_ct_hex)
    let cbc_ct = @util.hex_decode(cbc_ct_hex)
    inspect(ecb_encrypt(key, msg) == ecb_ct, content="true")
    inspect(ecb_decrypt(key, ecb_ct) == msg, content="true")
    inspect(cbc_encrypt(key, iv, msg) == cbc_ct, content="true")
    inspect(cbc_decrypt(key, iv, cbc_ct) == msg, content="true")
  }}
}}
"""


def openssl_sm4_ctr(key: bytes, iv: bytes, msg: bytes) -> bytes:
    """以 OpenSSL 命令行独立计算 SM4-CTR（python-gmssl 未提供该模式）。"""
    import subprocess

    p = subprocess.run(
        [
            "openssl",
            "enc",
            "-sm4-ctr",
            "-K",
            key.hex(),
            "-iv",
            iv.hex(),
            "-nosalt",
        ],
        input=msg,
        capture_output=True,
        check=True,
    )
    return p.stdout


def gen_ctr() -> str:
    """SM4-CTR 向量：明文长度 0..128 全覆盖，及计数器进位 IV 用例。"""
    drbg = Drbg(SEED + b"sm4-ctr")
    cases = []
    for n in range(0, 129):
        key = det_bytes(16, drbg)
        iv = det_bytes(16, drbg)
        msg = det_bytes(n, drbg)
        cases.append((key, iv, msg, openssl_sm4_ctr(key, iv, msg)))
    # 进位用例：末字/末两字/全 F 的 IV，80 字节消息触发进位链与回绕
    for iv_hex in [
        "101112131415161718191a1bffffffff",
        "0000000000000000ffffffffffffffff",
        "ffffffffffffffffffffffffffffffff",
    ]:
        key = det_bytes(16, drbg)
        msg = det_bytes(80, drbg)
        iv = bytes.fromhex(iv_hex)
        cases.append((key, iv, msg, openssl_sm4_ctr(key, iv, msg)))
    lines = [
        f'    ("{k.hex()}", "{i.hex()}", "{m.hex()}", "{c.hex()}"),'
        for k, i, m, c in cases
    ]
    body = "\n".join(lines)
    return f"""///|
// 自动生成：tests/gen_vectors.py（固定种子 SHA-256 DRBG）。
// 期望值来源：OpenSSL 3.0.17 enc -sm4-ctr（python-gmssl 未提供 CTR 模式，
// openssl 为该模式的独立期望值来源）。
// 明文长度 0..128 全覆盖，另含 3 组计数器进位 IV 用例（末字/末两字/全 F）。
// 字段：(key_hex, iv_hex, msg_hex, ct_hex)。
// 请勿手工修改。

test "sm4 ctr golden vectors" {{
  let vectors : FixedArray[(String, String, String, String)] = [
{body}
  ]
  for entry in vectors {{
    let (key_hex, iv_hex, msg_hex, ct_hex) = entry
    let key = Sm4Key::new(@util.hex_decode(key_hex))
    let iv = @util.hex_decode(iv_hex)
    let msg = @util.hex_decode(msg_hex)
    let ct = @util.hex_decode(ct_hex)
    inspect(ctr_crypt(key, iv, msg) == ct, content="true")
    inspect(ctr_crypt(key, iv, ct) == msg, content="true")
  }}
}}
"""


def gen_hmac() -> str:
    """HMAC-SM3 向量：密钥长度（含空/短/分组界/超分组）× 消息边界长度矩阵。"""
    import hashlib
    import hmac as py_hmac

    drbg = Drbg(SEED + b"hmac-sm3")
    key_lens = [0, 1, 20, 63, 64, 65, 100, 200]
    msg_lens = [0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 1000]
    lines = []
    for kl in key_lens:
        key = det_bytes(kl, drbg)
        for ml in msg_lens:
            msg = det_bytes(ml, drbg)
            mac = py_hmac.new(key, msg, "sm3").digest()
            assert len(mac) == 32
            lines.append(f'    ("{key.hex()}", "{msg.hex()}", "{mac.hex()}"),')
    body = "\n".join(lines)
    return f"""///|
// 自动生成：tests/gen_vectors.py（固定种子 SHA-256 DRBG）。
// 期望值来源：python hmac 标准库（digestmod=sm3，hashlib 原生实现），
// 并经 OpenSSL dgst -sm3 -mac HMAC -macopt hexkey 抽样核对一致。
// 密钥长度 0/1/20/63/64/65/100/200 × 消息边界长度 11 档，共 88 组。
// 字段：(key_hex, msg_hex, mac_hex)。
// 请勿手工修改。

test "sm3 hmac golden vectors" {{
  let vectors : FixedArray[(String, String, String)] = [
{body}
  ]
  for entry in vectors {{
    let (key_hex, msg_hex, mac_hex) = entry
    inspect(hmac(@util.hex_decode(key_hex), @util.hex_decode(msg_hex)) == @util.hex_decode(mac_hex), content="true")
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
        targets.append(("src/sm4/ctr_golden_wbtest.mbt", gen_ctr))
        targets.append(("src/sm3/hmac_golden_wbtest.mbt", gen_hmac))
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
