#!/bin/sh
# OpenSSL 命令行工具对拍：SM3 摘要与 SM4 加密。
#
# 期望值与 tests/gen_vectors.py 生成的金标准同源（python-gmssl）。
# 本脚本以 OpenSSL 独立重算并逐字节比对，确认三个实现来源一致：
# 规范附录向量（见各包 *_test.mbt）、python-gmssl、OpenSSL。
#
# 用法：sh tests/verify_openssl.sh
# 依赖：openssl 3.x（支持 sm3 摘要与 sm4-ecb/sm4-cbc），python3（仅作十六进制解码）

set -eu

TMPDIR_M=$(mktemp -d)
trap 'rm -rf "$TMPDIR_M"' EXIT

fail=0
pass=0

# hex_to_file HEX FILE
hex_to_file() {
    python3 -c "import sys; sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))" "$1" > "$2"
}

# check_sm3 NAME MSG_HEX EXPECTED_HEX
check_sm3() {
    name=$1
    hex_to_file "$2" "$TMPDIR_M/msg.bin"
    actual=$(openssl dgst -sm3 -r "$TMPDIR_M/msg.bin" | awk '{print $1}')
    if [ "$actual" = "$3" ]; then
        pass=$((pass + 1))
    else
        echo "FAIL sm3/$name: expected $3, got $actual"
        fail=$((fail + 1))
    fi
}

# check_sm4_enc NAME CIPHER KEY_HEX IV_HEX MSG_HEX EXPECTED_HEX PAD_FLAG
# PAD_FLAG 为 nopad 时不启用填充（输入须为整块），否则启用 PKCS#7。
check_sm4_enc() {
    name=$1
    cipher=$2
    padflag=$7
    hex_to_file "$5" "$TMPDIR_M/msg.bin"
    : > "$TMPDIR_M/out.bin"
    if [ "$padflag" = "nopad" ]; then
        openssl enc "-$cipher" -K "$3" -iv "$4" -nosalt -nopad \
            -in "$TMPDIR_M/msg.bin" -out "$TMPDIR_M/out.bin" 2>/dev/null || true
    else
        openssl enc "-$cipher" -K "$3" -iv "$4" -nosalt \
            -in "$TMPDIR_M/msg.bin" -out "$TMPDIR_M/out.bin" 2>/dev/null || true
    fi
    actual=$(python3 -c "print(open('$TMPDIR_M/out.bin','rb').read().hex())")
    expected=$(printf '%s' "$6" | tr 'A-F' 'a-f')
    if [ "$actual" = "$expected" ]; then
        pass=$((pass + 1))
    else
        echo "FAIL $cipher/$name: expected $6, got $actual"
        fail=$((fail + 1))
    fi
}

# check_sm4_ecb NAME KEY_HEX MSG_HEX EXPECTED_HEX —— 无填充单块/整块
check_sm4_ecb() {
    check_sm4_enc "$1" sm4-ecb "$2" "00000000000000000000000000000000" "$3" "$4" nopad
}

# check_sm4_ecb_padded NAME KEY_HEX MSG_HEX EXPECTED_HEX —— PKCS#7 填充
check_sm4_ecb_padded() {
    check_sm4_enc "$1" sm4-ecb "$2" "00000000000000000000000000000000" "$3" "$4" pad
}

# check_sm4_cbc NAME KEY_HEX IV_HEX MSG_HEX EXPECTED_HEX —— 无填充整块
check_sm4_cbc() {
    check_sm4_enc "$1" sm4-cbc "$2" "$3" "$4" "$5" nopad
}

# check_sm4_cbc_padded NAME KEY_HEX IV_HEX MSG_HEX EXPECTED_HEX —— PKCS#7 填充
check_sm4_cbc_padded() {
    check_sm4_enc "$1" sm4-cbc "$2" "$3" "$4" "$5" pad
}

# ---------- SM3：规范附录向量与代表性长度 ----------

# GB/T 32905-2016 附录 A.1
check_sm3 "gb-abc" "616263" \
    "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
# GB/T 32905-2016 附录 A.2
check_sm3 "gb-abcd16" "$(printf '61626364%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)" \
    "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
check_sm3 "empty" "" \
    "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
check_sm3 "len-55" "$(python3 -c "print('61'*55)")" \
    "288337eef51eec62e7544d7270424c8dbe656254c99852870a73b2453a6a7fb1"
check_sm3 "len-56" "$(python3 -c "print('61'*56)")" \
    "ba00ebedaab54065a5fd4f9f56326016203166bcee3eed44ea868d59d67aa3c8"
check_sm3 "len-64" "$(python3 -c "print('61'*64)")" \
    "616ec433c359e7c2b19f360e2b8f2a1b6e9ed76b8dc1a7d207b31a5341c611e9"
check_sm3 "len-128" "$(python3 -c "print('61'*128)")" \
    "5fd947effbe82a5925faaee9123d43cea200cc257b28ed797505694b4bb020f6"

# ---------- SM4：规范附录向量（GB/T 32907-2016 附录 A） ----------

# A.1 第一组：单块加密
check_sm4_ecb "gb-block1" "0123456789ABCDEFFEDCBA9876543210" \
    "0123456789ABCDEFFEDCBA9876543210" \
    "681edf34d206965e86b3e94f536e4246"

# ---------- SM4：PKCS#7 填充下的 ECB/CBC 代表性向量（python-gmssl 计算） ----------

SM4_K="0123456789ABCDEFFEDCBA9876543210"
SM4_IV="000102030405060708090A0B0C0D0E0F"

check_sm4_ecb_padded "pkcs7-msg8" "$SM4_K" "0123456789ABCDEF" \
    "ccd1b5b36941e70a3916d62edc78a969"
check_sm4_ecb_padded "pkcs7-msg32" "$SM4_K" \
    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF" \
    "3c2c71d577fa4fd41bd13a69141a1757ccd1b5b36941e70a3916d62edc78a969"
check_sm4_cbc_padded "pkcs7-msg8" "$SM4_K" "$SM4_IV" "0123456789ABCDEF" \
    "b76b6d80da0337286984c18855d8b52a"
check_sm4_cbc_padded "pkcs7-msg32" "$SM4_K" "$SM4_IV" \
    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF" \
    "8f57b32e3c0b8061cd25a8e2100c345b77b4c389d8b584c0608c76d555bf132d"

# ---------- SM4-CTR：流式模式与计数器进位（NIST SP 800-38A §6.5） ----------

# check_sm4_ctr NAME KEY_HEX IV_HEX MSG_HEX EXPECTED_HEX
check_sm4_ctr() {
    check_sm4_enc "$1" sm4-ctr "$2" "$3" "$4" "$5" pad
}

check_sm4_ctr "stream-32B" "0123456789ABCDEFFEDCBA9876543210" \
    "000102030405060708090A0B0C0D0E0F" \
    "3031323334353637383961626364656630313233343536373839616263646566" \
    "36a9ae5209935e9a12b496e082cc9c0c5f363f787496ca36e2a87287e264c87c"
# IV 末字 0xFFFFFFFF：跨块递增向高位字进位（消息为 (31i+13) mod 256 序列，48 字节）
check_sm4_ctr "counter-carry" "0123456789ABCDEFFEDCBA9876543210" \
    "101112131415161718191A1BFFFFFFFF" \
    "$(python3 -c "print(bytes((i*31+13)%256 for i in range(48)).hex())")" \
    "17a9c20247fbaac5d519499678608546417ff55ad564858803d9e90404487ade6b1b05f91a40f2fa73585239e84edb97"

# ---------- 汇总 ----------

echo "openssl cross-check: passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
