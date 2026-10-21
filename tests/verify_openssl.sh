#!/bin/sh
# OpenSSL 命令行工具对拍：SM3 摘要。
#
# 期望值与 tests/gen_vectors.py 生成的金标准同源（python-gmssl）。
# 本脚本以 OpenSSL 独立重算并逐字节比对，确认三个实现来源一致：
# 规范附录向量（见各包 *_test.mbt）、python-gmssl、OpenSSL。
#
# 用法：sh tests/verify_openssl.sh
# 依赖：openssl 3.x（支持 sm3 摘要），python3（仅作十六进制解码）

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

# ---------- 汇总 ----------

echo "openssl cross-check: passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
