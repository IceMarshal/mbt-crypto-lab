# crypto-lab

国密 SM3 密码杂凑算法与 SM4 分组密码算法的 MoonBit 语言实现。

## 规范依据

- SM3：GB/T 32905-2016《信息安全技术 SM3密码杂凑算法》
- SM4：GB/T 32907-2016《信息安全技术 SM4分组密码算法》
- 分组工作模式 ECB、CBC 及 PKCS#7 填充：RFC 5652 §6.3

## 构建与测试

```sh
moon check     # 类型检查
moon test      # 运行全部测试
moon fmt       # 格式化
```

本模块不依赖第三方包。

## 包结构

| 包 | 内容 |
|---|---|
| `src/util` | 大端字序转换、循环左移、十六进制编解码 |
| `src/sm3` | SM3 杂凑算法（开发中） |
| `src/sm4` | SM4 分组密码算法（开发中） |

## 验证

正确性验证采用三个相互独立的期望值来源：规范附录 A 的标准向量、
python-gmssl 库生成的确定性随机向量（`tests/gen_vectors.py`）、
以及 OpenSSL 命令行工具对拍（`tests/verify_openssl.sh`）。
