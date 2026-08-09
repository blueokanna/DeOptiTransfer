# deopti-transfer 中文文档

`deopti-transfer` 是面向单向传输信道（例如屏幕到摄像头）的 Rust
`no_std + alloc` LT 喷泉码核心。它提供二进制传输协议、有界剥离解码器、
文件容器、可选认证加密，以及指定裁决者恢复构造；它不负责生成二维码，也
不控制摄像头。

当前格式版本：

- 帧协议：v3，魔数 `D1 0F`；
- 文件容器：DCF3，魔数 `DCF3`；
- 裁决者可恢复承诺：JRC1；
- 裁决者可恢复证明组合：JRP2。

实现以生产环境为目标，但尚未经过独立安全审计。JRC/JRP 的命名以及“因果
首段”不能直接作为学术原创性的证据。托管承诺、可提取承诺、指定验证者系统
等方向与其密切相关；任何论文级创新声明都必须先完成系统的现有技术检索。

[English README](README.md)

## 已实现能力

- 三种 LT 模式：因果首段加修复尾流（默认）、直接系统码加修复尾流、纯
  鲁棒孤子编码。
- 确定性线格式与黄金向量。
- AVX2、SSE2、NEON、标量 XOR 路径，并在需要的平台运行时分派。
- 逐帧损坏过滤、流身份锁定、重复帧抑制和重建后整流校验。
- DCF3 文件元数据、有界 gzip 解压、文件名/MIME 校验和 BLAKE3 文件摘要。
- 可选 XChaCha20-Poly1305 加密与 Argon2id 口令派生。
- 可选的基于 X25519 的 JRC 指定裁决者恢复。
- 由应用提供关系证明后端的 JRP 组合；没有用公开哈希冒充“证明”，也没有
  内置通用 SNARK/STARK。
- 可配置接收上限与解码器硬存储预算。

## 安装与特性

```toml
[dependencies]
deopti_transfer = "0.1.2"
```

| 特性 | 默认 | 作用 |
| --- | --- | --- |
| `std` | 是 | 通过 `flate2` 压缩/解压 gzip |
| `encryption` | 否 | Argon2id、XChaCha20-Poly1305、系统随机数、X25519 JRC/JRP、密钥清零 |

```bash
cargo build --release
cargo build --release --no-default-features
cargo build --release --no-default-features --features encryption
```

最后一种配置仍是 `no_std + alloc`；目标平台仍需提供 `getrandom` 所需的随机
源，或者在支持的位置由应用传入外部生成的秘密密钥字节。

## 完整传输流程

```rust
use deopti_transfer::container::{pack_file, unpack_file};
use deopti_transfer::session::{Receiver, Sender};

let packed = pack_file("notes.txt", "text/plain", b"hello over light")?;
let mut sender = Sender::try_from_packed(&packed, 1465, 0x0cd1)?;
let mut receiver = Receiver::new();
let mut recovered = None;

for _ in 0..usize::from(sender.k()) * 4 {
    let frame = sender.try_next_frame()?;
    if let Some(container) = receiver.try_push(&frame.to_bytes())? {
        recovered = Some(container);
        break;
    }
}

let container = recovered.ok_or(deopti_transfer::Error::InvalidStream)?;
let file = unpack_file(&container)?;
assert_eq!(file.bytes, b"hello over light");
# Ok::<(), deopti_transfer::Error>(())
```

循环上限只是应用超时策略，不是解码保证。在有丢帧时，应继续产生新的序列号，
直到完成、策略超时，或返回 `Error::SequenceExhausted`。

## v3 帧协议

每帧长度为 `25 + block_len` 字节，并且自描述：

| 偏移 | 长度 | 字段 | 含义 |
| ---: | ---: | --- | --- |
| 0 | 2 | 魔数 | `D1 0F` |
| 2 | 1 | 标志 | `0` 纯 RSD，`1` 直接系统码，`2` 因果模式 |
| 3 | 2 | 会话 ID | 小端、发送方选择的标识符 |
| 5 | 4 | 序列号 | 方程选择器 |
| 9 | 2 | `K` | 源块数量 |
| 11 | 2 | 块长 | 每帧负载字节数 |
| 13 | 4 | 总长度 | 重建数据流字节数 |
| 17 | 4 | 流标签 | BLAKE3(stream) 的前 32 位 |
| 21 | 4 | 帧标签 | BLAKE3(各头字段, block) 的前 32 位 |
| 25 | 可变 | 块 | LT 方程负载 |

`parse_frame` 在方程进入解码器之前校验魔数、标志、长度和帧标签。
`Receiver` 锁定完整的恒定流身份
`(flags, session_id, K, block_len, total_len, stream_tag)`。

这些标签是截断的无密钥哈希。它们适合检测偶然损坏；在理想随机碰撞模型下，
每次检查的碰撞概率为 `2^-32`。它们不能认证发送者，主动攻击者可以重新计算
两个标签。需要负载认证时使用加密容器；需要发送者身份时还必须在应用层签名。

## 喷泉码构造

将长度为 `L` 的数据流分为 `K = ceil(L / B)` 个 `B` 字节源块
`x_0,...,x_{K-1}`，只在内部为最后一块补零。

### 因果首段

前 `K` 个方程为：

```text
y_0 = x_0
y_i = x_(i-1) XOR x_i,  1 <= i < K.
```

在 `GF(2)` 上有 `y = A x`，其中 `A` 是主对角线和次对角线均为 1 的
下双对角矩阵。因为 `A` 是三角矩阵，

```text
det(A) = product_i A[i,i] = 1,
```

所以对所有 `K >= 1`，`A` 都可逆。逆变换可显式写成：

```text
x_i = y_0 XOR y_1 XOR ... XOR y_i.
```

因此，只要前段全部 `K` 个不同帧都收到，无论到达顺序如何，都恰好用 `K`
帧重建。该定理只针对完整收到这 `K` 个方程；若缺少任意一个，已收到子矩阵
不保证可逆，必须依赖修复帧。

### 鲁棒孤子修复尾流

当 `seq >= K` 时，收发双方通过 `SplitMix32(session_id, seq)` 推导相同的
度数与源块子集。设 `c = 0.1`、`delta = 0.5`：

```text
R = max(1, c * ln(K / delta) * sqrt(K)),
s = min(K, ceil(K / R)),
rho(1) = 1/K,
rho(d) = 1/(d(d-1))                       当 d >= 2，
tau(d) = R/(dK)                           当 d < s，
tau(s) = R * max(0, ln(R/delta)) / K，
mu(d) = (rho(d) + tau(d)) / sum_j(rho(j) + tau(j)).
```

编码器 XOR 被选中的不同源块，解码器执行标准的一度剥离。

鲁棒孤子分析只在其采样模型下给出概率性能；它不保证任意有限帧集合都可解，
也不能推出通用的 `1.15K` 上限。测试中的确定性丢帧场景属于回归检查，不是
对所有信道的数学证明。

### 模式

| 构造函数 | 前 `K` 帧 | 尾流 |
| --- | --- | --- |
| `Sender::try_new` | 因果变换 | 鲁棒孤子 |
| `Sender::try_new_systematic` | 直接源块 | 鲁棒孤子 |
| `Sender::try_new_rsd` | 立即使用鲁棒孤子 | 鲁棒孤子 |

## 解码资源模型

线格式字段必须按敌意输入处理。`LtDecoder` 分配前要求：

- `K > 0`、`block_len > 0`、`total_len > 0`；
- `K = ceil(total_len / block_len)`；
- `K <= 65,535` 且 `total_len <= MAX_STREAM_BYTES`。

方程数据区最多保存四个源流等价大小；待处理邻接项累计最多 `64 * K`。超过
预算的帧计入 `frames_dropped()`，且不会写入重复帧集合，从而阻止构造高阶
方程导致元数据无界增长。

应用还应在接收第一帧前设置部署相关上限：

```rust
use deopti_transfer::{Receiver, ReceiverLimits};

let receiver = Receiver::with_limits(ReceiverLimits {
    max_stream_bytes: 8 * 1024 * 1024,
    max_source_blocks: 8192,
    max_block_len: 4096,
});
assert_eq!(receiver.limits().max_stream_bytes, 8 * 1024 * 1024);
```

## DCF3 文件容器

DCF3 由固定 73 字节头、清理后的文件名、校验后的 MIME 和传输数据组成。头中
含有标志、元数据长度、原始长度、传输长度、BLAKE3 摘要和 24 字节 nonce。

- 原文件最大 64 MiB。
- gzip 只在启用 `std`、媒体不是已压缩类型、文件至少 768 字节且至少节省
  64 字节时使用。
- 解压输出严格限制为声明的原长度，并校验 gzip `ISIZE`。
- 接收文件名会移除路径分量、控制字符、双向文本控制符、Windows 非法字符、
  尾随点/空格及保留设备名歧义。
- MIME 必须具有合法 ASCII `type/subtype`，不得含控制或非 ASCII 字节。
- 文件摘要用于损坏检测，不是签名或 MAC。

## 认证加密

启用 `encryption` 后，可使用 32 字节 `EncryptionKey` 或口令 API。DCF3 先
压缩文件数据，再用 XChaCha20-Poly1305 加密；标志、长度、摘要、文件名和
MIME 都作为关联数据，任何修改都会被拒绝。

```rust
use deopti_transfer::container::{
    pack_file_encrypted_with_password, unpack_file_with_password,
};
use deopti_transfer::crypto::random_nonce;

let nonce = random_nonce()?;
let packed = pack_file_encrypted_with_password(
    "secret.txt",
    "text/plain",
    b"classified",
    b"correct horse battery staple",
    &nonce,
)?;
let file = unpack_file_with_password(
    &packed.container,
    b"correct horse battery staple",
)?;
assert_eq!(file.bytes, b"classified");
# Ok::<(), deopti_transfer::Error>(())
```

口令派生参数为 Argon2id v1.3、19 MiB、两次迭代、单 lane、32 字节输出。
24 字节 nonce 同时作为口令盐。对同一个直接密钥复用 nonce，或在相同口令
模式下复用 nonce，都是不安全的；每个加密容器都应随机生成。普通加密 DCF3
的文件名、MIME、长度和摘要仍然公开。

## JRC：指定裁决者恢复

JRC 将整个内部 DCF3（包括元数据）对外部接收者隐藏，同时允许一个裁决者
密钥恢复：

```text
(dk, ek)      = X25519 裁决者密钥对
(e_sk, e_pk)  = 新生成的临时 X25519 密钥对
shared        = X25519(e_sk, ek)
k_enc         = BLAKE3 derive_key("deopti-transfer jrc enc v1", context)
k_com         = BLAKE3 derive_key("deopti-transfer jrc com v1", context)
c             = BLAKE3 keyed_hash(k_com, message)
ct            = XChaCha20-Poly1305(k_enc, nonce, message, aad = c)
aux           = e_pk || nonce || ct
```

其中 `context = shared || e_pk || ek || nonce`。线格式为
`"JRC\x01" || c || aux`，固定开销 108 字节。创建与恢复都会拒绝非贡献型
X25519 输入。

```rust
use deopti_transfer::crypto::random_nonce;
use deopti_transfer::{keygen, pack_file_jrc, unpack_file_jrc};

let judge = keygen()?;
let nonce = random_nonce()?;
let packed = pack_file_jrc(
    "report.pdf",
    "application/pdf",
    b"document bytes",
    &judge.ek,
    &nonce,
)?;

// 将 packed.envelope 交给 Sender/Receiver 传输。
let file = unpack_file_jrc(&packed.envelope, &judge.dk)?;
assert_eq!(file.bytes, b"document bytes");
# Ok::<(), deopti_transfer::Error>(())
```

### 条件化安全陈述

以下结论依赖：随机预言机模型中的 X25519 hashed Diffie-Hellman、域分离
BLAKE3 KDF/PRF 安全性、256 位密钥化承诺的多密钥碰撞抗性，以及
XChaCha20-Poly1305 AEAD 安全性：

1. 正确性：诚实的 X25519 双方得到相同共享秘密；AEAD 解密逆转加密，重算
   承诺一致。
2. 外部隐藏：对等长消息，先把 hashed-DH 密钥替换为随机密钥，再分别应用
   AEAD 机密性与密钥化 PRF 安全性。
3. 计算绑定：同一 `c` 的两个可接受 opening 若恢复出不同消息，将直接导出
   攻击者影响的密钥化承诺实例之间的碰撞。仅有 PRF 安全性不足以推出此结论，
   这里明确假设多密钥碰撞抗性。
4. 裁决者专属机密性：没有 `dk` 时，等长挑战消息计算不可区分；这并不阻止
   攻击者利用外部信息猜测低熵消息。

JRC 会泄露封套长度，不认证承诺创建者，长期裁决者密钥泄露后也不具备历史
前向保密。`dk` 应与光学收发设备隔离保存，并按敏感 32 字节密钥备份。

## JRP：关系证明组合

JRP2 不把哈希标签冒充证明。它要求应用实现 `RelationProofSystem`，并以零知识
证明知道 `(witness, output, JRC opening)`，满足：

```text
JRC.Commit(ek, output; opening) = 公开承诺
R(statement, witness) = true
output = f(statement, witness).
```

`jrp::prove` 生成 JRC 承诺，要求后端证明精确关系，自校验后输出
`"JRP\x02" || proof_len || relation_proof || JRC-envelope`。
`jrp::verify_ext` 针对语句、裁决者公钥和完整 JRC 转写调用后端；
`jrp::judge_recover` 先验证，接受后才解密。

本库不内置通用 ZK 后端。这是刻意的生产边界：实际选择必须明确电路、验证
密钥生命周期、可信设置策略、大小预算和安全级别。JRP 的完备性、可靠性与
零知识完全继承所选后端；只实现公开输入哈希违反 trait 契约。

## 性能

热路径使用字数组、确定性度数表、开放寻址序列去重和 SIMD XOR。本项目不
声明固定吞吐数字，因为结果取决于 CPU、编译器、块长、负载大小和模式。

```bash
cargo bench
```

Criterion 解码基准会先确认预生成帧集合确实完成重建，不会把未完成解码当作
成功吞吐量。

## 验证命令

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo test --all-features
cargo check --no-default-features
cargo check --no-default-features --features encryption
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo package --allow-dirty
```

测试覆盖线格式黄金向量、确定性对数/CDF 指纹、三种传输模式、丢帧与重复帧、
畸形容器、解压上限、元数据校验、接收分配策略、SIMD 等价性与长度安全、
AEAD/JRC 篡改、非贡献型 X25519 密钥、JRP 关系/篡改行为以及 `no_std` 编译。

测试只能确认已测输入上的实现行为，不能证明密码学假设、通用喷泉码开销、
学术原创性或所有目标平台的侧信道安全。

## 运行限制

- 本库不包含二维码/条码渲染、摄像头管线、界面或设备发现。
- 喷泉解码处理擦除和已校验方程，不是拜占庭纠错码。
- 第一条外观合法的帧可以锁定接收器并造成拒绝服务；应使用超时、`reset`、
  接收上限，并在必要时认证发送者。
- 会话 ID 和完整性标签都是短协议字段，不是安全身份。
- 发送序列空间是有限的 `u32`；检查型 API 会报告耗尽。
- 修改线格式必须发布新版本并更新黄金向量。

## 许可证

Apache-2.0，见 [LICENSE](LICENSE)。
