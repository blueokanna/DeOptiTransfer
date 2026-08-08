# deopti-transfer 中文文档

[English](README.md)

> `no_std` 的 LT 喷泉码核心，用于单向光学数据传输——只用一块屏幕和一个
> 摄像头在两台设备之间传送文件：无网络路径、无配对、无重传。

`deopti-transfer` 是一个 `no_std + alloc` 的喷泉码核心。发送端持续发射
自包含的帧；接收端无需任何确认或重传控制即可重建数据流。**丢帧只增加
时间，绝不损害正确性。**

当前线上协议为 **v3**（帧魔法字 `D1 0F`）。v2 帧被有意拒绝：它没有每帧
完整性标签，损坏的方程可能污染解码器。

---

## 核心亮点

- **因果编织（默认发送模式）**——可逆下双对角矩阵首段：`K` 帧即可
  **恰好用 K 帧**、任意顺序重建载荷；缺失一帧只是把链条切成若干
  **分量**，剥皮解码可廉价恢复；其后是无穷的确定性鲁棒孤子修复尾，
  中途接入的接收端也能完成解码。
- **每帧完整性**——25 字节帧头携带两个 BLAKE3 派生的 32 位标签：
  `frame_tag`（到达即验）、`stream_tag`（重建后再验）。损坏帧被当作
  擦除，永不污染解码器。
- **认证加密（可选）**——容器级 XChaCha20-Poly1305，Argon2id 派生密钥、
  密钥零化；旁路摄像头只能看到密文。
- **极限吞吐**——SIMD XOR 引擎（AVX2/SSE2/NEON/标量运行时派发，
  通过 `core::arch` 支持 no_std）、扁平字竞技场（每帧零堆分配）、两级
  量化度采样、双射乘性哈希去重。参考机器上**解码可达 3.8–6.6 Gbps**。

---

## 协议 v3 —— 帧、标签、身份

每个 QR 帧完全自描述：无握手；接收端可在中途锁定数据流，新的会话 id
直接开启新传输。

**25 字节小端帧头：**

```text
 0  2 字节  magic        D1 0F（协议 v3）
 2  u8      flags        bit0 直接系统性，bit1 因果
 3  u16     session_id   每次发送端启动随机
 5  u32     seq          驱动喷泉/编织
 9  u16     k            源块数量
11  u16     block_len    每帧载荷字节数
13  u32     total_len    容器总长
17  u32     stream_tag   整个容器的 BLAKE3 派生标签
21  u32     frame_tag    本帧头+数据块的 BLAKE3 派生标签
```

帧头由 `rustbinary` 的定宽小端 legacy 配置序列化，字节布局由黄金向量
测试钉死。

**`frame_tag`** = `BLAKE3(flags ‖ session ‖ seq ‖ k ‖ block_len ‖ total_len
‖ stream_tag ‖ block)` 的前 4 字节。`parse_frame` 在帧进入解码器之前
校验：损坏帧作为擦除被拒绝，同一序号稍后可重新接收。

**`stream_tag`** = `BLAKE3(container)` 的前 4 字节（`checksum32`），标识
完整容器并在重建后复验。两者都只能检测意外光学损坏，**不是消息认证码**；
对抗主动篡改请使用 `encryption` 特性。

**流身份**——接收端锁定第一个合法的
`StreamIdentity { flags, session_id, k, block_len, total_len, stream_tag }`。
来自其它流的帧返回 `Error::StreamConflict` 且不丢弃当前进度；调用
`Receiver::reset` 可主动切换数据流。

**上限**——`MAX_FILE_BYTES = 64 MiB`；`MAX_STREAM_BYTES =
64 MiB + 2·0xFFFF + 128`（容器头与元数据余量）。解码器载荷存储上限为
源块竞技场的 4 倍，且容量在去重集合增长前先做检查。

---

## 因果编织构造

默认发送端（`Sender::new`）发射**因果**首段。对源块 `x[0]..x[K-1]`：

```text
y[0] = x[0]
y[i] = x[i-1] XOR x[i]     （1 <= i < K）
```

这是一个**可逆的下双对角编码矩阵**。收到前 `K` 帧——任意顺序——恰好
`K` 帧即可重建载荷。丢失首段的一帧只是把链条切成**分量**，而非留下孤立
缺失块；当后续修复方程解出某一分量的一个成员时，剥皮会沿该分量所有已收
到的边传播。

首段之后，发送端无限发射确定性的鲁棒孤子 LT 修复方程，中途接入的接收端
仍可完成解码。

该构造由黄金向量钉死，并在乱序、孤立断链、确定性丢帧下均有测试。

### 实测回归（K = 139，确定性逐帧丢帧掩码）

解码器接纳帧数相对 K 的倍数：

| 丢帧率 | 因果 | 直接系统性 | 纯 RSD |
| --- | ---: | ---: | ---: |
| 0%  | **1.000 K** | **1.000 K** | 1.317 K |
| 10% | **1.043 K** | 1.403 K | 1.173 K |
| 30% | **1.554 K** | 1.554 K | 1.317 K |

这是确定性回归测量——不是通用信道模型，也不构成学术新颖性声明；由
`systematic_reduces_frames_needed_under_loss` 复现。当实测信道更偏爱某
模式时，应用可显式选择直接系统性或纯 RSD。

---

## 传输模式

| 模式 | `Sender` 构造器 | flags | 首段 |
| --- | --- | --- | --- |
| 因果（默认） | `Sender::new` / `try_new` | `FLAG_CAUSAL` | 双对角编织 |
| 直接系统性 | `Sender::new_systematic` / `try_new_systematic` | `FLAG_SYSTEMATIC` | 源块原样 |
| 纯 RSD | `Sender::new_rsd` / `try_new_rsd` | 0 | 鲁棒孤子 LT |

底层编解码器对应：`LtEncoder::new` / `new_systematic` / `new_causal` 与
`LtDecoder::new` / `new_systematic` / `new_causal`（均含 `try_*` 变体）。
帧头的 flags 字节携带模式，接收端自动适配。

---

## 帧完整性与流隔离

- `Error::CorruptFrame` —— 帧未通过 BLAKE3 标签，或重建容器未通过
  `stream_tag`。该帧作为擦除丢弃，解码器保持完好。
- `Error::StreamConflict` —— 收到其它流身份的帧；当前进度保留，
  `Receiver::reset` 切换流。
- `Error::SequenceExhausted` —— 发送端 `u32` 序号在 `2^32` 帧后回绕。
- `Receiver::try_push` 返回 `Result<Option<Vec<u8>>>`：未完成时
  `Ok(None)`，完成时恰好一次 `Ok(Some(container))`（防止重复交付），
  其余情况返回 `Err`。

---

## 认证加密（防共收）

光学信道是公开广播——**任何对准屏幕的摄像头都能收到相同的帧**。开启
`encryption` 特性后，容器被加密，共收者或中途窥探者只能看到密文。

- **AEAD** —— XChaCha20-Poly1305（RustCrypto，no_std），24 字节 nonce、
  16 字节标签。容器头、文件名、类型与摘要均作为关联数据（AAD）认证：
  任何字段被篡改都会在解密前失败。
- **密钥派生** —— `EncryptionKey::from_password(password, salt)` 用
  **Argon2id**（19 MiB、2 轮）派生 32 字节密钥，并在析构时零化
  （`zeroize`）。24 字节 nonce 兼任 Argon2 盐，nonce 新鲜则密钥新鲜。
- **Nonce** —— `random_nonce()`（std 构建）使用操作系统随机源；no_std
  应用自行提供（如嵌入式 TRNG）。同一密钥下每个加密必须使用唯一 nonce。
- **API** —— `pack_file_encrypted` / `pack_file_encrypted_with_password`；
  `unpack_file_with_key` / `unpack_file_with_password`。无密钥、密钥错误、
  或单个字节被翻转的加密容器都会被拒绝（已测）。

---

## 性能与数据结构

- **SIMD XOR 引擎**（`simd::xor_into`）——运行时派发 AVX2（经 `__cpuid`
  + `_xgetbv` XCR0 状态校验）、SSE2、NEON、标量回退；通过 `core::arch`
  支持 no_std。
- **扁平字竞技场**（`LtDecoder`）——所有帧字存于单个 `Vec<u32>`，按索引
  切分；索引在扩容下稳定，**每帧零堆分配**；不相交区间经 `split_at_mut`
  做 XOR。
- **两级量化度采样**（`DegreeCdf`）——1024 项分位数表把逆 CDF 搜索收敛
  到缓存友好的小窗口；结果与二分搜索**完全相等**（对每个 K 在 2^20 网格
  加 10 万随机采样上证明）。
- **双射乘性哈希去重**（`U32Set`）——开放寻址，`v·0x9E3779B1 mod 2^t`
  对低位是双射，因此**连续序号永不冲突**；位打包占用表；0.7 负载摊销
  扩容。

### 基准测试

`criterion 0.8`，100 样本，3 秒预热，`-O3` + `lto`；硬件
**Intel Core i7-11850H @ 2.50 GHz，32 GB**。`BLOCK_LEN = 2933`。可用
`cargo bench` 复现。

| 组 | 用例 | 中位时间 | 吞吐 |
| --- | --- | --- | --- |
| xor | 派发（AVX2） | 203.7 µs | 19.18 GiB/s |
| xor | 标量参照 | 193.7 µs | 20.16 GiB/s |
| degree_sample | 量化，K=357 | 10.46 µs | — |
| degree_sample | 二分，K=357 | 29.73 µs | — |
| degree_sample | 量化，K=11440 | 10.62 µs | — |
| degree_sample | 二分，K=11440 | 49.87 µs | — |
| dedup | u32_set_insert × 65536 | 292.9 µs | 约 2.24 亿次/秒 |
| encode | 流式，1 MiB | 3.718 ms | 364.9 MiB/s |
| encode | 流式，8 MiB | 56.92 ms | 187.8 MiB/s |
| encode | 流式，32 MiB | 314.9 ms | 135.6 MiB/s |
| decode | 剥皮，1 MiB | 1.212 ms | 825.1 MiB/s |
| decode | 剥皮，8 MiB | 11.76 ms | 680.2 MiB/s |
| decode | 剥皮，32 MiB | 65.89 ms | 485.7 MiB/s |

按比特计（×8）：**解码 3.9–6.6 Gbps**、编码 1.1–2.9 Gbps——每个测量尺寸
都高于 1 Gbps。编码随负载增大而降速，是因为从数 MB 的块表中随机取块受
**内存延迟**约束（而非计算）；解码同表缓存较暖。消耗这些帧的光学信道本身
只有约 0.1–0.2 MB/s——比编解码器慢三个数量级，编解码器永远不是信道瓶颈。

---

## API 参考

| 模块 | 公共接口 |
| --- | --- |
| `frame` | `FrameHeader`、`StreamIdentity`、`pack_frame`、`parse_frame`、`stream_identity`、`checksum32`、`frame_checksum`、`fnv1a`、`HEADER_LEN`、`MAGIC0/1`、`FLAG_SYSTEMATIC`、`FLAG_CAUSAL`、`MAX_FILE_BYTES`、`MAX_STREAM_BYTES` |
| `fountain` | `LtEncoder`（`new`/`new_systematic`/`new_causal` + `try_*`、`encode`、`encode_into`、`k`、`block_len`、`session_id`、`is_causal`、`is_systematic`、`sys_span`）、`LtDecoder`（`new`/`new_systematic`/`new_causal` + `try_*`、`add_frame`、`assemble`、`is_complete`、`frames_new/dup/dropped`、`solved_count`）、`frame_indices` |
| `session` | `Sender`（`new`/`new_systematic`/`new_rsd` + `try_*`、`from_packed`/`try_from_packed`、`try_next_frame`、`next_frame`、`k`、`session_id`、`is_causal`、`is_systematic`）、`Frame`（`to_bytes`）、`Receiver`（`new`、`reset`、`try_push`、`push`、`is_active`） |
| `container` | `pack_file`、`pack_file_encrypted`、`pack_file_encrypted_with_password`、`unpack_file`、`unpack_file_with_key`、`unpack_file_with_password`、`verify_file`、`safe_file_name`、`is_precompressed_type`、`Compression`、`PackedOpticalFile`、`OpticalFile`、`FILE_HEADER_LEN` |
| `crypto` *（encryption）* | `EncryptionKey`（`new`、`from_password`）、`random_nonce`、`encrypt`、`decrypt`、`NONCE_LEN`、`TAG_LEN` |
| `capacity` | `block_length`、`source_block_count`、`fits_in_one_stream`、`minimum_frame_bytes`、`smallest_sufficient_frame_size`、`MAX_SOURCE_BLOCKS` |
| `soliton` | `soliton_cdf`、`DegreeCdf`、`degree_binary`、`SOLITON_C`、`SOLITON_DELTA` |
| `prng` | `SplitMix32`、`frame_seed` |
| `set` | `U32Set` |
| `simd` | `xor_into` |
| `dlog` | `dlog` |
| `error` | `Error`、`Result` |

---

## 快速开始

```toml
[dependencies]
deopti-transfer = { version = "0.1", features = ["encryption"] }
```

### 明文传输

```rust
use deopti_transfer::container::{pack_file, unpack_file};
use deopti_transfer::session::{Receiver, Sender};

let packed = pack_file("notes.txt", "text/plain", b"hello over light")?;

let mut sender = Sender::try_from_packed(&packed, 1465, 0x0c_d1)?; // 因果模式
let mut receiver = Receiver::new();
let mut recovered = None;
for _ in 0..sender.k() as usize * 4 {
    let frame = sender.try_next_frame()?;
    if let Some(container) = receiver.try_push(&frame.to_bytes())? {
        recovered = Some(container);
        break;
    }
}
let file = unpack_file(&recovered.expect("stream completed"))?;
assert_eq!(file.bytes, b"hello over light");
```

### 加密传输（防共收）

```rust
use deopti_transfer::container::unpack_file_with_password;
use deopti_transfer::crypto::random_nonce;

let nonce = random_nonce()?;
let packed = deopti_transfer::pack_file_encrypted_with_password(
    "secret.txt", "text/plain", b"top secret", b"correct horse battery staple", &nonce,
)?;
let file = unpack_file_with_password(&packed.container, b"correct horse battery staple")?;
assert_eq!(file.bytes, b"top secret");
```

对于有损或乱序信道，持续推送帧即可——解码器在收到足够的不同帧后自然完成。

---

## no_std、特性、依赖

```bash
# 纯 no_std + alloc 构建（无 gzip、无加密）
cargo build --release --no-default-features

# 开启加密（Argon2id + XChaCha20-Poly1305，均为 no_std）
cargo build --release --no-default-features --features encryption
```

| 特性 | 引入 | 作用 |
| --- | --- | --- |
| `std`（默认） | `flate2` | 容器 gzip 压缩 |
| `encryption` | `argon2`、`chacha20poly1305`、`getrandom`、`zeroize` | 容器认证加密 |

运行时依赖全部支持 no_std：`rustbinary`（二进制编解码）、`serde`
（derive）、`blake3`（哈希）、`libm`（no_std 浮点），以及可选的
`flate2` / `argon2` / `chacha20poly1305` / `getrandom` / `zeroize`。

---

## 正确性与安全

- **黄金向量**（`tests/golden.rs`）钉死线上格式：帧头字节、RSD 与系统性/
  因果编码流、`dlog` 的穷举 FNV-1a 指纹，以及量化采样等价性证明。
- **往返测试**（`tests/roundtrip.rs`）覆盖：有损与乱序下的喷泉、因果编织
  的乱序与孤立断链、加密容器（错误密钥、篡改、缺密钥）、以及构造的头部
  放大攻击。
- 来自光学信道的每个字段在使用前都被校验；唯一的 `unsafe` 是有界检查的
  `u32 ↔ u8` 重解释与 SIMD 内核。
- `#![forbid(unsafe_op_in_unsafe_fn)]`，`cargo clippy --all-features
  --all-targets` 零警告，所有特性组合均能 `--release` 构建。

---

## 许可证

Apache-2.0。见 [LICENSE](LICENSE)。