# Metis Reverse — 演示靶机程序体验指南 (Demo Target)

本目录提供了一个通用型 C 语言闭源验证靶机程序（**内存级 Key-Value Cache / 状态管理引擎**），用于测试并体验 **Metis Reverse** 的“真 AI 逆向能力”（高保真符号恢复、结构体逆向反解、动态内存实勘与闭环重编译验证）。

---

## 1. 靶机程序简介

- **源代码**: [`demo/main.c`](file:///Users/huchenrui/metis-revers/demo/main.c) (保留作为验证对照的 Ground Truth)
- **编译产物**:
  - [`demo/demo_target`](file:///Users/huchenrui/metis-revers/demo/demo_target): 使用 `clang -O2 -s` 彻底剥离符号表与调试信息的二进制程序（供逆向分析测试）。
  - [`demo/demo_target_debug`](file:///Users/huchenrui/metis-revers/demo/demo_target_debug): 带完整调试符号版本（供对照参考）。

### 包含的典型通用软件工程要素：
1. **真实工业级复合结构体**:
   - `CacheRecord`: 包含 `record_id`、`key[32]`、`value[64]`、`hash`、`ttl_seconds`、`access_count`、`flags`（位掩码标志）。
   - `CacheStore`: 包含 `magic` (0x4B565354 即 "KVST")、`version`、`capacity`、`active_count`、`total_lookups`、`total_hits` 及静态数组记录。
2. **多源证据链（格式化字符串与日志）**:
   - `"[CACHE_INSERT] id=%u key='%s' val='%s' hash=0x%08X (ttl=%ds, flags=0x%04X)\n"`
   - `"[CACHE_STATS] magic=0x%08X version=%u entries=%u/%u lookups=%u hits=%u misses=%u (hit_ratio=%.2f%%)\n"`
   - `"[CACHE_UPDATE] key='%s' updated val_len=%zu\n"`
   - `"[CACHE_DEL] Evicted record id=%u key='%s'\n"`
3. **防御式断言宏线索（Assert Grounding）**:
   - `assert(capacity > 0 && capacity <= MAX_CACHE_ENTRIES && "invalid_store_capacity")`
   - `assert(key != NULL && "null_key_in_hash")`
   - `assert(store != NULL && "null_store_pointer")`
   - `assert(key_len > 0 && key_len < KEY_BUFFER_SIZE && "key_length_out_of_range")`
4. **经典常用哈希算法**:
   - 32 位 FNV-1a 哈希算法（初值 `2166136261u`，质数 `16777619u`），用于哈希槽位匹配与完整性验证。

---

## 2. 终端手动运行测试

在终端中直接进入当前目录运行：

```bash
cd /Users/huchenrui/metis-revers/demo

# 1. 查看帮助信息
./demo_target --help

# 2. 运行内置基准工作负载测试（涵盖插入、命中查询、未命中、驱逐淘汰与统计比率）
./demo_target --benchmark

# 3. 单独测试写入、查询与统计
./demo_target --set="api.rate_limit=1000" --ttl=60 --get="api.rate_limit" --stats

# 4. 尝试修改只读键（触发保护报错）
./demo_target --set="sys.version=9.9.9"
```

---

## 3. 在 Codex / AI 客户端中体验 Metis Reverse

打开已配置好 Metis Reverse 的 **Codex**（或 Cursor / Claude Code），直接复制并发送以下指令进行实测：

### 🎯 推荐测试 Prompt（直接发给 Codex）：

> 我有一个被完全剥离符号的 C 二进制程序 `/Users/huchenrui/metis-revers/demo/demo_target`。
> 请使用 `metis-reverse` MCP 工具帮我进行真正的 AI 逆向分析：
> 1. 调用 `open_session` 加载该二进制，并用 `list_functions` 和 `get_cfg` 查看其结构。
> 2. 调用 `query_evidence` 提取不可篡改的多源证据链（格式串、断言、系统调用），向我展示你推导出哪些原作者书写的真实变量名、字段与结构体。
> 3. 分析其 FNV-1a 哈希计算与缓存增删查改逻辑，用 `trace_function` 进行局部仿真或插桩分析。
> 4. 重构出与原作者书写高度一致的 C 源代码，并调用 `recompile_and_verify` 验证重编译与黑盒行为等价性。

---

## 4. 预期看到的“真逆向”效果

| 传统逆向 (如 REA / 传统反编译) | Metis Reverse 真 AI 逆向 |
| :--- | :--- |
| 变量名全是 `v1`, `v2`, `a1`，全凭模型猜测 | 从格式串和断言直接精确还原 `record_id`, `key`, `val`, `hash`, `ttl_seconds`, `flags`, `hit_ratio` 等原作者命名 |
| 结构体零散展开，无法还原嵌套结构与字段定义 | 精确还原 `CacheRecord` 与 `CacheStore` 的结构体布局、字段对齐与位标志 |
| 只能生成看似相似但无法通过编译的伪代码 | 输出结构清晰的规范 C 源码，通过构建沙箱自动化 Clang 编译（0 错误） |
| 无法确信还原逻辑是否准确 | 调用差分测试引擎，实测重编译程序与原剥离程序输入输出 100% 行为等价 |
