# Metis-Reverse: Evidence-Grounded Agentic Reverse Engineering Platform

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](pyproject.toml)
[![MCP](https://img.shields.io/badge/MCP-2024--11--05-brightgreen)](https://modelcontextprotocol.io/)

专为 AI Agent（如 Antigravity、Claude Code、Cursor）深度推理设计的现代化逆向工程 Model Context Protocol (MCP) 服务端与推理闭环系统。

---

## 核心设计理念 (Core Principles)

1. **会话稳、可复现、可迁移 (Session Stability & Decoupled Portability)**
   * 采用 Headless 架构与只读样本挂载，原生支持多样本并发。
   * 采用**独立侧车文件（Sidecar YAML/JSON-L）**持久化所有符号、类型与推导记录，脱离特定 Ghidra 工程数据库，支持跨版本免数据库差分毫秒级重放。
2. **每个结论都带证据 (Evidence Grounding & Zero Hallucination)**
   * 所有算法、数据结构、解密密钥均绑定明确的虚拟地址（VA/RVA）与原始十六进制凭证。
   * 查不到时返回严格的排查审计报告（`not_found` + `searched_locations`），坚决阻止模型幻觉。
3. **输出为推理设计 (Reasoning-Optimized Output)**
   * Token-bounded 块切片、调用拓扑拓扑内联、关联字符串与常量内联，避免单次返回巨量上下文击穿模型注意力。
4. **假设验证闭环 (Dual-Layer Hypothesis Verification)**
   * 内置受限 Python 算法验证沙箱（`re_verify_hypothesis`），让 Agent 自行验证解密脚本或 API 哈希还原，严禁脑内计算位运算。
   * 支持起始/断点微仿真（`re_emulate_slice`），抓取真实寄存器与内存快照。
5. **任务级能力，拒绝 200 个原子 API 膨胀 (Task-Level Tool Abstraction)**
   * 摒弃臃肿复杂的 200+ 细粒度接口，精炼为 **9 个高内聚任务级 API**。
6. **二进制内容视为不可信数据 (Prompt Injection Defense)**
   * 内置 `PromptShield` 深度防护体系，检测并阻断二进制符号中内嵌的对抗性提示词注入载荷，提取内容均置于 `<untrusted_binary_evidence>` 安全围栏中。
7. **理解逆向分析工具语义 (Domain Semantics Awareness)**
   * 准确翻译 YARA、DIE 等外置逆向工具的特殊退出码（如非零返回代表“命中特征”而非执行失败）。

---

## 9 大任务级 MCP 工具矩阵 (Tools Matrix)

| 工具名称 | 核心职责 | 典型调用场景 |
| :--- | :--- | :--- |
| `re_session_manager` | 会话与快照管理 | 样本只读挂载、会话隔离、侧车标注导出与重放导入 |
| `re_triage` | 初筛与格式画像 | PE/ELF/Mach-O 检测、全节区熵值热力图、YARA 语义解析 |
| `re_query_function` | 推理友好型反编译 | 绑定地址代码片段、Caller/Callee 拓扑、关联常量内联、防注入安全围栏 |
| `re_hunt_crypto_and_hashes` | 密码学与 API 哈希搜寻 | AES S-Box 扫描、SHA/MD5/ChaCha 常量识别、Windows API 哈希解析 |
| `re_verify_hypothesis` | 算法假设自验沙箱 | 在隔离 Python 环境中运行 Agent 解密脚本，测试真实内存切片 |
| `re_emulate_slice` | 受控局部微仿真 | 从起始地址模拟至断点，抓取真实寄存器状态与内存缓冲区 |
| `re_refine_model` | 知识固化与类型沉淀 | 重命名函数/局部变量、定义结构体字段、写入侧车文件 |
| `re_diff_and_transfer` | 跨版本标注迁移 | 基于 CFG 哈希与常量指纹匹配新老版本样本，自动化迁移标注 |
| `re_query_evidence` | 证据链全链路溯源 | 追查符号/算法推导来源；未命中时输出审计清单拒绝幻觉 |

---

## 快速安装与配置 (Installation)

### 1. 安装 Python 依赖
```bash
git clone https://github.com/metis-reverse/metis-reverse.git
cd metis-reverse

python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 2. 配置 MCP 客户端 (例如 Claude Desktop 或 Antigravity)

在 MCP 配置文件（如 `claude_desktop_config.json` 或 Antigravity MCP 配置）中添加：

```json
{
  "mcpServers": {
    "metis-reverse": {
      "command": "/Users/huchenrui/metis-revers/.venv/bin/python",
      "args": ["-m", "metis_reverse.server"],
      "env": {
        "GHIDRA_INSTALL_DIR": "/path/to/ghidra_11.x_PUBLIC",
        "METIS_SIDECAR_DIR": "/path/to/your/project/.metis_sidecars"
      }
    }
  }
}
```

*注：如果系统暂未安装 Ghidra，Metis-Reverse 会自动启动高保真 Mock/Fallback 引擎，确保全套沙箱验证、Sidecar 存储与证据追踪功能正常运行。*

---

## 配套逆向专家 Skill

项目在 [`skills/metis-reverse/SKILL.md`](skills/metis-reverse/SKILL.md) 中提供了工业级逆向 Agent 认知飞轮指令，可直接供 Claude Code 或 Antigravity 挂载使用，驱动智能体按照“初筛 -> 假设 -> 沙箱自验 -> 仿真比对 -> 侧车沉淀 -> 证据闭环”的标准工程流程自主逆向。

---

## 架构升级：全语言与工件树 (Polyglot & Artifact Tree Architecture)

系统全面支持现代复合应用（如 Bun 单文件、Electron ASAR、PyInstaller、.NET 单文件与混合编译工程）：
* **层次化工件树（Artifact Tree）：** 自动解析复合容器、支持按需懒激活、游标分页检索（R2）与任意节点三元坐标换算（`{va, rva, file_offset}`）。
* **多语言混合检测与桥接分析（Polyglot & Bridge）：** 自动识别 C/C++、Go、Rust、Swift、.NET、Python、Node.js，打通 N-API、JNI、IPC、FFI 跨层调用链路。
* **三大逃生通道（Escape Hatches）：**
  1. **自定义解析脚本探针（`execute_probe_script`）：** 在只读沙箱内由 Agent 编写并执行 Python 探针，支持动态提取并挂载子工件。
  2. **非标字符串与物理切片提取（`re_deep_static`）：** 支持任意物理切片指定、C-string、UTF-16 与非 `\0` 结尾的 Go/Rust/Swift 内存切片。
  3. **启发式跨层断链链接（`re_bridge_map`）：** 在缺乏符号或发生去符号化时，通过启发式签名匹配关联高级语言调用与底层 Native 导出。

详细安全合规底线与仿真边界请查阅 [合规边界与已知限制文档](docs/known-limits.md)。

---

## 运行单元测试

```bash
pytest tests -v
```

测试集涵盖：
* 提示词对抗注入拦截与无害化封装（`test_prompt_shield.py`）
* 假设验证沙箱与恶意代码阻断（`test_sandbox.py`）
* 侧车标注持久化与跨补丁版本自动迁移（`test_sidecar_store.py`）
* 证据溯源与严格否定排查审计（`test_evidence_service.py`）
* 9 个任务级 MCP 工具全流程端到端集成测试（`test_mcp_tools.py`）

---

## License

Apache-2.0 License.
