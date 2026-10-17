# Original User Request

## Initial Request — 2026-10-16T05:57:19Z

开发 **Metis Reverse** —— 一个具备真正 AI 逆向能力的 MCP 服务器（Python FastMCP）。核心目标是赋能 Agent 获得“开发者级原始源码高保真重构能力”，彻底颠覆 REA 等工具“粗糙伪代码+大模型盲猜”模式。通过多源证据链（格式串反解/断言/系统调用/语言元数据）、动态内存探查（Frida/模拟器）及交互式反编译数据库更新，实现符号/变量名的确定性还原，并以“重构源码可重新编译且黑盒动态测试 100% 行为等价”作为严格闭环标准。

Working directory: /Users/huchenrui/metis-revers
Integrity mode: development
Requested team: 全功能智能体团队 (Full Team)

## Requirements

### R1. 统一逆向抽象与分级后端架构 (Tiered Backends & FastMCP Server)
基于 Python FastMCP 构建跨平台的逆向分析 MCP 服务器，对原生二进制（PE/ELF/Mach-O）、脚本/Web代码（JS/WASM）及移动端字节码提供统一分析抽象与会话管理：
- **Tier 1 (内置轻量级引擎)**：集成 Angr / LIEF / Capstone / Unicorn / Tree-sitter / Frida，开箱即用，提供基础二进制解析、反汇编、控制流分析与动态插桩。
- **Tier 2 (专业反编译器增强)**：自动探测系统中已安装的 Ghidra Headless、IDA Pro 或 JADX，无缝接管高层反编译与持久化数据库操作。

### R2. 多源证据链驱动的确定性符号恢复引擎 (Multi-Evidence Grounding Engine)
杜绝无依据猜测，建立严格基于事实证据的变量名与类型推导机制：
- **格式化字符串与日志反解**：深入分析字符串常量引用（如 printf/spdlog/fmt 及 assert 宏），反向解析出原作者书写的变量名、参数名及诊断标识。
- **系统调用与标准库语义传播**：基于已知 API/POSIX/Kernel 强类型签名，顺向与逆向传播变量类型与语义命名。
- **语言元数据与符号表深度挖掘**：自动提取 Go pclntab/symtab、C++ RTTI/VTable、ObjC/Swift 类元数据、DEX 符号表及 JS 作用域图。
- **不可篡改证据标记 (Evidence Tagging)**：向 Agent 暴露的每个符号均附带确定性证据来源与置信度，严禁无事实支撑的自由捏造。

### R3. 动态观测与内存探查工具集 (Dynamic Tracing & Memory Probing)
通过集成本地动态插桩（Frida）或轻量级模拟执行（Unicorn/Qiling），为 Agent 提供运行时真实环境探查能力：
- 支持函数级动态挂钩与断点探查，捕获运行时入参值、返回值、堆栈内存缓冲及解密后的明文字符串。
- 将动态观测到的事实回填至静态反编译上下文，提供最强确凿证据。

### R4. 交互式反编译数据库修改与等价性闭环 (Interactive DB Mutation & Equivalence Loop)
- **双向修改工具**：提供 MCP 工具允许 Agent 针对反编译数据库进行增量修正（重命名符号、调整结构体字段、重定义类型），并触发底层引擎的级联数据流更新。
- **构建与差分等价性校验**：提供目标源码构建与黑盒测试执行工具，对比重构源码生成程序与原二进制在多组测试输入下的 stdout/stderr/exit code 行为一致性。

## Verification Resources

开发团队需在 `tests/synthetic_benchmarks/` 下建立合成靶标验证套件：
1. **C 语言典型测试目标**：包含日志输出、结构体操作、字符串解析的 C 程序，使用 `gcc -O2 -s` 或 `clang -O2` 彻底剥离符号。
2. **Go 语言测试目标**：包含复杂包调用与 goroutine 的 Go 编译二进制（`-ldflags="-s -w"`）。
3. **混淆前端代码目标**：经过 Terser/Uglify 变量名混淆并剥离 SourceMap 的 JavaScript 代码。
每个目标均保留未剥离的原始源码与输入输出测试样例集作为 Ground Truth。

## Acceptance Criteria

### Functional Tools Verification
- [ ] FastMCP 服务器成功启动并通过 stdio/SSE 暴露完整的逆向分析工具集。
- [ ] Tier 1 内置引擎（LIEF/Capstone/Frida等）在无外部重型反编译器环境下能独立完成基础二进制反汇编、字符串提取与动态内存探查。
- [ ] 提供完整的交互式修改工具（`rename_symbol`, `update_variable_type`, `define_struct` 等），支持修改持久化。

### Evidence-Based Fidelity & De-anonymization
- [ ] 对合成靶标二进制中存在格式化字符串、assert 宏或标准库调用的变量，符号恢复引擎给出的命名与原始源码匹配率达到 100%（证据确凿项零幻觉）。
- [ ] 所有暴露给 Agent 的符号建议均附带证据来源追踪（如 `evidence_type: "format_string_inference"`、`confidence: 1.0`）。

### Equivalence & Recompilability Loop
- [ ] Agent 利用该 MCP 工具逆向重构的 C 源码能够使用目标编译器成功编译为可执行文件（0 编译错误）。
- [ ] 重构编译生成的目标程序在基准测试用例集下的输入输出、退出码与原剥离二进制 100% 行为一致（通过差分测试）。
- [ ] 自动化测试套件（pytest）覆盖核心证据挖掘、动态挂钩、MCP 工具调用与差分校验流程，测试全部通过。

## Follow-up — 2026-10-16T07:05:30Z

The host environment experienced a crash/restart. All background tasks and subagents were stopped. Please inspect the current state in `.agents/teamwork/orchestrator/progress.md`, revive or respawn the orchestrator, and resume execution of the Metis Reverse project.

## Follow-up — 2026-10-16T08:49:36Z

Network connection has been fully restored. Please proceed with reviving or respawning the orchestrator (or executing the primed succession to orchestrator_gen2) and continue with Milestone 2 execution.

## Follow-up — 2026-10-16T11:19:56Z

Quota has been restored and server is back online. Please resume orchestration and execution for Metis Reverse.
