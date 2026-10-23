# Metis-Reverse: Known Limitations & Compliance Boundaries (合规边界与已知限制)

本文档明确定义 Metis-Reverse 在多架构指令微仿真、现代操作系统安全机制合规以及多语言工件提取中的边界与限制规范。

---

## 1. 架构与指令级微仿真边界 (Micro-Emulation Boundaries)

Metis-Reverse 的微仿真能力（`re_emulate_slice`）旨在为逆向分析员与 AI Agent 提供**短片段逻辑自验**（如解密循环执行、动态 API 哈希计算、关键分支解算），而非全系统全状态模拟器。

### 1.1 ARM64 PAC (Pointer Authentication Code)
* **行为模式：** 在用户态受限微仿真环境下，系统不具备 Apple Silicon / ARMv8.3+ 内核级的真实硬件密钥（APIAKey、APIBKey 等）。
* **仿真策略：** `pacibsp`、`autibsp`、`pacia`、`autia` 等签名与认证指令默认采用确定性仿真桩处理（验证通过），或视为标准 NOP 执行。
* **边界告警：** 若跳转目标地址被 PAC 损坏或包含无效指针标签，系统将拦截异常并输出 `unmapped_memory_jump`，严禁猜测跳转目的地。

### 1.2 ARM NEON & SVE 向量指令
* **支持范围：** 支持常见 128 位 NEON 向量寄存器（`q0`-`q31`）加载、存储（`ld1`, `st1`）、异或及向量加减运算。
* **边界限制：** 对于跨 Lane 混洗、浮点舍入模式动态切换或涉及外部未映射内存的巨型查找表，仿真引擎不会隐式伪造内存，而是精确记录并在返回中标记 `uninitialized_memory_accesses`。

### 1.3 线程局部存储 (TLS - Thread Local Storage)
* **寄存器基址：** x86_64 的 `fs_base` / `gs_base` 与 ARM64 的 `tpidr_el0` 默认初始化为确定性沙箱内存块基址。
* **多线程与并发：** 微仿真仅支持单线程执行切片，不支持真实并发锁竞态模拟。

---

## 2. 操作系统安全合规与对抗防护底线 (Compliance & Non-Evasion Policy)

Metis-Reverse 严格遵守白帽安全工程规范、安全开发审计标准以及现代操作系统安全模型。

### 2.1 严守操作系统防御底线 (Zero Bypass Policy)
* **macOS SIP / Hardened Runtime / AMFI：** Metis-Reverse **不提供**任何绕过系统完整性保护（SIP）、绕过 AMFI 签名校验、注入受保护进程或利用内核特权的对抗性漏洞能力。
* **Windows Defender / AppLocker / EDR：** 系统不会伪造系统签名、不提供驱动证书绕过，亦不包含反射型 DLL 注入器或针对防病毒软件的动态免杀载荷。
* **分析对象定位：** 所有分析均基于只读样本挂载、离线反编译、静态模型抽象以及物理字节切片。

### 2.2 R6 沙箱与资源消耗红线 (Sandboxing Red Line)
* **自定义脚本执行：** 任何自定义探索探针（Escape Hatch 1 `execute_probe_script`）或解密假设自验（`re_verify_hypothesis`）均运行在独立、只读挂载且非特权的受限沙箱进程中。
* **DoS 防护：** 针对解压炸弹（Zip Bomb / Tar Bomb）、畸形 Mach-O `ncmds` 溢出攻击、无限递归符号解析，系统均实施了严格的字节膨胀比上限（最大 50MB）、扫描窗口上限与超时限制。

### 2.3 R5 不可信输入与防提示词注入 (Prompt Injection Defense)
* 样本提取出的一切内容（函数名、demangle 符号、JS 源码、注释、节名）均视为不可信数据，封装在独立数据字段与 `<untrusted_binary_evidence>` 围栏中。
* 系统持续扫描注入特征（如假冒系统指令、假冒工具调用格式），命中时标记 `suspicious_instruction_like: true`，严禁与模型指令性上下文混排。

---

## 3. 多语言工件与降级分析说明 (Degraded Analysis & Fallbacks)

### 3.1 不透明字节码 (Opaque Bytecode)
* 对于 V8 CodeCache、JSC 字节码缓存、Hermes HBC 以及 Python/Lua 等专有字节码，当引擎检测到非标准或魔改版本且缺乏反编译支持时，系统遵循 R4 原则：
  1. 输出格式与版本矩阵识别结果；
  2. 明确返回 `degraded_result: true`；
  3. 保留原始字节切片供沙箱 Python 探针（Escape Hatch 1）自定义提取，不隐式阻断用户分析。

### 3.2 符号与常量反混淆
* 对于 Go 语言寄存器 ABI（ABIInternal）、Rust monomorphization 代码膨胀、Swift protocol witness table，系统通过 `re_capabilities` 与多视角并列呈现（三元坐标、反汇编与物理字节）协助分析，防止反编译器失真造成的误判。
