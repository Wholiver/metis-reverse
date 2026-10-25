# Metis Reverse 安装教程（1.0.1）

[English](INSTALL.md) · **简体中文**

对照当前 CLI（`metis-reverse-cli@1.0.1`）写的。旧版 doctor / `Done.` / `clients` / 「111 个组件」那套已经作废，别再抄。

**目标：** 给本机编程助手挂上 Metis Reverse MCP（约 29 个 `re_*` / `js_*` 工具）。  
**正式包名：** [`metis-reverse-cli`](https://www.npmjs.com/package/metis-reverse-cli)（npm `latest` = **1.0.1**）。  
**不要装：** 旧 npm 名 `metis-reverse`（仍停在 **0.0.1**）。

引擎不在 npm 里：setup 写入的是 `uvx --from git+https://github.com/Wholiver/metis-reverse.git@latest metis-reverse`（Git 浮动标签 `latest`，当前 = `v1.0.1`）。**没有** PyPI 包。

---

## 你需要准备

| 东西 | 要求 |
| --- | --- |
| Node.js | **≥ 18**（装完重开终端，`node -v` 能看到版本） |
| uv | 装完重开终端，`uv --version` 能看到版本（引擎靠 `uvx`） |
| 编程助手 | Cursor / Claude Code / Codex 等任选；约 **23** 个客户端可写 |

---

## 第 0 步：打开终端

- **Windows**：Win 键 → 输入 `PowerShell` → 打开
- **macOS**：`Command + 空格` → `Terminal` /「终端」
- **Linux**：常见 `Ctrl + Alt + T`

后面说「粘贴」，就是复制进这个窗口再回车。

![打开终端](images/readme/tutorial/open-terminal.png)

## 第 1 步：装 Node.js

1. 打开 https://nodejs.org/en/download ，下 **LTS**，装完  
2. **关掉终端再开**，跑：

```bash
node -v
```

看到 `v18` / `v20` / `v22` 这类即可。

## 第 2 步：装 uv

**Windows（PowerShell）：**

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**macOS / Linux：**

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

装完**重开终端**，再检查：

```bash
uv --version
```

也可用 `brew install uv`（macOS）或 `winget install --id=astral-sh.uv -e`（Windows）。

## 第 3 步：跑 setup

若用 **Claude Desktop**：先**完全退出**（不只关窗口）。

```bash
npx metis-reverse-cli@latest setup
```

第一次可能较慢（`npx` 拉 CLI；之后引擎依赖由 `uvx` 按需拉）。看起来卡住时先别关窗口。

交互大致是这样（文案以你终端里为准，下面按源码）：

1. 探测本机 Agent（会提示找到几个）
2. **`Which agents should Metis Reverse be installed into?`**  
   方向键移动，**空格勾选**，回车。已检测到 / 已配置的一般会预勾。

![选择要安装的 Agent](images/readme/tutorial/setup-pick.png)

3. **`Install complete Agent Skill package (SKILL.md + reverse references + rules)?`**  
   默认 Yes；只想写 MCP 可选 No，或事先加 `--no-skill`。
4. 弹出 **Installation Plan**（各客户端 MCP 路径 + Skill 是否开启）。已有 MCP 配置会先留 **`.bak`**。
5. **`Apply these configurations to selected agents?`**  
   默认 Yes。

成功结束语（1.0.1）：

```text
Setup complete! Please restart your selected agents to activate Metis Reverse.
```

![Setup 成功](images/readme/tutorial/setup-done.png)

跳过菜单的例子：

```bash
npx metis-reverse-cli@latest setup --client cursor --client claude_code --yes
```

或先全局再跑：

```bash
npm install -g metis-reverse-cli@latest
metis setup
```

`preview` = 不写盘的 dry-run：

```bash
npx metis-reverse-cli@latest preview
# 等同：setup --dry-run
```

## 第 4 步：重启助手

把刚勾选的软件**完全退出再打开**。不重启读不到新 MCP。

## 第 5 步：自检

```bash
npx metis-reverse-cli@latest doctor
```

![doctor 自检](images/readme/tutorial/doctor.png)

1.0.1 的 doctor 会列出每个客户端：`Detected` / `MCP: Ready` / `Skill: Ready`（或不支持 Skill）。  
配好了一般会看到类似：`Metis Reverse is active on N agent(s).` → `All systems operational.`  
还没配过：会提示去跑 `setup`。

看具体路径用 JSON：

```bash
npx metis-reverse-cli@latest doctor --json
```

每项里有 `config_path` / `skill_path`。**没有** `clients` 子命令。

在 Cursor：**Settings → MCP**，应能看到 `metis-reverse`，下面大约 **29** 个任务级工具。

只卸 Metis Reverse（其它 MCP 保留）：

```bash
npx metis-reverse-cli@latest uninstall
```

---

## 常见问题

**`node` / `npx` 不是命令**  
Node 没装好或没重开终端。重开；不行就重装 LTS。

**`uv` / `uvx` not found**  
回到第 2 步，装完务必重开终端。

**npx 很慢**  

```bash
npx --registry=https://registry.npmmirror.com metis-reverse-cli@latest setup
```

**Windows「禁止运行脚本」**  

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

输入 `Y`，重开终端。

**列表一个都没勾 / 被取消**  
重跑并用空格勾选，或：

```bash
npx metis-reverse-cli@latest setup --client cursor --yes
```

**想确认写到哪**  
`doctor` 或 `doctor --json`（看 `config_path`）。

**装错旧包**  
务必 `metis-reverse-cli@latest`（或钉 `@1.0.1`）。旧名 `metis-reverse@0.0.1` 不是本版。

**还是不行**  
把 `npx metis-reverse-cli@latest doctor` 完整输出贴到 [Issues](https://github.com/Wholiver/metis-reverse/issues)。

---

## 和 README 的关系

README 里是短版安装；本页是逐步说明。协议 **Apache-2.0**。仓库：https://github.com/Wholiver/metis-reverse
