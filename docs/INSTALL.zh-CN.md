# Metis Reverse 安装教程（零基础版）

[English](INSTALL.md) · **简体中文**

按现在的 **1.0.1** CLI 写的。流程是：装好 Node 和 uv → 跑一行 `setup` → 按提示勾选助手 → 看到完成提示 → **重启**那些软件。

> **请装对包名。** 正式 CLI 是 [`metis-reverse-cli`](https://www.npmjs.com/package/metis-reverse-cli)。旧 npm 名 `metis-reverse` 还停在 **0.0.1**，不是这一版。推荐：
>
> ```bash
> npx metis-reverse-cli@latest setup
> ```
>
> （也可钉死 `@1.0.1`。）引擎不在 npm / PyPI，setup 写入的 MCP 用 `uvx` 从 GitHub 的 **`latest`** 标签拉。

## 需要什么

| 东西 | 干什么 | 版本 |
| --- | --- | --- |
| [Node.js](https://nodejs.org/) | 跑 `npx` / CLI | **18+**（建议 LTS） |
| [uv](https://docs.astral.sh/uv/) | 给 MCP 引擎用 `uvx` | 装好能跑 `uv --version` 即可 |

装完任何一个，都要**关掉终端再开一次**，否则可能还是 `command not found`。

## 第 0 步：打开终端

- **Windows**：按 Windows 键，输入 `PowerShell`，打开「Windows PowerShell」
- **macOS**：`Command + 空格`，输入「终端」或 `Terminal`，回车
- **Linux**：一般是 `Ctrl + Alt + T`

后面说的「粘贴命令」，就是复制进这个窗口再按回车。

## 第 1 步：安装 Node.js

1. 打开 https://nodejs.org/en/download ，下载 **LTS**，一路下一步装完（Linux 按该页说明）
2. 重开终端，检查：

```bash
node -v
```

看到 `v18` / `v20` / `v22` 这类版本号即可。

## 第 2 步：安装 uv

uv 负责拉分析引擎；它会自己准备 Python，你不用另装。

**Windows（PowerShell）：**

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**macOS / Linux：**

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

重开终端后检查：

```bash
uv --version
```

也可以：`brew install uv`（macOS）或 `winget install --id=astral-sh.uv -e`（Windows）。

## 第 3 步：跑 setup

若用 **Claude Desktop**，先**完全退出**（不是只关窗口）。

```bash
npx metis-reverse-cli@latest setup
```

第一次 `npx` 可能问要不要执行 / 下载包，按提示同意即可。随后进入 Metis Reverse 自己的安装界面（标题类似 `METIS REVERSE  Agent Installer & MCP Manager  v1.0.1`）。

### 你会依次看到

1. **Detecting installed AI agents…**  
   它在扫本机大约二十多个支持的编程助手。

2. **Which agents should Metis Reverse be installed into?**  
   多选列表。已检测到或已配置的会靠前，并带 `detected` / `MCP active` 等提示。  
   - 方向键移动  
   - **空格**勾选 / 取消  
   - 有的终端可用 `a` 全选  
   - **回车**确认  
   至少要选一个。

3. **Install complete Agent Skill package (SKILL.md + reverse references + rules)?**  
   默认 Yes。会给支持 Skill 的客户端装上技能包（Cursor 还会带 rules）。一般直接回车。

4. **Installation Plan**  
   列出每个客户端要写的 MCP 配置路径，以及 Skill 开不开。已有配置文件时，写入前会先留一份 **`.bak`** 备份。

5. **Apply these configurations to selected agents?**  
   默认 Yes。确认后开始写入。

### 成功长什么样

交互结束时会看到类似：

```text
Setup complete! Please restart your selected agents to activate Metis Reverse.
```

中间每条会显示某个助手的 `MCP` / `Skill` 写入结果（成功或失败原因）。

### 不想点菜单时

```bash
npx metis-reverse-cli@latest setup --client cursor --client claude_code --yes
```

只写 MCP、不装 Skill：

```bash
npx metis-reverse-cli@latest setup --client cursor --yes --no-skill
```

先全局装 CLI 再跑也可以：

```bash
npm install -g metis-reverse-cli@latest
metis setup
```

（`metis` 和 `metis-reverse` 是同一个入口。）

## 第 4 步：重启软件

把刚才勾选的软件**完全退出再打开**。不重启读不到新 MCP。

## 第 5 步：用 doctor 自检

```bash
npx metis-reverse-cli@latest doctor
```

它会列出每个支持的助手：有没有检测到、MCP 是否 Ready、Skill 是否 Ready。  
配好了会出现类似：

```text
Metis Reverse is active on N agent(s).
All systems operational.
```

还没配过会提示去跑 `setup`。

需要机器可读输出（含配置路径）时：

```bash
npx metis-reverse-cli@latest doctor --json
```

在 Cursor 里也可以看：**Settings → MCP**，能看到 `metis-reverse`，下面大约 **29** 个任务级工具，就接上了。

## 常用命令

| 命令 | 作用 |
| --- | --- |
| `npx metis-reverse-cli@latest setup` | 交互安装（默认命令） |
| `npx metis-reverse-cli@latest preview` | 干跑：界面和探测一样，**不写盘** |
| `npx metis-reverse-cli@latest doctor` | 健康检查 |
| `npx metis-reverse-cli@latest uninstall` | 只卸 Metis Reverse（其它 MCP 不动） |

`setup` 的别名还有 `init`、`install`；`doctor` 还有 `check`、`status`；`uninstall` 还有 `remove`。

## 常见问题

**`node` / `npx` 不是命令**  
Node 没装好，或装完没重开终端。重开；还不行就重装 LTS。

**`uv` / `uvx` not found**  
回到第 2 步，装完务必重开终端。引擎靠 `uvx`，没有 uv 时 MCP 起不来。

**npx 很慢或卡住**  
可换国内镜像：

```bash
npx --registry=https://registry.npmmirror.com metis-reverse-cli@latest setup
```

**Windows「禁止运行脚本」**

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

按提示输入 `Y`，再重开终端。

**提示没有可选客户端 / 一个都没选到**  
列表里要用空格勾选，或直接：

```bash
npx metis-reverse-cli@latest setup --client cursor --yes
```

**想看配置写到哪**  
看 setup 的 Installation Plan，或：

```bash
npx metis-reverse-cli@latest doctor --json
```

1.0.x **没有** `clients` 子命令。

**装错了旧包名**  
务必用 `metis-reverse-cli@latest`（或 `@1.0.1`）。旧名 `metis-reverse` 仍是 0.0.1。

**还是不行**  
把 `npx metis-reverse-cli@latest doctor` 的完整输出贴到仓库 [Issues](https://github.com/Wholiver/metis-reverse/issues)，或发到 Metis QQ 交流群：**801193315**。
