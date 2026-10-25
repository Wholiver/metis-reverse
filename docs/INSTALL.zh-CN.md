# Metis Reverse 安装教程（零基础版）

[English](INSTALL.md) · **简体中文**

整个过程就五步：**打开终端 → 粘贴一行命令 → 回车 → 看到 `Done.` → 重启软件**。

开始前要先装两个小工具：Node.js 和 uv。下面每一步都写了怎么做，照着来就行。

> **请装对包名。** 正式 CLI 是 [`metis-reverse-cli`](https://www.npmjs.com/package/metis-reverse-cli)。旧 npm 名 `metis-reverse` 仍停在 **0.0.1**，**不是**本版。推荐：`npx metis-reverse-cli@latest setup`（也可钉死 `@1.0.1`）。引擎用 GitHub 的 **`latest`** 标签拉取。

## 第 0 步：打开终端

终端就是一个能输入命令的黑色（或白色）窗口。

- **Windows**：按键盘上的 Windows 键，输入 `PowerShell`，点开「Windows PowerShell」。
- **macOS**：按 `Command + 空格`，输入 `终端`（或 `Terminal`），回车。
- **Linux**：一般按 `Ctrl + Alt + T`。

![打开终端](images/readme/tutorial/open-terminal.png)

后面说「粘贴命令」，就是把命令复制进这个窗口，再按回车。

## 第 1 步：安装 Node.js

1. 打开 https://nodejs.org/en/download ，下载 **LTS**（长期支持版）安装包。
2. 双击安装包，一路点「下一步」装完。Linux 用户按这个页面上的说明装。
3. **关掉终端再重新打开**，粘贴下面这行，回车：

```bash
node -v
```

看到 `v20.19.2` 这样的版本号（**18 以上**都行），就装好了。

## 第 2 步：安装 uv

uv 用来下载和运行 Metis Reverse 的分析引擎（`uvx` 从 GitHub 拉；**目前没有** PyPI 包）。它会自己把需要的 Python 装好，你不用另外装 Python。

**Windows**（在 PowerShell 里粘贴）：

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**macOS / Linux**：

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

装完**一定要关掉终端再重新打开**，然后检查：

```bash
uv --version
```

看到 `uv 0.x.x` 这样的输出就好了。也可以用 `brew install uv`（macOS）或 `winget install --id=astral-sh.uv -e`（Windows）安装。

## 第 3 步：运行安装命令

> 用 Claude Desktop 的话，先把它**完全退出**（不只是关掉窗口）。

粘贴这一行，回车：

```bash
npx metis-reverse-cli@latest setup
```

第一次运行要多等几分钟。它会从网上下载引擎依赖，有几个比较大，中途看着像卡住也别关窗口。

接下来会出现几个问题：

- **问你要不要安装 `metis-reverse-cli`**：输入 `y` 回车。
- **一个软件列表**：它会把电脑上找到的编程软件（Cursor、Claude Code、VS Code 等）列出来。用方向键上下移动，空格勾选，回车确认。
- **`Install Agent Skill where supported?`**：问要不要顺便装上技能，默认是 Yes，直接回车。
- **写入计划（`Setup plan`）**：它会列出要改哪些文件。如果原来已经有配置，改之前会先备份成 `.bak`。
- **`Proceed with installation?`**：问要不要开始写入，默认也是 Yes，直接回车。

![setup 选择软件](images/readme/tutorial/setup-pick.png)

最后看到这一行，就是成功了：

```
Done. Restart the configured agents to load Metis Reverse.
```

![安装完成](images/readme/tutorial/setup-done.png)

跳过菜单也可以直接指定客户端，例如：

```bash
npx metis-reverse-cli@latest setup --client cursor --client claude_code --yes
```

或先全局安装 CLI，再跑同一套向导：

```bash
npm install -g metis-reverse-cli@latest
metis setup
```

## 第 4 步：重启软件

把刚才勾选的软件**完全退出，再重新打开**。不重启它是读不到新配置的。

## 第 5 步：检查一下（可选）

```bash
npx metis-reverse-cli@latest doctor
```

最后一行是 `Healthy: yes` 就说明一切正常。中间的列表里，你配好的软件后面会显示 `registered`。需要机器可读输出时用 `doctor --json`。

看到 WARN 不影响先用；本机若另装了可选后端（例如通过 `GHIDRA_INSTALL_DIR` 接 Ghidra），doctor 里会反映出来。

![doctor 检查](images/readme/tutorial/doctor.png)

在软件里也能确认：打开它的 MCP 设置（Cursor 在「Settings → MCP」），能看到 `metis-reverse`，下面大约 **29** 个任务级工具，就接好了。

只卸 Metis Reverse（其它 MCP 保留）：

```bash
npx metis-reverse-cli@latest uninstall
```

不写盘的预览 / dry-run：

```bash
npx metis-reverse-cli@latest preview
```

## 常见问题

**提示 `node` 或 `npx` 不是命令 / command not found**  
Node.js 没装好，或者装完没重开终端。关掉终端重新打开再试；还不行就重新装一遍 Node.js。

**提示 `uv` / `uvx` not found**  
uv 没装好，或者装完没重开终端。回到第 2 步。

**npx 下载特别慢，或者一直卡住**  
多半是网络问题。可以换国内的 npm 镜像：

```bash
npx --registry=https://registry.npmmirror.com metis-reverse-cli@latest setup
```

**Windows 提示「禁止运行脚本」（执行策略）**  
在 PowerShell 里粘贴这行，回车，按提示输入 `Y`，然后重开终端：

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

**提示 `No clients selected`**  
你在列表里一个都没勾。重新跑一遍，记得用空格勾选。也可以直接指定，比如：

```bash
npx metis-reverse-cli@latest setup --client cursor --yes
```

**我想知道配置写到哪个文件了**  
跑 `npx metis-reverse-cli@latest doctor`（或 `doctor --json`）。1.0.x 已没有 `clients` 子命令。

**装错了旧包名**  
务必用 `metis-reverse-cli@latest`（或钉死 `@1.0.1`）。旧名 `metis-reverse` 仍是 0.0.1，不是这一版。

**还是不行**  
把 `npx metis-reverse-cli@latest doctor` 的完整输出贴到仓库 [Issues](https://github.com/Wholiver/metis-reverse/issues)，或发到 Metis QQ 交流群：**801193315**。
