# dsh-coredump

DSH 插件：**通过 SSH 在远端 Linux 设备上排查 ELF coredump**（gdb 7.6+ / Python 3.6+）。
一个 Web GUI 面板 + 三个 Agent 工具，覆盖「找 core → 出栈 → 深挖单帧」的完整路径；支持多跳（`ssh -J` / `ProxyJump`）。

## 它解决什么

- 不用登录跳板机手敲 `gdb -batch`，对话里一句话出栈，或直接在侧边栏面板里点；
- 每次解析都附带**符号状态**（模块 / build-id / 是否有 debug 文件），避免拿着一份错栈分析半天；
- 崩溃现场直接给齐：信号、**崩溃指令**、指令涉及的**寄存器值**、完整线程栈；
- 需要看某一帧的实参/局部变量/反汇编/源码时，用面板点帧或 `coredump_frame` 单独深挖，不把整份 gdb 输出灌进上下文；
- 失败也是结论：核心诊断码（`EXE_MISMATCH`、`SYMBOL_MISSING`、`CORE_TRUNCATED`、`GDB_MISSING` …）告诉你该补什么；
- 多跳（`ssh -J`）、别名、`~/.ssh/config`、ssh-agent 全部复用系统 OpenSSH，插件不碰任何凭据。

## 安装

前提：

1. DSH ≥ `0.2.1-rc.2`；
2. 本机有 **OpenSSH 客户端**（Windows 10/11 自带 `ssh.exe`）；
3. 远端有 `gdb`（7.6+）和 `python3`（3.6+）。**远端不需要装任何插件或脚本** —— 解析引擎随每次请求从 stdin 下发。

方式 A（GitHub 仓库直接装，无需 registry，推荐）：

```
plugin_manager install_bundle  target: https://github.com/CartYuyDgs/dsh-coredump
```

方式 B（发布到 npm 后从 registry 装）：

```
plugin_manager install_bundle  target: dsh-coredump
```

方式 C（本地目录 / tarball，开发时用）：

```
plugin_manager install_bundle  target: D:\path\to\dsh-coredump
plugin_manager install_bundle  target: D:\path\to\dsh-coredump-0.3.0.tgz
```

方式 D（脚本，junction 链接源码、不复制；会改 profile 清单，执行前先备份）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1
# 指定 profile / DSH_HOME / 演练：
#   .\install.ps1 -ProfileName web -DshHome D:\dsh-home -DryRun
```

装完如果工具没出现，**完全退出 DSH 进程**再启动（客户端面板只在启动时扫描）。

> 源码以 **link / junction** 方式装进 profile 时，插件不能从自己的真实路径解析 `@deepseek-ai/*`；
> 所以本插件的 Host 侧**不 import 任何 dsh 包**，工具 schema 是本地构造的 JSON Schema（见 `lib/tool-kit.js`）。
> 别为了图省事把 `defineTool` 加回来 —— 那会让整个插件挂不上。

## 用法

### GUI 面板

侧边栏会多一个 **Coredump** 图标（SSH 图标下方），点开就是面板：

```
主机 / core / exe / 私钥路径  ▸ [扫描 core] [解析]
最近：host:core  ▸ 点一下直接重解析
──────────────┬─────────────────────────────
线程列表       │ 调用栈（点某帧 → 下方帧详情）
① crashed      │ #0 crash_here  crash.c:18
②              │ #1 main        crash.c:27
──────────────┴─────────────────────────────
帧详情：寄存器 / 参数 / 局部变量 / 反汇编 / 源码窗口
诊断 + 模块（build-id、符号状态）
```

- 「扫描 core」= `coredump_find`，列出 `core_pattern`、`ulimit -c`、`coredumpctl` 与目录里的 core，
  每行带一个「解析这个」；
- 面板与工具走**同一个引擎**（`lib/routes.js` 复用 `engine-run.js`），同一份 core 出的栈不会两边不一致；
- 面板只接受**本机（loopback）**请求：读 core 等于读进程内存，所以刻意不暴露给 LAN 浏览器；
- 最近记录存在浏览器 `localStorage`，不落远端、不落磁盘文件。

> 客户端模块只在 **DSH 启动时**扫描 `dsh.client`。首次装好/给插件新加面板后，需要**完全重启 DSH**
> （不是刷新页面）才会出现侧边栏图标；之后再改面板代码刷新页面即可。

对话里也可以直接说：

> 解析一下 prod-db 上的 `/data/core.18422`，可执行文件是 `/opt/app/bin/order-server`

或者：

> 这台机器 `/var/crash` 下有没有 core？有的话看下最新那个的崩溃栈

### 三个工具

| 工具 | 作用 | 何时用 |
|---|---|---|
| `coredump_find` | 列 `core_pattern`、`ulimit -c`、`coredumpctl list`、默认目录里的 core。不跑 gdb，秒回 | 不知道 core 在哪 / 想确认有没有 |
| `coredump_parse` | 信号、崩溃指令、相关寄存器、所有线程栈、模块符号状态、诊断建议 | 已有 core 路径 |
| `coredump_frame` | 单帧：寄存器、实参、局部变量、pc 附近反汇编、源码窗口 | 要定位某一个关键帧 |

`coredump_parse` 参数：

| 参数 | 必填 | 说明 |
|---|---|---|
| `host` | ✅ | `~/.ssh/config` 别名或 `user@host` |
| `core` | ✅ | 远端 core 绝对路径 |
| `exe` | | 崩溃那次构建的可执行文件；强烈建议显式给 |
| `jumps` | | 跳板机链路，`ssh -J` 语义（`"a,b"` 或 `["a","b"]`，支持 `user@host:port`） |
| `symbolDirs` | | 额外符号目录，映射到 `set solib-search-path` / `set debug-file-directory` |
| `maxFrames` | | 每线程帧数上限（默认 40） |
| `timeoutMs` | | 整体超时（默认 180000，最小 10000） |
| `user` / `port` | | SSH 用户 / 端口 |
| `identityFile` | | 私钥**文件路径**（`ssh -i`，支持开头 `~`），不是密码；不传则用 ssh-agent / `~/.ssh/config` / 默认密钥 |
| `saveReport` | | 把完整 JSON 落到本机 `$DSH_HOME/coredump/`（默认 true） |

`coredump_frame` 参数：`host`、`core`、`thread`（必填，取 parse 输出里的 `#id`）、`frame`（默认 0）、
`exe`、`symbolDirs`、`timeoutMs`、`saveReport`（默认 false）、以及同样的 ssh 参数。

多跳两种写法都行：

- 工具参数：`jumps: ["bastion", "ops@jump2:2222"]` → `ssh -J bastion,ops@jump2:2222`
- 或直接在 `~/.ssh/config` 给别名配 `ProxyJump`，工具用别名即可。

## 输出

`coredump_parse` 返回 markdown 摘要（信号、崩溃指令与相关寄存器、崩溃线程栈、其他线程摘要、模块与符号、诊断、建议下一步），
完整 JSON 落在 `$DSH_HOME/coredump/<时间戳>-<主机>-<core>.json`（schemaVersion 1）。

JSON 的关键字段：

```jsonc
{
  "schemaVersion": 1,
  "signal": { "name": "SIGSEGV", "description": "Segmentation fault" },
  "crashThread": 2,
  "crash": {
    "thread": 2,
    "instruction": { "address": "0x4012ab", "symbol": "OrderService::submit(int)+27",
                     "text": "mov (%rax),%eax", "current": true },
    "disassembly": [ /* pc 附近 8 条，带 current 标记 */ ]
  },
  "registers": { "rip": "0x4012ab", "rax": "0x0" },
  "threads": [{ "id": 2, "name": "worker-1", "lwp": 18423, "frames": [
    { "index": 0, "address": "0x4012ab", "symbol": "OrderService::submit",
      "source": { "file": "/src/order/service.cpp", "line": 218 },
      "module": "/opt/app/bin/order-server", "unresolved": false }
  ]}],
  "modules": [{ "path": "…", "buildId": "a1b2…", "symbolsLoaded": true,
                "debugFile": "/usr/lib/debug/.build-id/a1/b2….debug" }],
  "diagnostics": [{ "code": "SYMBOL_MISSING", "severity": "warn", "message": "…", "hint": "…" }]
}
```

`coredump_frame` 返回 `mode: "frame"` 的报告：`currentFrame`、`frameInfo`、`args`、`locals`、
`disassembly`、`source.lines`（当前行带 `current: true`）。

## 工作原理

```
[DSH host 插件]                                   [远端 Linux]
  read engine/cdparse.py  ──ssh stdin──►  python3 - --core … --exe …
        ▲                                        │
        └────── JSON (schemaVersion 1) ◄──── gdb -batch / readelf
```

- 引擎在远端只做「采集 + 归一化」，不做归因；归因规则留在插件的 `lib/report.js`；
- 远端不落任何文件、不留脚本，升级插件即升级引擎；
- gdb 用 `-batch -nx -q` 跑：不加载用户 `.gdbinit`、不执行 objfile 自带脚本；
- 各段输出用 `@@cdparse:<name>@@` 标记切分，寄存器一定取自 core 载入时选中的崩溃线程；
- 一次解析 = 一次短连接（解析本质是一锤子买卖，不需要连接池）。

## 诊断码

| code | 含义 | 处理 |
|---|---|---|
| `CORE_NOT_FOUND` / `CORE_UNREADABLE` | core 不存在 / 无读权限 | 确认路径，必要时用有权限的账号 |
| `GDB_MISSING` | 远端没 gdb | `yum install gdb` / `apt install gdb` |
| `GDB_TIMEOUT` | gdb 超时 | 调大 `timeoutMs`，大 core 先只解析崩溃线程 |
| `EXE_MISMATCH` | core 与 exe 不匹配 | **栈不可信**，换同批构建产物 |
| `EXE_NOT_FOUND` | exe 路径不存在 | 用同批产物，或删掉 `/proc/sys/kernel/core_pattern` 里的绝对路径依赖 |
| `SYMBOL_MISSING` / `NO_DEBUG_SYMBOLS` | 模块缺符号 | 按 build-id 装 `-debuginfo` |
| `CORE_TRUNCATED` | core 不完整 | 查 `ulimit -c` / `core_pattern` |
| `ARCH_MISMATCH` | core 与 exe 架构不同 | 换产物 |
| `FRAME_NOT_FOUND` | 指定的线程/帧不存在 | 先用 `coredump_parse` 看线程与帧号 |
| `SOURCE_UNAVAILABLE` | 拿不到源码 | 二进制无调试信息，或编译期路径与现场不一致 |
| `SSH_AUTH_FAILED` | 密钥/agent 不通过 | 插件不支持密码登录，配好 key 或 ProxyJump |

## 排障

- **连不上**：先在终端手动验证链路 `ssh [-J 跳板] 主机 "python3 --version"`，能过再交给插件；
  `coredump_find` 的报错会直接给出 ssh 的分类结论（认证 / 主机指纹 / DNS / 端口 / 超时）。
- **「私钥」框填什么**：填**私钥文件路径**（映射到 `ssh -i`），不是密码、也不是 passphrase。
  开头的 `~` 会自动展开；留空则用 ssh-agent / `~/.ssh/config` / 默认密钥。
- **远端只有密码登录**：插件刻意不做密码认证（不读、不存密码）。两条路：
  1. `ssh-copy-id root@主机` 装一把公钥（一次性，之后面板留空私钥即可——`ssh-agent` 里有对应私钥时）；
  2. 把 `Host 别名 / IdentityFile` 写进 `~/.ssh/config`，面板里只填别名。
- **私钥有 passphrase**：面板不弹口令输入。`ssh-add 私钥` 一次，之后面板私钥留空走 agent；
  Windows 上需要 `Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent`。
- **全是 `??`**：远端装对应 build-id 的 debuginfo，或用 `symbolDirs` 指到 `.debug` 目录。
- **core 来自容器**：宿主机上通常没有容器里的路径，用 `symbolDirs` 把容器产物目录映射上去，或把产物放回同路径。
- **core 很大**：调大 `timeoutMs`；报告会标注 `FRAMES_TRUNCATED` / `OUTPUT_TRUNCATED`。

## 开发与测试

```powershell
# JS（报告渲染 / SSH 参数 / 工具 schema / 标记分节）
node --test-isolation=none --test test/report.test.js test/ssh.test.js test/tools.test.js

# Python 引擎（离线回放，不需要真实 core）
python test/test_engine.py

# 手工回放一段带分节标记的 gdb 输出
python engine/cdparse.py --from-gdb-output test/fixtures/gdb-segv-marked.txt --core /data/core.18422
```

> 在 DSH 沙箱里跑 JS 测试时，`node --test` 的进程隔离会被拦截（spawn EPERM），所以用
> `--test-isolation=none` 逐文件跑。

## 发布

不需要构建步骤：Host 是普通 ESM，Client 是浏览器可直接加载的普通 JS，`engine/cdparse.py` 原样随包走。

```powershell
cd packages/dsh-coredump
npm pack --dry-run        # 先看会打进去哪些文件（必须包含 client.js / engine/cdparse.py / locale / icon）
npm test                  # 34 个 JS 测试（prepublishOnly 也会跑一遍）
npm login                 # 未登录时 npm whoami 会 ENEEDAUTH
npm publish               # 名字被占用时改用 scope：@your-scope/dsh-coredump
```

发布后的安装：

```
plugin_manager install_bundle  target: dsh-coredump
```

### 没有 npm 账户也能分发

`npm pack` 出的 tarball 就是完整可安装包，不需要 registry：

```powershell
npm pack --pack-destination dist
# dist/dsh-coredump-0.3.0.tgz
plugin_manager install_bundle  target: D:\path\to\dsh-coredump-0.3.0.tgz
```

注意 tarball / registry 安装是**复制进 profile**，之后改源码不会自动生效；想保持源码联动就用上面的
「方式 B（本地目录）」装 link。两种方式同一个包名只能存在一个。

要一个 npm 账户：<https://www.npmjs.com/signup> 注册并验证邮箱，然后 `npm login`（npm 11 默认走浏览器授权，
可用 `--auth-type=web`）；发布时若要求 2FA，`npm publish --otp=<6 位码>`。

打包清单的边界：

| 进包 | 说明 |
|---|---|
| `lib/`、`client.js`、`locale/`、`icon.svg`、`cordis.patch.yml`、`README.md`、`LICENSE` | 运行时与展示资源 |
| `engine/cdparse.py` | 远端引擎，**按单文件列进 `files`**，避免把 `__pycache__` 带进包 |
| 不进包 | `test/`、`scripts/`、`engine/__pycache__`、本地私钥/缓存 |

几个容易踩的点：

- **包名必须和 `cordis.patch.yml` 里的 `name` 一致**。改成 scope 时两处一起改，否则装上了也不挂载；
- `dsh.engines.dsh` 是兼容门槛（现在 `>=0.2.1-rc.2`）；DSH 主版本升级时同步改；
- 发布前把 `repository` / `homepage` 补进 `package.json`（有仓库再填，别写假的）；
- 私有 registry：在 `~/.npmrc` 配 `@scope:registry=...` 后同样 `npm publish`，安装时 `plugin_manager` 会问 registry；
- 不想发 registry：`npm pack` 出 `.tgz` 直接发给同事，`install_bundle` 支持 tarball / 本地目录 / git 地址；
- 版本语义：插件按 0.x 演进，新增面板/工具升 minor，修 bug 升 patch；升级 DSH 后先跑一遍实测记录里的场景。

## 兼容性

- 远端：Debian 13 + gdb 16.3 + Python 3.13 实测（2026-11）；RHEL 7 + gdb 7.6.1 + Python 3.6.8 的语法约束仍然遵守
  （引擎不用 f-string / dataclasses / `subprocess.run`）；
- 引擎不用任何第三方 Python 包，只调 `gdb` / `readelf` / `find` / `coredumpctl`；
- gdb 输出格式按「有 Thread 指针 / 只有 LWP」两种排版都解析（exe 不匹配时 gdb 会退化）；
- 只支持 Linux ELF core（C/C++）；Windows minidump 不在范围内。

## 实测记录（2026-11-02）

在 Debian 13 / x86_64 / gdb 16.3 上用一个真实的多线程 SIGSEGV core 跑通：

| 场景 | 结果 |
|---|---|
| `coredump_find` | 列出 `/tmp/cdtest/core.4360`（8.4MB），`core_pattern=core` |
| `coredump_parse` | 崩溃线程 `crash_here (ptr=0x0) at crash.c:18`；崩溃指令 `mov (%rax),%eax`；rax=0x0；其他线程摘要显示 `waiter at crash.c:11`；exe 符号 ✓ |
| `coredump_frame` 线程 1 #1 | `main` 的 `p = 0x0`、局部变量 `t/p/v`、反汇编与源码窗口（当前行 27 高亮） |
| `coredump_frame` #99（不存在） | `FRAME_NOT_FOUND` + 标题标注「请求的 #99 不存在，显示 #0」，不伪造帧 |
| 错误 exe（`/bin/ls`） | `EXE_MISMATCH`，报告顶部标红「栈不可信」，线程仍能列出 |
| `-s` strip 二进制 | 帧显示 `??（无符号）`，给出 build-id 对应的 debuginfo 路径 |
| 面板数据通路 | 直接打 `/api/dsh-coredump/{find,parse,frame}` 均返回真实结果；非 POST 返回 405；非 loopback 拒绝 |
| 面板离线冒烟 | `test/client.test.js`：loader 契约、两个 slot 的 id/key 一致、zh/en 词典键对齐、首屏渲染不抛异常 |

未实测：多跳 `-J`（现场没有第二台可作跳板机的主机）；该路径由 `buildSshArgs` 的单元测试覆盖。
SSH 认证只走密钥/agent：目标机是纯密码认证时需要先 `ssh-copy-id`。


## 安全

- 只读远端文件，**不下载 core**（core 里有明文内存）；
- 报告只包含符号化栈、寄存器、崩溃指令、模块路径，不包含内存内容与变量值以外的数据；
- 不处理密码登录，不读取/存储任何密钥；
- 解析引擎来自本插件包，不执行远端已有的未知脚本；
- gdb 禁用 auto-load / 用户 `.gdbinit`，避免恶意 ELF 借 objfile 脚本执行代码。
