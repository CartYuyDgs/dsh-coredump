/**
 * dsh-coredump — host half.
 *
 * Registers three agent tools and one system-prompt section:
 *   coredump_find  — list cores / core_pattern on a remote host (no gdb)
 *   coredump_parse — signal + all thread stacks + modules + diagnostics
 *   coredump_frame — one frame in depth (registers / args / locals / disasm / source)
 *
 * No client half, no settings page, no route family: this plugin is pure
 * tooling. Connection handling and credential lookup stay in the system OpenSSH
 * client (~/.ssh/config), so multi-hop means `ssh -J` and nothing else.
 */

import { createFindTool } from './find-tool.js'
import { createFrameTool } from './frame-tool.js'
import { createParseTool } from './parse-tool.js'
import { makeRoutes } from './routes.js'

/** Stable cordis plugin name. */
export const name = 'coredump'

/** Services required before the tool surface can mount. */
export const inject = ['tools', 'systemPrompt']

/** Order of the guidance section inside the plugin band (dsh-ssh uses 150). */
const SECTION_ORDER = 155

/** Model-facing announcement: what it does, when to use it, what it does NOT do. */
export const COREDUMP_GUIDANCE = '本机已安装 dsh-coredump 插件（远端 coredump 排障），三个工具都通过系统 OpenSSH 连远端 Linux 主机，多跳用 jumps 参数（ssh -J 语义）或直接在 ~/.ssh/config 配 ProxyJump。用法顺序：① 不知道 core 在哪 → coredump_find（列 core_pattern / coredumpctl / 默认目录，不跑 gdb）；② 拿到路径 → coredump_parse（崩溃信号、崩溃指令与相关寄存器、所有线程调用栈、模块 build-id 与符号状态、诊断建议；默认每线程 40 帧）；③ 需要看某一帧的实参/局部变量/反汇编/源码 → coredump_frame（thread + frame）。远端只需 gdb 7.6+ 与 python3 3.6+，解析引擎每次随请求从 stdin 下发，远端不装任何东西；只读远端文件、不下载 core（core 含明文内存）。不处理密码登录（走密钥或 ssh-agent）。用户提到 core / coredump / 段错误 / abort / 崩溃栈时优先用它，而不是自己手敲 gdb。'

/** Register one tool factory and dispose it with the fiber. */
function registerTool(ctx, factory, label) {
  ctx.effect(() => {
    const dispose = ctx.tools.register(factory())
    return () => dispose()
  }, label)
}

/**
 * Mount the tools, their guidance, and the browser panel's data routes.
 * @param {import('@deepseek-ai/cordis').Context} ctx - host plugin context.
 */
export function apply(ctx) {
  registerTool(ctx, createFindTool, 'dsh-coredump: tool find')
  registerTool(ctx, createParseTool, 'dsh-coredump: tool parse')
  registerTool(ctx, createFrameTool, 'dsh-coredump: tool frame')

  ctx.effect(() => {
    const dispose = ctx.systemPrompt.section({
      name: 'plugin:dsh-coredump',
      order: SECTION_ORDER,
      text: COREDUMP_GUIDANCE,
    })
    return () => dispose()
  }, 'dsh-coredump: prompt')

  // Optional: headless profiles have no web server, and must keep the tools.
  ctx.inject(['webServer'], (scoped) => {
    if (!scoped.webServer) return
    scoped.effect(() => {
      const disposers = makeRoutes().map(route => scoped.webServer.register(route))
      return () => {
        for (const dispose of disposers) dispose()
      }
    }, 'dsh-coredump: routes')
  })
}
