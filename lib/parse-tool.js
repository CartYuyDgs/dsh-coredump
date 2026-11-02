/**
 * The `coredump_parse` agent tool.
 *
 * Flow: hand the core path to the bundled engine over ssh → render a compact
 * markdown report from the engine's JSON → keep the full copy locally.
 *
 * The remote host needs nothing installed beyond gdb and python3: the engine
 * travels with the request, so upgrading the plugin upgrades the engine too.
 */

import { renderFailure, renderMarkdown, saveReport } from './report.js'
import { runEngine } from './engine-run.js'
import {
  SSH_PARAMETERS,
  optionalBoolean,
  optionalInteger,
  optionalString,
  optionalStringArray,
  objectSchema,
  requiredString,
  sshOptions,
  textContent,
  toInt,
  toText,
  finish,
} from './tool-kit.js'

/** Model-facing failure result. */
function failure(context, failureInfo) {
  return {
    ok: false,
    host: context.host || '-',
    core: context.core || '-',
    markdown: renderFailure({ title: 'coredump 解析失败', host: context.host, core: context.core }, failureInfo),
    error: `${failureInfo.code || 'ERROR'}：${failureInfo.message}`,
  }
}

/** Create the tool definition. */
export function createParseTool() {
  return {
    name: 'coredump_parse',
    description: '通过 SSH 在远端 Linux 主机解析 ELF coredump（远端需 gdb 7.6+ 与 python3 3.6+）：返回崩溃信号、崩溃线程调用栈、崩溃指令与相关寄存器、其他线程摘要、模块符号状态和诊断建议。只在远端读取解析，不下载 core 文件。用户给出远端 core 路径、服务崩溃、段错误、abort、卡死（gcore）时使用。',
    parameters: objectSchema(
      {
        host: requiredString('SSH 别名（~/.ssh/config 里的 Host）或 user@host；多跳用 jumps。'),
        core: requiredString('远端 core 文件的绝对路径。'),
        exe: optionalString('产生这个 core 的可执行文件远端绝对路径；强烈建议显式给，省略时从 core 推断。'),
        symbolDirs: optionalStringArray('额外的远端符号搜索目录（set solib-search-path / debug-file-directory）。'),
        maxFrames: optionalInteger('每个线程最多解析的栈帧数（默认 40）。'),
        timeoutMs: optionalInteger('整体超时毫秒（默认 180000，范围 10000~900000）。'),
        saveReport: optionalBoolean('是否把完整 JSON 落到本机 $DSH_HOME/coredump（默认 true）。'),
        ...SSH_PARAMETERS,
      },
      ['host', 'core'],
    ),
    output: {
      schema: objectSchema(
        {
          ok: { type: 'boolean' },
          host: { type: 'string' },
          core: { type: 'string' },
          signal: { type: 'string' },
          threads: { type: 'integer' },
          reportPath: { type: 'string' },
          markdown: { type: 'string' },
          error: { type: 'string' },
        },
        ['ok', 'markdown'],
      ),
      render: (_args, value) => textContent(value.markdown),
    },
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      const context = {
        host: toText(args.host),
        core: toText(args.core),
      }
      if (context.host === '' || context.core === '') {
        return failure(context, { code: 'BAD_ARGS', message: '参数错误：host 与 core 必填。' })
      }

      const timeoutMs = toInt(args.timeoutMs, 180000, 10000, 900000)
      const maxFrames = toInt(args.maxFrames, 40, 1, 500)

      const outcome = await runEngine({
        ssh: sshOptions(args),
        core: context.core,
        exe: toText(args.exe) || undefined,
        symbolDirs: args.symbolDirs,
        maxFrames,
        timeoutMs,
        signal: exec?.signal,
      })
      if (!outcome.ok) return failure(context, outcome)

      const report = outcome.report
      let reportPath
      if (args.saveReport !== false) {
        try {
          reportPath = await saveReport(report, { host: context.host, core: context.core })
        } catch {
          reportPath = undefined
        }
      }

      // Only defined fields may leave the tool: a JSON `undefined` is not a
      // lossless value and fails the runtime's output validation.
      return finish({
        ok: true,
        host: context.host,
        core: context.core,
        signal: report.signal?.name,
        threads: Array.isArray(report.threads) ? report.threads.length : 0,
        reportPath,
        markdown: renderMarkdown(report, { host: context.host, reportPath }),
      })
    },
  }
}
