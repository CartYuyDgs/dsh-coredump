import test from 'node:test'
import assert from 'node:assert/strict'

import { createFindTool } from '../lib/find-tool.js'
import { createFrameTool } from '../lib/frame-tool.js'
import { createParseTool } from '../lib/parse-tool.js'
import { buildScanCommand, parseCoreRows, renderScan } from '../lib/find-tool.js'
import { crashRegisters, renderFailure, renderFrameDetail, renderMarkdown, threadTrace } from '../lib/report.js'
import { splitSections } from '../lib/output.js'
import { toArray, toInt, sshOptions, finish } from '../lib/tool-kit.js'

test('tools: every tool definition is registry-ready', () => {
  const tools = [createParseTool(), createFrameTool(), createFindTool()]
  const names = tools.map(tool => tool.name)
  assert.deepEqual(names, ['coredump_parse', 'coredump_frame', 'coredump_find'])
  for (const tool of tools) {
    assert.equal(typeof tool.description, 'string')
    assert.ok(tool.description.length > 20)
    assert.equal(tool.parameters.type, 'object')
    assert.equal(tool.parameters.additionalProperties, false)
    assert.ok(Array.isArray(tool.parameters.required))
    assert.equal(tool.output.schema.type, 'object')
    assert.equal(typeof tool.output.render, 'function')
    assert.equal(typeof tool.execute, 'function')
    const blocks = tool.output.render({}, { ok: true, markdown: '# hi' })
    assert.deepEqual(blocks, [{ type: 'text', text: '# hi' }])
  }
})

test('tools: multi-hop and exe are exposed on parse and frame', () => {
  const parse = createParseTool().parameters.properties
  assert.ok(parse.jumps)
  assert.ok(parse.exe)
  const frame = createFrameTool().parameters.properties
  assert.ok(frame.jumps)
  assert.ok(frame.thread)
  const find = createFindTool().parameters.properties
  assert.ok(find.dirs)
  assert.ok(find.jumps)
})

test('buildScanCommand: dirs are quoted and markers separate the sections', () => {
  const command = buildScanCommand(['/var/crash', "/data/core files"])
  assert.match(command, /@@cdparse:pattern@@/)
  assert.match(command, /@@cdparse:files@@/)
  assert.match(command, /'\/var\/crash'/)
  assert.match(command, /'\/data\/core files'/)
  assert.match(command, /coredumpctl --no-pager list/)
})

test('splitSections: marker blocks become named sections', () => {
  const stdout = [
    'Welcome to prod-db',
    '@@cdparse:pattern@@',
    '/var/lib/systemd/coredump/core.%e.%p',
    '',
    '@@cdparse:files@@',
    '1024 2026-11-02T10:00 /var/crash/core.1',
    '@@cdparse:end@@',
  ].join('\n')
  const sections = splitSections(stdout)
  assert.equal(sections.pattern, '/var/lib/systemd/coredump/core.%e.%p')
  assert.equal(sections.files, '1024 2026-11-02T10:00 /var/crash/core.1')
})

test('parseCoreRows: sorts newest first and keeps paths with spaces', () => {
  const rows = parseCoreRows(
    ['2048 2026-11-02T09:00 /var/crash/core.1', '4096 2026-11-02T11:00 /data/my core.2'].join('\n'),
  )
  assert.equal(rows.length, 2)
  assert.equal(rows[0].path, '/data/my core.2')
  assert.equal(rows[0].sizeBytes, 4096)
  assert.equal(rows[1].path, '/var/crash/core.1')
})

test('renderScan: reports the pattern, coredumpctl and files', () => {
  const markdown = renderScan('prod-1', {
    pattern: '/var/lib/systemd/coredump/core.%e.%p',
    limits: 'unlimited',
    coredumpctl: 'TIME PID COMM',
    files: '1048576 2026-11-02T10:00 /var/crash/core.18422',
  })
  assert.match(markdown, /远端 core 文件：prod-1/)
  assert.match(markdown, /core_pattern/)
  assert.match(markdown, /coredumpctl list/)
  assert.match(markdown, /1\.0MB/)
  assert.match(markdown, /\/var\/crash\/core\.18422/)
})

test('crashRegisters: instruction operands come first, arch defaults follow', () => {
  const registers = { rax: '0x0', rdi: '0x0', rip: '0x4012ab', rsp: '0x7ff...', rbx: '0x60e010' }
  const picked = crashRegisters(registers, { text: 'mov (%rax),%eax' }, 'x86_64')
  const names = picked.map(item => item.name)
  assert.equal(names[0], 'rax')
  assert.ok(names.includes('rip'))
})

test('renderFrameDetail: renders registers, args, locals, disassembly and source', () => {
  const detail = {
    mode: 'frame',
    thread: 2,
    frame: 1,
    target: { core: '/data/core.18422', exe: '/opt/app/bin/order-server', arch: 'x86_64' },
    currentFrame: {
      index: 1,
      address: '0x4017c2',
      symbol: 'worker_loop',
      source: { file: '/src/worker.cpp', line: 88 },
      module: '/opt/app/bin/order-server',
    },
    frameInfo: { pc: '0x4017c2' },
    registers: { rip: '0x4017c2', rsp: '0x7ffffffdf80' },
    args: [{ name: 'ctx', value: '0x60e010', truncated: false }],
    locals: [{ name: 'worker', value: '{id = 1}', truncated: true }],
    disassembly: [{ address: '0x4017c2', symbol: 'worker_loop+34', text: 'call 0x401290', current: true }],
    source: { file: '/src/worker.cpp', lines: [{ number: 88, text: '}', current: true }] },
    diagnostics: [{ code: 'SOURCE_UNAVAILABLE', severity: 'info', message: 'x' }],
  }
  const markdown = renderFrameDetail(detail, { host: 'prod-1' })
  assert.match(markdown, /帧详情：线程 2 #1/)
  assert.match(markdown, /ctx = 0x60e010/)
  assert.match(markdown, /结构体已截断/)
  assert.match(markdown, /call 0x401290/)
  assert.match(markdown, />   88 {2}}/)
  assert.match(markdown, /SOURCE_UNAVAILABLE/)
})

test('threadTrace: prefers application frames over libc frames', () => {
  const thread = {
    frames: [
      { index: 0, symbol: '??', unresolved: true, source: null },
      { index: 1, symbol: 'clock_nanosleep', unresolved: false, source: null },
      { index: 2, symbol: 'waiter', unresolved: false, source: { file: 'crash.c', line: 11 } },
    ],
  }
  assert.equal(threadTrace(thread), 'waiter at crash.c:11')
})

test('threadTrace: falls back to raw frames when no source exists', () => {
  const thread = {
    frames: [
      { index: 0, symbol: '??', unresolved: true, source: null },
      { index: 1, symbol: 'epoll_wait', unresolved: false, source: null },
    ],
  }
  assert.equal(threadTrace(thread), '?? ← epoll_wait')
  assert.equal(threadTrace({ frames: [] }), '无栈帧')
})

test('renderMarkdown: other-thread summary shows the app frame', () => {
  const markdown = renderMarkdown({
    schemaVersion: 1,
    ok: true,
    target: { core: '/tmp/core.1', exe: '/tmp/crash', arch: 'x86_64' },
    signal: { name: 'SIGSEGV', description: 'Segmentation fault' },
    crashThread: 1,
    threads: [
      { id: 1, current: true, frames: [{ index: 0, symbol: 'crash_here', address: '0x1', args: 'ptr=0x0', source: null, unresolved: false }] },
      {
        id: 2,
        lwp: 4361,
        frames: [
          { index: 0, symbol: '??', unresolved: true, source: null },
          { index: 5, symbol: 'waiter', unresolved: false, source: { file: 'crash.c', line: 11 } },
        ],
      },
    ],
    modules: [],
    diagnostics: [],
  })
  assert.match(markdown, /#2 \(LWP 4361\).*waiter at crash\.c:11/)
})

test('renderMarkdown: untrusted report is called out before the stack', () => {
  const markdown = renderMarkdown({
    schemaVersion: 1,
    ok: true,
    trusted: false,
    target: { core: '/tmp/core.1', arch: 'x86_64' },
    signal: { name: 'SIGSEGV', description: 'Segmentation fault' },
    crashThread: 1,
    threads: [],
    modules: [],
    diagnostics: [{ code: 'EXE_MISMATCH', severity: 'error', message: 'x' }],
  })
  assert.match(markdown, /core 与可执行文件不匹配（EXE_MISMATCH）：下面的栈不可信/)
})

test('renderFailure: keeps the actionable code and hint', () => {
  const markdown = renderFailure(
    { host: 'prod-1', core: '/data/core.1' },
    { code: 'GDB_MISSING', message: '主机上没有 gdb。', hint: '安装 gdb。' },
  )
  assert.match(markdown, /GDB_MISSING/)
  assert.match(markdown, /主机上没有 gdb/)
  assert.match(markdown, /安装 gdb/)
})

test('tool-kit: coerces model-supplied scalars', () => {
  assert.equal(toInt('40', 12, 1, 100), 40)
  assert.equal(toInt('nope', 12, 1, 100), 12)
  assert.equal(toInt(500, 12, 1, 100), 100)
  assert.deepEqual(toArray('a, b'), ['a, b'])
  assert.deepEqual(toArray([' a ', '', 'b']), ['a', 'b'])
  assert.deepEqual(toArray(undefined), [])
})

test('tool-kit: finish drops undefined fields (lossless JSON only)', () => {
  assert.deepEqual(finish({ ok: true, signal: undefined, reportPath: 'x' }), { ok: true, reportPath: 'x' })
})

test('tool-kit: jumps accept both "a,b" and ["a","b"]', () => {
  assert.deepEqual(sshOptions({ host: 'x', jumps: 'bastion,ops@jump2:2222' }).jumps, [
    'bastion',
    'ops@jump2:2222',
  ])
  assert.deepEqual(sshOptions({ host: 'x', jumps: ['bastion', 'b'] }).jumps, ['bastion', 'b'])
  assert.deepEqual(sshOptions({ host: 'x' }).jumps, [])
})
