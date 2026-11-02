import test from 'node:test'
import assert from 'node:assert/strict'
import os from 'node:os'

import { buildRemoteCommand, buildSshArgs, classifySshError, expandHome, shellQuote } from '../lib/ssh.js'
import { parseEngineOutput, clip } from '../lib/output.js'

test('buildSshArgs: alias, multi-hop, port, user merge', () => {
  const args = buildSshArgs({
    host: 'prod-db',
    user: 'deploy',
    port: 2200,
    jumps: ['jump-1', 'user@jump-2:2222'],
  })
  assert.equal(args[args.length - 1], 'deploy@prod-db')
  const portIndex = args.indexOf('-p')
  assert.ok(portIndex > -1)
  assert.equal(args[portIndex + 1], '2200')
  const jumpIndex = args.indexOf('-J')
  assert.ok(jumpIndex > -1)
  assert.equal(args[jumpIndex + 1], 'jump-1,user@jump-2:2222')
  assert.ok(args.includes('BatchMode=yes'))
  assert.ok(args.includes('StrictHostKeyChecking=accept-new'))
})

test('buildSshArgs: host already carrying user@ is left alone', () => {
  const args = buildSshArgs({ host: 'ops@10.0.0.8', user: 'deploy' })
  assert.equal(args[args.length - 1], 'ops@10.0.0.8')
})

test('expandHome: only a leading tilde is expanded, remote paths untouched', () => {
  assert.equal(expandHome('~'), os.homedir())
  // path.join uses the platform separator, so compare in normalized form.
  assert.ok(expandHome('~/.ssh/id_ed25519').replace(/\\/g, '/').endsWith('.ssh/id_ed25519'))
  assert.ok(!expandHome('~/.ssh/id_ed25519').startsWith('~'))
  assert.equal(expandHome('/root/core.1'), '/root/core.1')
  assert.equal(expandHome('C:\\keys\\id'), 'C:\\keys\\id')
})

test('buildSshArgs: an identityFile with ~ reaches ssh expanded', () => {
  const args = buildSshArgs({ host: 'prod-db', identityFile: '~/.ssh/id_ed25519' })
  const index = args.indexOf('-i')
  assert.ok(index > -1)
  assert.ok(!args[index + 1].startsWith('~'))
})

test('shellQuote: single quotes survive the remote shell', () => {
  assert.equal(shellQuote("a'b"), "'a'\\''b'")
  assert.equal(shellQuote('/data/core.1234'), "'/data/core.1234'")
})

test('buildRemoteCommand: engine on stdin, args after the dash', () => {
  const command = buildRemoteCommand({
    python: 'python3',
    core: '/data/core with space/core.18422',
    exe: '/opt/app/bin/order-server',
    symbolDirs: ['/usr/lib/debug', '/opt/sym'],
    maxFrames: 40,
    remoteTimeout: 95,
  })
  assert.equal(
    command,
    "python3 - --core '/data/core with space/core.18422' --exe '/opt/app/bin/order-server' " +
      "--symbol-dirs '/usr/lib/debug:/opt/sym' --max-frames 40 --timeout 95",
  )
})

test('parseEngineOutput: skips an ssh banner and finds the JSON line', () => {
  const stdout = [
    'Welcome to prod-db',
    '{"schemaVersion":1,"ok":true,"signal":{"name":"SIGSEGV"}}',
    '',
  ].join('\n')
  assert.equal(parseEngineOutput(stdout).signal.name, 'SIGSEGV')
})

test('parseEngineOutput: garbage yields undefined', () => {
  assert.equal(parseEngineOutput('not json at all\n'), undefined)
  assert.equal(parseEngineOutput(''), undefined)
})

test('classifySshError: maps the common failure modes', () => {
  assert.equal(classifySshError('Permission denied (publickey).').code, 'SSH_AUTH_FAILED')
  assert.equal(classifySshError('Host key verification failed.').code, 'SSH_HOSTKEY')
  assert.equal(classifySshError('ssh: Could not resolve hostname x').code, 'SSH_UNREACHABLE')
  assert.equal(classifySshError('Connection refused').code, 'SSH_UNREACHABLE')
})

test('clip: keeps short text, ellipsizes long text', () => {
  assert.equal(clip('abc', 10), 'abc')
  assert.equal(clip('abcdefghij', 5), 'abcd…')
})
