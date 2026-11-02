/**
 * Path and environment resolution for the plugin.
 *
 * The engine ships INSIDE the package (engine/cdparse.py) and is streamed to the
 * remote host over ssh stdin, so the remote side needs no installation step and
 * its version is always the one this plugin was built with.
 */

import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

/** Package root (…/dsh-coredump/). */
export const PACKAGE_ROOT = fileURLToPath(new URL('..', import.meta.url))

/** DSH home directory, matching the host process' own resolution. */
export function dshHome() {
  return process.env.DSH_HOME || path.join(os.homedir(), '.dsh')
}

/** Absolute path of the remote engine script. */
export function engineScriptPath() {
  return path.join(PACKAGE_ROOT, 'engine', 'cdparse.py')
}

/** Remote interpreter. Older RHEL images ship python3.6 only; that is enough. */
export const DEFAULT_PYTHON = process.env.DSH_COREDUMP_PYTHON || 'python3'
