# Changelog

All notable changes to this package are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
semantic versioning with a 0.x line.

## 0.3.0 — 2026-11-02

### Added

- **Web GUI panel** (`main` key `coredump`, opened from its sidebar icon):
  host / core / executable / key inputs, core scan, thread list, stack frames,
  single-frame detail (registers, arguments, locals, disassembly, source window),
  diagnostics and module list, recent entries in `localStorage`.
- Browser routes `/api/dsh-coredump/{find,parse,frame}`; loopback-only fence
  (socket address + `Host` header + same-origin markers).
- `coredump_find` tool: `core_pattern`, `ulimit -c`, `coredumpctl list`, and
  cores under the usual directories — no gdb involved.
- Crash scene in the parse report: faulting instruction, disassembly context,
  and the registers the instruction mentions.
- `coredump_frame` tool: one frame in depth.
- Locale dictionaries (`zh`, `en`), plugin icon and metadata.
- `LICENSE` (Apache-2.0), CI workflow, release/packaging scripts.

### Changed

- Host half imports **no** `@deepseek-ai/*` package: a workspace-linked plugin
  cannot resolve them from its real path. Tool schemas are built locally in
  `lib/tool-kit.js`, which is also why the plugin mounts when installed by link.
- `readelf` NT_FILE parsing accepts both the path-on-next-line and
  path-on-same-line layouts.
- gdb thread headers accept both `Thread N (Thread 0x.. (LWP M))` and
  `Thread N (LWP M)`; parse errors emitted on stderr are now part of diagnosis.
- Module symbol state for the main executable is derived from `.symtab`.

### Fixed

- Build-id mismatch (`EXE_MISMATCH`) is now detected from gdb stderr and marks
  the report untrusted instead of silently printing a wrong stack.
- A non-existent frame no longer reports the fallback frame as if it were the
  requested one (`FRAME_NOT_FOUND`, header says which frame is shown).
- `~` in `identityFile` is expanded; the field is documented as a key path,
  not a password.

## 0.2.0 — 2026-11-02

### Added

- Remote engine `engine/cdparse.py` streamed over ssh stdin (gdb `-batch`,
  no remote installation).
- `coredump_parse` tool: signal, all thread stacks, modules/build-ids,
  diagnostics, saved JSON report.

## 0.1.0 — 2026-11-01

### Added

- Initial plugin skeleton and SSH transport (aliases, jump hosts, agent keys).
