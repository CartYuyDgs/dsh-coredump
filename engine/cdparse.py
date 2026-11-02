#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cdparse — coredump 解析与归一化引擎。

运行在目标 Linux 主机上（Python 3.6+，只依赖 gdb / readelf），把 ELF core 解析成
schemaVersion=1 的 JSON，由 dsh-coredump 插件渲染；也可独立当命令行工具用：

    python3 cdparse.py --core /data/core.1234 --exe /opt/app/bin/server
    python3 cdparse.py --core C --exe E --json-out report.json
    python3 cdparse.py --from-gdb-output captured.txt --core C   # 离线回放

被插件调用时脚本从 stdin 送进来：

    ssh host python3 - --core C --exe E < cdparse.py

设计约束（改代码前先读一遍）：
- 永远输出「数据」，不靠异常：失败也输出 {"ok": false, "error": {...}} 并退出 0。
- 只做解析与归一化，不做归因；信任问题全部落到 diagnostics 里。
- 输出大小可控：线程帧数限制、模块数限制、原始 gdb 文本默认不外传。
- Python 3.6 兼容：不用 dataclasses / walrus / capture_output / text= True。
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

SCHEMA_VERSION = 1
ENGINE_VERSION = "0.2.0"
DEFAULT_MAX_FRAMES = 40
MAX_MODULES = 40
MAX_GDB_OUTPUT = 64 * 1024 * 1024
DEFAULT_TIMEOUT = 120
MAX_LOCALS = 40
MAX_ARG_LINES = 20
MAX_SOURCE_LINES = 24
MAX_DISASM = 40

# gdb 不打印分隔符，各段靠这些标记切分；用 printf 保证老 gdb 也认。
MARK = "@@cdparse:%s@@"


def mark(name):
    return 'printf "\\n' + (MARK % name) + '\\n"'

# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------


class CmdResult(object):
    __slots__ = ("rc", "out", "err", "timed_out")

    def __init__(self, rc, out, err, timed_out=False):
        self.rc = rc
        self.out = out
        self.err = err
        self.timed_out = timed_out


def _decode(data):
    return data.decode("utf-8", "replace")


def run(cmd, timeout, stdin_data=None):
    """跑一个子进程，返回 CmdResult。stdin 永远显式给 DEVNULL（gdb 不能抢我们的 stdin）。"""
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        return CmdResult(127, "", str(exc), False)
    try:
        if stdin_data is not None:
            out, err = proc.communicate(stdin_data, timeout=timeout)
        else:
            out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return CmdResult(124, _decode(out), _decode(err), True)
    return CmdResult(proc.returncode, _decode(out), _decode(err), False)


def diag(code, severity, message, hint=None):
    item = {"code": code, "severity": severity, "message": message}
    if hint:
        item["hint"] = hint
    return item


def write_json(payload):
    """始终按 UTF-8 写 stdout：远端 sshd 的 LANG 可能是 C/ASCII，不能靠 locale。"""
    data = json.dumps(payload, ensure_ascii=False) + "\n"
    stream = getattr(sys.stdout, "buffer", None)
    if stream is not None:
        stream.write(data.encode("utf-8"))
        stream.flush()
    else:  # 被别的宿主嵌进来时（无 buffer 的 StringIO）
        sys.stdout.write(data)


def emit(payload, exit_code=0):
    write_json(payload)
    sys.exit(exit_code)


def fail(code, message, hint=None, extra=None):
    payload = {
        "schemaVersion": SCHEMA_VERSION,
        "ok": False,
        "engine": {"name": "cdparse", "version": ENGINE_VERSION},
        "error": diag(code, "error", message, hint),
    }
    if extra:
        payload.update(extra)
    emit(payload)


# --------------------------------------------------------------------------
# readelf 探测（带缓存，模块多的时候别重复跑）
# --------------------------------------------------------------------------

_READELF_CACHE = {}


def readelf(args, timeout=30):
    key = tuple(args)
    cached = _READELF_CACHE.get(key)
    if cached is not None:
        return cached
    result = run(["readelf"] + list(args), timeout)
    _READELF_CACHE[key] = result
    return result


_ARCH_MAP = [
    ("X86-64", "x86_64"),
    ("AArch64", "aarch64"),
    ("ARM", "arm"),
    ("Intel 80386", "i386"),
    ("PowerPC64", "ppc64"),
    ("PowerPC", "ppc"),
    ("RISC-V", "riscv64"),
    ("IBM S/390", "s390x"),
    ("MIPS", "mips"),
    ("LoongArch", "loongarch64"),
]


def normalize_arch(machine_line):
    for needle, name in _ARCH_MAP:
        if needle in machine_line:
            return name
    return machine_line.strip() or "unknown"


def readelf_arch(path):
    result = readelf(["-h", path])
    if result.rc != 0:
        return None
    match = re.search(r"Machine:\s*(.+?)\s*$", result.out, re.MULTILINE)
    if not match:
        return None
    return normalize_arch(match.group(1))


def readelf_build_id(path):
    result = readelf(["-n", path])
    if result.rc != 0:
        return None
    match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", result.out)
    return match.group(1) if match else None


def debug_file_for(build_id):
    if not build_id or len(build_id) < 3:
        return None
    candidate = "/usr/lib/debug/.build-id/%s/%s.debug" % (build_id[:2], build_id[2:])
    return candidate if os.path.isfile(candidate) else None


_MAPPING_RE = re.compile(
    r"^\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(\S.*?)\s*$"
)
# 新版 readelf 把路径单独放下一行：`0xstart 0xend 0xoffset` 然后一行路径。
_MAPPING_ADDRS_RE = re.compile(
    r"^\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s*$"
)


def parse_mappings(text):
    """从 `readelf -n` 文本里解析 NT_FILE 映射表（兼容新旧两种排版）。"""
    mappings = []
    in_block = False
    pending = None
    for line in text.splitlines():
        if "NT_FILE" in line or "Mapped address spaces" in line:
            in_block = True
            pending = None
            continue
        if not in_block:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("Page size"):
            continue
        match = _MAPPING_RE.match(line)
        if match:
            mappings.append(
                {
                    "start": match.group(1),
                    "end": match.group(2),
                    "offset": match.group(3),
                    "path": match.group(4),
                }
            )
            pending = None
            continue
        match = _MAPPING_ADDRS_RE.match(line)
        if match:
            pending = {
                "start": match.group(1),
                "end": match.group(2),
                "offset": match.group(3),
                "path": None,
            }
            continue
        if pending is not None and not stripped.startswith("0x"):
            pending["path"] = stripped
            mappings.append(pending)
            pending = None
    return [item for item in mappings if item["path"]]


def core_mappings(core):
    """从 NT_FILE 注记里取 core 的地址空间映射（gdb 之外的第二来源）。"""
    result = readelf(["-n", core], timeout=60)
    if result.rc != 0:
        return []
    return parse_mappings(result.out)


# --------------------------------------------------------------------------
# gdb 输出解析
# --------------------------------------------------------------------------

THREAD_BT_RE = re.compile(
    r'^Thread\s+(\d+)(?:\s+"([^"]*)")?\s+\(Thread\s+(0x[0-9a-fA-F]+)\s+\(LWP\s+(\d+)\)\):\s*$'
)
# gdb 在 exe 不匹配 / 无符号时不给 Thread 指针，只打印 `Thread 2 (LWP 4361):`
THREAD_BT_ALT_RE = re.compile(
    r'^Thread\s+(\d+)(?:\s+"([^"]*)")?\s+\(LWP\s+(\d+)\):\s*$'
)
THREAD_INFO_RE = re.compile(
    r'^\s*(\*?)\s*(\d+)\s+Thread\s+(0x[0-9a-fA-F]+)\s+\(LWP\s+(\d+)\)(?:\s+"([^"]*)")?\s*(.*)$'
)
# 同上：`* 1    LWP 4360          0x... in ?? ()`
THREAD_INFO_ALT_RE = re.compile(
    r'^\s*(\*?)\s*(\d+)\s+LWP\s+(\d+)(?:\s+"([^"]*)")?\s*(.*)$'
)
FRAME_RE = re.compile(r"^#(\d+)\s+(.*)$")
SIGNAL_RE = re.compile(r"Program terminated with signal (\w+), (.+?)\s*$", re.MULTILINE)
GENERATED_BY_RE = re.compile(r"Core was generated by `(.+?)'\.")
SHARED_RE = re.compile(
    r"^(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(Yes|No)(\s*\(\*\))?\s+(\S+)\s*$"
)
REG_RE = re.compile(r"^([a-z][a-z0-9]*)\s+(0x[0-9a-fA-F]+)\b")


def parse_signal(text):
    match = SIGNAL_RE.search(text)
    if not match:
        return None
    description = match.group(2).strip()
    if description.endswith("."):
        description = description[:-1]
    return {"name": match.group(1), "description": description}


def parse_generated_by(text):
    match = GENERATED_BY_RE.search(text)
    return match.group(1) if match else None


def split_symbol(text):
    """把 `func (a=1, b=2)` 拆成 (func, args)；C++ 模板里的尖括号和嵌套括号都要照顾到。"""
    text = text.strip()
    if text.endswith(")"):
        depth = 0
        for i in range(len(text) - 1, -1, -1):
            ch = text[i]
            if ch == ")":
                depth += 1
            elif ch == "(":
                depth -= 1
                if depth == 0:
                    return text[:i].strip(), text[i + 1 : -1]
    return text, None


def parse_frame(line):
    match = FRAME_RE.match(line)
    if not match:
        return None
    frame = {
        "index": int(match.group(1)),
        "address": None,
        "symbol": None,
        "args": None,
        "source": None,
        "module": None,
        "unresolved": False,
        "signalHandler": False,
    }
    rest = match.group(2).strip()
    if rest.startswith("<") and rest.endswith(">"):
        frame["symbol"] = rest
        frame["signalHandler"] = rest == "<signal handler called>"
        return frame

    address = re.match(r"^(0x[0-9a-fA-F]+)\s+in\s+(.*)$", rest)
    if address:
        frame["address"] = address.group(1)
        rest = address.group(2)
    elif rest.startswith("in "):
        rest = rest[3:]

    source = re.search(r"\s+at\s+(.+):(\d+)\s*$", rest)
    if source:
        frame["source"] = {"file": source.group(1).strip(), "line": int(source.group(2))}
        rest = rest[: source.start()]

    module = re.search(r"\s+from\s+(\S+)\s*$", rest)
    if module:
        frame["module"] = module.group(1)
        rest = rest[: module.start()]

    symbol, args = split_symbol(rest)
    frame["symbol"] = symbol
    frame["args"] = args
    if symbol in ("??", "", None):
        frame["unresolved"] = True
        frame["symbol"] = "??"
    return frame


def parse_thread_blocks(text):
    """把 `thread apply all bt` 的输出切成 {线程号: [帧行]}，保持出现顺序。"""
    blocks = {}
    order = []
    current = None
    for line in text.splitlines():
        header = THREAD_BT_RE.match(line) or THREAD_BT_ALT_RE.match(line)
        if header:
            current = int(header.group(1))
            if current not in blocks:
                blocks[current] = []
                order.append(current)
            continue
        if current is None:
            continue
        if line.startswith("#"):
            blocks[current].append(line)
        elif line.strip() == "":
            continue
        else:
            # 遇到下一段（info threads / info registers ...）就封口
            current = None
    return blocks, order


def parse_thread_info(text):
    infos = {}
    for line in text.splitlines():
        match = THREAD_INFO_RE.match(line)
        if match:
            tid = int(match.group(2))
            infos[tid] = {
                "id": tid,
                "lwp": int(match.group(4)),
                "name": match.group(5),
                "current": match.group(1) == "*",
                "pc": None,
            }
            rest = match.group(6)
        else:
            match = THREAD_INFO_ALT_RE.match(line)
            if not match:
                continue
            tid = int(match.group(2))
            infos[tid] = {
                "id": tid,
                "lwp": int(match.group(3)),
                "name": match.group(4),
                "current": match.group(1) == "*",
                "pc": None,
            }
            rest = match.group(5)
        pc = re.search(r"(0x[0-9a-fA-F]+)\s+in\s", rest)
        if pc:
            infos[tid]["pc"] = pc.group(1)
    return infos


def parse_registers(text):
    regs = {}
    for line in text.splitlines():
        match = REG_RE.match(line)
        if not match:
            continue
        regs[match.group(1)] = match.group(2)
        if len(regs) >= 64:
            break
    return regs


def parse_shared_libraries(text):
    libs = []
    for line in text.splitlines():
        match = SHARED_RE.match(line)
        if not match:
            continue
        libs.append(
            {
                "from": match.group(1),
                "to": match.group(2),
                "symbolsLoaded": match.group(3) == "Yes",
                "path": match.group(5),
            }
        )
    return libs


MARKER_RE = re.compile(r"^\s*@@cdparse:(\w+)@@\s*$")
DISASM_RE = re.compile(r"^(=>)?\s*(0x[0-9a-fA-F]+)\s*(?:<([^>]*)>)?\s*:\s*(.*)$")
ASSIGN_RE = re.compile(r"^([A-Za-z_$][\w$]*(?:\[[^\]]*\])?(?:\.\w+)*)\s*=\s*(.*)$")


def split_sections(text):
    """按 @@cdparse:name@@ 标记把 gdb 输出切成 dict（标记前的丢弃）。"""
    sections = {}
    current = None
    buffer = []
    for line in text.splitlines():
        match = MARKER_RE.match(line)
        if match:
            if current is not None:
                sections[current] = "\n".join(buffer)
            current = match.group(1)
            buffer = []
        elif current is not None:
            buffer.append(line)
    if current is not None:
        sections[current] = "\n".join(buffer)
    return sections


def parse_disassembly(text, limit=MAX_DISASM):
    items = []
    for line in text.splitlines():
        match = DISASM_RE.match(line)
        if not match:
            continue
        items.append(
            {
                "address": match.group(2),
                "symbol": (match.group(3) or None),
                "text": match.group(4).strip(),
                "current": match.group(1) == "=>",
            }
        )
        if len(items) >= limit:
            break
    return items


def crash_instruction(disassembly):
    for item in disassembly:
        if item["current"]:
            return item
    return disassembly[0] if disassembly else None


def parse_assignments(text, limit):
    """解析 `info args` / `info locals`：`name = value`，多行结构只留首行。"""
    values = []
    for raw in text.splitlines():
        if not raw.strip() or raw.strip().startswith("No symbols"):
            continue
        match = ASSIGN_RE.match(raw.strip())
        if not match:
            continue
        value = match.group(2).strip()
        truncated = value.endswith("{") or value.endswith("[") or value.startswith("{")
        values.append(
            {
                "name": match.group(1),
                "value": value[:200],
                "truncated": bool(truncated),
            }
        )
        if len(values) >= limit:
            break
    return values


def parse_source(text, current_line=None):
    """解析 `list` 的输出：`行号\\t源码`，顺便按行号标出当前行。"""
    file_path = None
    lines = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        header = re.match(r"^File:\s+(.+)$", stripped)
        if header:
            file_path = header.group(1).strip()
            continue
        match = re.match(r"^(\d+)\s*\t\s*(.*)$", raw)
        if not match:
            match = re.match(r"^(\d+)\s+(\S.*)$", stripped)
        if not match:
            continue
        number = int(match.group(1))
        lines.append(
            {
                "number": number,
                "text": match.group(2)[:200],
                "current": number == current_line,
            }
        )
        if len(lines) >= MAX_SOURCE_LINES:
            break
    return {"file": file_path, "lines": lines}


def parse_frame_info(text):
    info = {"pc": None, "symbol": None, "caller": None}
    # x86_64 打印 `rip = ...`，aarch64 打印 `pc = ...`，都要认。
    match = re.search(r"\b(?:rip|pc)\s*=\s*(0x[0-9a-fA-F]+)\s+in\s+([^\n(]+)", text)
    if match:
        info["pc"] = match.group(1)
        info["symbol"] = match.group(2).strip()
    caller = re.search(r"caller of frame at\s+(0x[0-9a-fA-F]+)", text)
    if caller:
        info["caller"] = caller.group(1)
    return info


# --------------------------------------------------------------------------
# 地址 -> 模块
# --------------------------------------------------------------------------


def to_int(value):
    try:
        return int(value, 16)
    except (TypeError, ValueError):
        return None


def resolve_module(address, mappings):
    addr = to_int(address)
    if addr is None:
        return None
    for mapping in mappings:
        start = to_int(mapping["start"])
        end = to_int(mapping["end"])
        if start is not None and end is not None and start <= addr < end:
            return mapping["path"]
    return None


# --------------------------------------------------------------------------
# 分析
# --------------------------------------------------------------------------


def readelf_sections(path):
    result = readelf(["-S", path])
    return result.out if result.rc == 0 else ""


def has_symtab(path):
    """有 .symtab 才能把地址解析成函数名（.debug_info 只影响行号/变量）。"""
    return ".symtab" in readelf_sections(path)


def build_module(path, probe=True):
    info = {
        "path": path,
        "symbolsLoaded": None,
        "buildId": None,
        "arch": None,
        "debugFile": None,
        "exists": None,
        "symtab": None,
    }
    if probe:
        info["exists"] = os.path.isfile(path)
        if info["exists"]:
            info["arch"] = readelf_arch(path)
            info["buildId"] = readelf_build_id(path)
            info["debugFile"] = debug_file_for(info["buildId"])
            info["symtab"] = has_symtab(path)
    return info


def analyze(text, options):
    """把 gdb 输出归一化成报告。纯函数（只读文件系统探测 build-id），方便离线回测。"""
    max_frames = options.get("max_frames", DEFAULT_MAX_FRAMES)
    probe = options.get("probe", True)
    mappings = options.get("mappings") or []
    core = options.get("core")
    exe = options.get("exe")
    generated_by = parse_generated_by(text)

    diagnostics = []
    signal = parse_signal(text)
    infos = parse_thread_info(text)
    blocks, order = parse_thread_blocks(text)

    # gdb 把 warning（exe 不匹配、core 截断）写到 stderr，必须一起看，
    # 否则会给出一份「看起来正常」的错栈。
    stderr = options.get("stderr") or ""
    diag_text = text + "\n" + stderr if stderr else text

    mismatch = "may not match" in diag_text or "does not match" in diag_text
    if mismatch:
        diagnostics.append(
            diag(
                "EXE_MISMATCH",
                "error",
                "core 与指定的可执行文件/A/符号不匹配，栈可能不可信。",
                "用产生这个 core 的那次构建产物重跑，或先确认 build-id。",
            )
        )
    if "is truncated" in diag_text or "unexpected end of file" in diag_text:
        diagnostics.append(
            diag(
                "CORE_TRUNCATED",
                "warn",
                "core 文件不完整（截断），部分线程/内存无法读取。",
                "检查 core 大小与 ulimit / core_pattern 的落盘策略。",
            )
        )
    if "no debugging symbols found" in diag_text:
        diagnostics.append(
            diag(
                "NO_DEBUG_SYMBOLS",
                "warn",
                "可执行文件没有调试符号，函数名可能缺失或只有地址。",
                "安装对应 build-id 的 -debuginfo 包，或把 .debug 放到 /usr/lib/debug。",
            )
        )

    threads = []
    if blocks:
        for tid in order:
            frames = []
            truncated = False
            for line in blocks[tid]:
                frame = parse_frame(line)
                if frame is None:
                    continue
                if frame["module"] is None and frame["address"]:
                    frame["module"] = resolve_module(frame["address"], mappings)
                frames.append(frame)
            if len(frames) >= max_frames:
                truncated = True
            info = infos.get(tid, {})
            threads.append(
                {
                    "id": tid,
                    "lwp": info.get("lwp"),
                    "name": info.get("name"),
                    "current": bool(info.get("current")),
                    "frames": frames,
                    "truncated": truncated,
                }
            )
    elif infos:
        for tid in sorted(infos.keys()):
            info = infos[tid]
            threads.append(
                {
                    "id": tid,
                    "lwp": info.get("lwp"),
                    "name": info.get("name"),
                    "current": info.get("current"),
                    "frames": [],
                    "truncated": False,
                }
            )

    crash_id = None
    for thread in threads:
        if thread["current"]:
            crash_id = thread["id"]
            break
    if crash_id is None and threads:
        crash_id = threads[0]["id"]

    if signal and crash_id is not None:
        crash_thread = next((t for t in threads if t["id"] == crash_id), None)
        if crash_thread is not None and len(crash_thread["frames"]) == 0:
            diagnostics.append(
                diag("CRASH_THREAD_EMPTY", "warn", "崩溃线程没有解析出任何栈帧。")
            )
    if not threads:
        diagnostics.append(
            diag(
                "NO_THREADS",
                "warn",
                "没有解析到线程栈，可能是 core 不完整或 gdb 输出被截断。",
            )
        )
    for thread in threads:
        if thread["truncated"]:
            diagnostics.append(
                diag(
                    "FRAMES_TRUNCATED",
                    "info",
                    "线程 %s 的栈深度超过上限（%d 帧），更深帧未展开。"
                    % (thread["id"], max_frames),
                    "把 maxFrames 调大后重跑。",
                )
            )
            break

    sections = split_sections(text)
    registers = parse_registers(sections.get("reg", text))
    disassembly = parse_disassembly(sections.get("disasm", ""))
    instruction = crash_instruction(disassembly)

    modules = []
    seen = set()
    exe_path = exe
    if exe_path is None and generated_by:
        first = generated_by.split(" ")[0]
        if first:
            exe_path = first
    if exe_path:
        modules.append(build_module(exe_path, probe))
        seen.add(exe_path)
    for lib in parse_shared_libraries(text):
        if lib["path"] in seen:
            # exe 也会出现在 info sharedlibrary 里：以 gdb 的 Syms Read 为准。
            for module in modules:
                if module["path"] == lib["path"]:
                    module["symbolsLoaded"] = lib["symbolsLoaded"]
            continue
        seen.add(lib["path"])
        module = build_module(lib["path"], probe)
        module["symbolsLoaded"] = lib["symbolsLoaded"]
        modules.append(module)

    if len(modules) > MAX_MODULES:
        modules = modules[:MAX_MODULES]
        diagnostics.append(
            diag(
                "MODULES_TRUNCATED",
                "info",
                "模块超过 %d 个，只保留前 %d 个。" % (MAX_MODULES, MAX_MODULES),
            )
        )

    for module in modules:
        # 主可执行文件不会出现在 info sharedlibrary 里，符号状态用 .symtab 判定。
        if module["symbolsLoaded"] is None and module["symtab"] is not None:
            module["symbolsLoaded"] = bool(module["symtab"])
        module.pop("symtab", None)

    for module in modules:
        if module["symbolsLoaded"] is False:
            hint = "安装 %s 对应的 debuginfo" % os.path.basename(module["path"])
            if module["buildId"]:
                hint = "找 build-id %s 的 debug 文件（/usr/lib/debug/.build-id/%s/%s.debug）" % (
                    module["buildId"],
                    module["buildId"][:2],
                    module["buildId"][2:],
                )
            diagnostics.append(
                diag(
                    "SYMBOL_MISSING",
                    "warn",
                    "模块没有加载符号：%s" % module["path"],
                    hint,
                )
            )
        elif module["exists"] is False and module["symbolsLoaded"] is None:
            diagnostics.append(
                diag(
                    "MODULE_NOT_FOUND",
                    "info",
                    "模块文件在主机上不存在：%s（core 来自容器或已删版本）"
                    % module["path"],
                    "把产物放到同路径，或用 --symbol-dirs 指到符号目录。",
                )
            )

    if generated_by and exe:
        generated_exe = generated_by.split(" ")[0]
        if os.path.basename(generated_exe) != os.path.basename(exe):
            diagnostics.append(
                diag(
                    "EXE_FROM_CORE",
                    "info",
                    "core 由 `%s` 生成，与传入的 exe 不是同一个文件名。" % generated_by,
                    "确认你传的是崩溃那一次的产物。",
                )
            )

    report = {
        "schemaVersion": SCHEMA_VERSION,
        "ok": True,
        "engine": {"name": "cdparse", "version": ENGINE_VERSION},
        "target": {
            "core": core,
            "exe": exe_path,
            "generatedBy": generated_by,
            "arch": options.get("arch"),
            "coreArch": options.get("core_arch"),
        },
        "signal": signal,
        "crashThread": crash_id,
        "trusted": not mismatch,
        "crash": {
            "thread": crash_id,
            "instruction": instruction,
            "disassembly": disassembly,
            "registersThread": crash_id,
        },
        "threads": threads,
        "registers": registers,
        "modules": modules,
        "mappings": {
            "count": len(mappings),
            "sample": mappings[:20],
        },
        "diagnostics": diagnostics,
        "limits": {
            "maxFramesPerThread": max_frames,
            "gdbOutputBytes": len(text),
        },
    }
    return report


# --------------------------------------------------------------------------
# 单帧深挖
# --------------------------------------------------------------------------


def build_frame_report(text, options):
    """把 --thread/--frame 模式的 gdb 输出归一化成单帧报告。"""
    sections = split_sections(text)
    thread = options.get("thread")
    frame = options.get("frame")
    diagnostics = []

    select_text = sections.get("select", "")
    stderr = options.get("stderr") or ""
    # gdb 的选帧/选线程错误写到 stderr，和 stdout 的标记段一起判定。
    error_text = select_text + "\n" + stderr
    frame_info = parse_frame_info(sections.get("frameinfo", ""))
    missing = re.search(r"(Non-existent|No such|No frame|No stack|Not a valid)", error_text) or re.search(
        r"(No frame|No stack)", sections.get("frameinfo", "")
    )
    if missing:
        # 错误文本里可能夹着整段 stdout；只留第一行有效信息。
        first_line = next(
            (line.strip() for line in error_text.splitlines() if re.search(r"(No frame|No stack|Non-existent|No such)", line)),
            "",
        )
        diagnostics.append(
            diag(
                "FRAME_NOT_FOUND",
                "error",
                "线程 %s 的帧 %s 不存在（%s）。" % (thread, frame, first_line or "gdb 未定位到该帧"),
                "先用 coredump_parse 看线程表与实际帧号，再指定单帧。",
            )
        )

    backtrace = []
    for line in sections.get("bt", "").splitlines():
        if not line.startswith("#"):
            continue
        parsed = parse_frame(line)
        if parsed is not None:
            backtrace.append(parsed)

    current = None
    for line in sections.get("selected", "").splitlines():
        if line.startswith("#"):
            current = parse_frame(line)
            break
    if current is None and backtrace:
        current = backtrace[0]

    # gdb 选帧/选线程失败时不会中止，只会留在原帧：用「实际选中的」兜底判定，
    # 免得把 #0 当成用户要的 #99 报出来。
    if current is not None and frame is not None and current["index"] != frame and not missing:
        diagnostics.append(
            diag(
                "FRAME_NOT_FOUND",
                "error",
                "线程 %s 没有帧 #%s，实际停在 #%d。" % (thread, frame, current["index"]),
                "先用 coredump_parse 看该线程的栈深度，再指定帧号。",
            )
        )
    thread_info = parse_thread_info(sections.get("threadinfo", ""))
    if thread_info and thread not in thread_info:
        diagnostics.append(
            diag(
                "THREAD_NOT_FOUND",
                "error",
                "线程 %s 不存在，实际停在 %s。"
                % (thread, ", ".join("线程 %s" % item for item in sorted(thread_info))),
                "先用 coredump_parse 看线程表。",
            )
        )

    current_line = None
    if current and current.get("source"):
        current_line = current["source"].get("line")
    source = parse_source(sections.get("list", ""), current_line)
    if not source["lines"]:
        diagnostics.append(
            diag(
                "SOURCE_UNAVAILABLE",
                "info",
                "拿不到源码窗口：二进制没有调试信息、源码文件不在主机上，或编译期路径与当前路径不同。",
            )
        )

    for item in [current] if current else []:
        if item.get("unresolved"):
            diagnostics.append(
                diag(
                    "SYMBOL_MISSING",
                    "warn",
                    "该帧没有函数符号：%s" % (item.get("address") or "?"),
                    "安装对应 build-id 的 debuginfo 后重跑。",
                )
            )

    return {
        "schemaVersion": SCHEMA_VERSION,
        "ok": True,
        "mode": "frame",
        "engine": {"name": "cdparse", "version": ENGINE_VERSION},
        "target": {
            "core": options.get("core"),
            "exe": options.get("exe"),
            "arch": options.get("arch"),
        },
        "thread": thread,
        "frame": frame,
        "frameInfo": frame_info,
        "currentFrame": current,
        "registers": parse_registers(sections.get("reg", "")),
        "args": parse_assignments(sections.get("args", ""), MAX_ARG_LINES),
        "locals": parse_assignments(sections.get("locals", ""), MAX_LOCALS),
        "disassembly": parse_disassembly(sections.get("disasm", ""), 20),
        "source": source,
        "backtrace": backtrace,
        "diagnostics": diagnostics,
        "limits": {"gdbOutputBytes": len(text)},
    }


# --------------------------------------------------------------------------
# 采集
# --------------------------------------------------------------------------


def gdb_available():
    return shutil.which("gdb")


def quote_path(path):
    return '"%s"' % path.replace("\\", "\\\\").replace('"', '\\"')


def gdb_commands(core, exe, symbol_dirs, max_frames):
    cmds = [
        "set pagination off",
        "set width 0",
        "set height 0",
        "set confirm off",
        "set print thread-events off",
        "set print demangle on",
        "set print elements 64",
        "set backtrace past-main on",
    ]
    dirs = [d for d in symbol_dirs if d]
    if dirs:
        joined = ":".join(dirs)
        cmds.append("set solib-search-path " + joined)
        cmds.append("set debug-file-directory " + joined)
    if exe:
        cmds.append("file " + quote_path(exe))
    cmds.append("core-file " + quote_path(core))
    # 寄存器必须紧跟 core-file：此时 gdb 选中的就是收到信号的那个线程。
    cmds.append(mark("reg"))
    cmds.append("info registers")
    cmds.append(mark("disasm"))
    cmds.append("x/8i $pc-16")
    cmds.append(mark("threads"))
    cmds.append("info threads")
    cmds.append(mark("bt"))
    cmds.append("thread apply all bt %d" % max_frames)
    cmds.append(mark("shared"))
    cmds.append("info sharedlibrary")
    return cmds


def gdb_frame_commands(core, exe, symbol_dirs, thread, frame, max_frames):
    """单帧深挖：寄存器 / 参数 / 局部变量 / 反汇编 / 源码窗口。"""
    cmds = gdb_commands(core, exe, symbol_dirs, 1)
    # bt 1 段之前插入定位命令：先切线程和帧，后面的 info/print 才是这一帧的。
    insert_at = cmds.index(mark("reg"))
    location = [mark("select"), "thread %d" % thread]
    if frame is not None:
        location.append("frame %d" % frame)
    location.append(mark("threadinfo"))
    location.append("info thread")
    location.append(mark("frameinfo"))
    location.append("info frame")
    cmds[insert_at:insert_at] = location
    # 丢掉整线程栈（单帧模式不需要）和基础反汇编（后面换成 12 条）。
    del cmds[cmds.index(mark("threads")):]
    disasm_at = cmds.index(mark("disasm"))
    del cmds[disasm_at:disasm_at + 2]
    cmds.extend(
        [
            mark("args"),
            "info args",
            mark("locals"),
            "info locals",
            # `bt` 总是从 #0 开始，光靠它认不出当前选中的帧；`frame` 会打印
            # 选中帧本身（`#1  0x... in main ... at f.c:27`）。
            mark("selected"),
            "frame",
            mark("bt"),
            "bt %d" % max_frames,
            mark("disasm"),
            "x/12i $pc-16",
            mark("list"),
            "list",
        ]
    )
    return cmds


def run_gdb(core, exe, symbol_dirs, max_frames, timeout):
    cmd = ["gdb", "-batch", "-nx", "-q"]
    for item in gdb_commands(core, exe, symbol_dirs, max_frames):
        cmd.extend(["-ex", item])
    return run(cmd, timeout)


def run_gdb_frame(core, exe, symbol_dirs, thread, frame, max_frames, timeout):
    cmd = ["gdb", "-batch", "-nx", "-q"]
    for item in gdb_frame_commands(core, exe, symbol_dirs, thread, frame, max_frames):
        cmd.extend(["-ex", item])
    return run(cmd, timeout)


def probe_generated_by(core, timeout):
    """exe 没给时先裸跑一次 gdb，从 'Core was generated by' 里挖出可执行文件路径。"""
    result = run(
        ["gdb", "-batch", "-nx", "-q", "-ex", "core-file " + quote_path(core)],
        min(timeout, 40),
    )
    return parse_generated_by(result.out)


def read_gdb_output(path):
    with open(path, "rb") as handle:
        return _decode(handle.read())


def check_core(core):
    if not os.path.isfile(core):
        fail(
            "CORE_NOT_FOUND",
            "找不到 core 文件：%s" % core,
            "确认路径与读权限（core 通常属于 root 或 systemd-coredump）。",
        )
    if not os.access(core, os.R_OK):
        fail(
            "CORE_UNREADABLE",
            "core 文件不可读：%s" % core,
            "用有权限的账号，或 sudo 后通过插件重新解析。",
        )
    if gdb_available() is None:
        fail(
            "GDB_MISSING",
            "主机上没有 gdb。",
            "安装 gdb（RHEL: yum install gdb），或通过 --from-gdb-output 回放。",
        )


def resolve_exe(args, diagnostics):
    """exe 显式给定的必须存在；从 core 推断出来的不存在时降级为 None。"""
    exe = args.exe
    if exe and not os.path.isfile(exe):
        fail("EXE_NOT_FOUND", "找不到可执行文件：%s" % exe)
    if not exe:
        exe = probe_generated_by(args.core, args.timeout)
        if exe and not os.path.isfile(exe):
            diagnostics.append(
                diag(
                    "EXE_NOT_FOUND",
                    "warn",
                    "core 生成命令里的可执行文件不存在：%s" % exe,
                    "产物可能已被替换或删除；用同批构建产物重跑。",
                )
            )
            exe = None
    return exe


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="coredump 解析与归一化引擎（输出 schemaVersion=1 JSON）"
    )
    parser.add_argument("--core", required=True, help="core 文件路径（远端本机路径）")
    parser.add_argument("--exe", help="可执行文件路径；省略时从 core 的 NT_PRPSINFO 推断")
    parser.add_argument("--symbol-dirs", default="", help="额外的符号搜索目录，冒号分隔")
    parser.add_argument(
        "--max-frames",
        type=int,
        default=DEFAULT_MAX_FRAMES,
        help="每线程最多解析的栈帧数（默认 40）",
    )
    parser.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT, help="gdb 超时秒数（默认 120）"
    )
    parser.add_argument("--json-out", help="把报告写到文件（默认写 stdout）")
    parser.add_argument(
        "--thread", type=int, default=None, help="单帧模式：线程号（gdb 的 thread 编号）"
    )
    parser.add_argument("--frame", type=int, default=0, help="单帧模式：帧号（默认 0）")
    parser.add_argument("--from-gdb-output", help=argparse.SUPPRESS)
    parser.add_argument("--version", action="store_true", help="打印引擎版本")
    args = parser.parse_args(argv)

    if args.version:
        emit({"schemaVersion": SCHEMA_VERSION, "engine": {"name": "cdparse", "version": ENGINE_VERSION}})

    symbol_dirs = [d for d in (args.symbol_dirs or "").split(":") if d]
    diagnostics = []

    if args.from_gdb_output:
        text = read_gdb_output(args.from_gdb_output)
        report = analyze(
            text,
            {
                "core": args.core,
                "exe": args.exe,
                "max_frames": args.max_frames,
                "mappings": [],
                "probe": False,
            },
        )
    else:
        check_core(args.core)
        exe = resolve_exe(args, diagnostics)

        if args.thread is not None:
            result = run_gdb_frame(
                args.core, exe, symbol_dirs, args.thread, args.frame, args.max_frames, args.timeout
            )
        else:
            result = run_gdb(args.core, exe, symbol_dirs, args.max_frames, args.timeout)
        text = result.out
        stderr_text = result.err
        if result.timed_out:
            fail(
                "GDB_TIMEOUT",
                "gdb 超过 %d 秒未完成。" % args.timeout,
                "core 很大时先调大 timeout，或先只解析崩溃线程。",
            )
        if result.rc != 0 and not text.strip():
            fail(
                "GDB_FAILED",
                "gdb 执行失败（rc=%s）：%s" % (result.rc, result.err.strip()[:2000]),
            )
        if len(text) > MAX_GDB_OUTPUT:
            text = text[:MAX_GDB_OUTPUT]
            diagnostics.append(
                diag("OUTPUT_TRUNCATED", "warn", "gdb 输出过大，已截断，栈可能不完整。")
            )

        exe_arch = readelf_arch(exe) if exe else None
        core_arch = readelf_arch(args.core)
        if args.thread is not None:
            report = build_frame_report(
                text,
                {
                    "core": args.core,
                    "exe": exe,
                    "arch": exe_arch,
                    "thread": args.thread,
                    "frame": args.frame,
                    "stderr": stderr_text,
                },
            )
            report["target"]["coreArch"] = core_arch
        else:
            report = analyze(
                text,
                {
                    "core": args.core,
                    "exe": exe,
                    "max_frames": args.max_frames,
                    "mappings": core_mappings(args.core),
                    "probe": True,
                    "arch": exe_arch,
                    "core_arch": core_arch,
                    "stderr": stderr_text,
                },
            )
        report["diagnostics"] = diagnostics + report["diagnostics"]
        if core_arch and report["target"]["arch"] and core_arch != report["target"]["arch"]:
            report["diagnostics"].append(
                diag(
                    "ARCH_MISMATCH",
                    "error",
                    "core 架构（%s）与可执行文件（%s）不一致。"
                    % (core_arch, report["target"]["arch"]),
                    "换对的产物，跨架构的 core 解析结果没有意义。",
                )
            )

    payload = json.dumps(report, ensure_ascii=False)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")
        emit(
            {
                "schemaVersion": SCHEMA_VERSION,
                "ok": True,
                "engine": {"name": "cdparse", "version": ENGINE_VERSION},
                "written": args.json_out,
            }
        )
    else:
        write_json(report)


if __name__ == "__main__":
    main()
