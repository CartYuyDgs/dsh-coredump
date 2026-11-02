#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cdparse 引擎的离线回测：跑在捕获的 gdb 文本上，不需要真实 core。"""

import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE_DIR = os.path.join(os.path.dirname(HERE), "engine")
FIXTURES = os.path.join(HERE, "fixtures")
sys.path.insert(0, ENGINE_DIR)

import cdparse  # noqa: E402

MAPPINGS = [
    {"start": "0x400000", "end": "0x410000", "offset": "0x0", "path": "/opt/app/bin/order-server"},
    {"start": "0x7f8d4a8ab000", "end": "0x7f8d4aa6a000", "offset": "0x0", "path": "/lib64/libpthread.so.0"},
    {"start": "0x7f8d4ac1f000", "end": "0x7f8d4af9a000", "offset": "0x0", "path": "/lib64/libstdc++.so.6"},
    {"start": "0x7f8d4b3f9000", "end": "0x7f8d4b4f8000", "offset": "0x0", "path": "/lib64/libc.so.6"},
]


def fixture(name):
    with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as handle:
        return handle.read()


def analyze(name):
    return cdparse.analyze(
        fixture(name),
        {
            "core": "/data/core.18422",
            "exe": "/opt/app/bin/order-server",
            "max_frames": 40,
            "mappings": MAPPINGS,
            "probe": False,
            "arch": "x86_64",
            "core_arch": "x86_64",
        },
    )


class FrameParsingTest(unittest.TestCase):
    def test_cpp_template_and_args(self):
        frame = cdparse.parse_frame(
            "#12  0x0000000000400abc in std::vector<int, std::allocator<int> >::size "
            "(this=0x0) at /usr/include/c++/4.8.2/bits/stl_vector.h:734"
        )
        self.assertEqual(frame["index"], 12)
        self.assertEqual(frame["address"], "0x0000000000400abc")
        self.assertEqual(frame["symbol"], "std::vector<int, std::allocator<int> >::size")
        self.assertEqual(frame["args"], "this=0x0")
        self.assertEqual(frame["source"], {"file": "/usr/include/c++/4.8.2/bits/stl_vector.h", "line": 734})

    def test_stripped_frame(self):
        frame = cdparse.parse_frame("#3  0x00007f8d4b3f9c8d in ?? ()")
        self.assertTrue(frame["unresolved"])
        self.assertEqual(frame["symbol"], "??")
        self.assertIsNone(frame["source"])

    def test_signal_handler_frame(self):
        frame = cdparse.parse_frame("#0  <signal handler called>")
        self.assertTrue(frame["signalHandler"])
        self.assertEqual(frame["symbol"], "<signal handler called>")

    def test_lib_frame_from(self):
        frame = cdparse.parse_frame(
            "#0  0x00007f8d4a8b3a86 in __lll_lock_wait () from /lib64/libpthread.so.0"
        )
        self.assertEqual(frame["symbol"], "__lll_lock_wait")
        self.assertEqual(frame["module"], "/lib64/libpthread.so.0")
        self.assertFalse(frame["unresolved"])

    def test_no_address_symbolic_frame(self):
        frame = cdparse.parse_frame("#1  main () at /src/main.c:10")
        self.assertIsNone(frame["address"])
        self.assertEqual(frame["symbol"], "main")
        self.assertEqual(frame["source"], {"file": "/src/main.c", "line": 10})


class SegvReportTest(unittest.TestCase):
    def setUp(self):
        self.report = analyze("gdb-segv.txt")

    def test_signal(self):
        self.assertEqual(self.report["signal"], {"name": "SIGSEGV", "description": "Segmentation fault"})

    def test_generated_by(self):
        self.assertEqual(
            self.report["target"]["generatedBy"],
            "/opt/app/bin/order-server --config /etc/order/config.yaml",
        )

    def test_threads_and_crash_thread(self):
        self.assertEqual(len(self.report["threads"]), 3)
        self.assertEqual(self.report["crashThread"], 2)

    def test_crash_thread_frames(self):
        crash = next(t for t in self.report["threads"] if t["id"] == 2)
        self.assertEqual(crash["name"], "worker-1")
        self.assertEqual(crash["lwp"], 18423)
        self.assertEqual(len(crash["frames"]), 5)
        top = crash["frames"][0]
        self.assertEqual(top["symbol"], "OrderService::submit")
        self.assertEqual(top["source"], {"file": "/src/order/service.cpp", "line": 218})
        # 地址落在 exe 映射里 -> 模块由 NT_FILE 回填
        self.assertEqual(top["module"], "/opt/app/bin/order-server")

    def test_waiting_thread_resolves_lib(self):
        waiting = next(t for t in self.report["threads"] if t["id"] == 1)
        self.assertEqual(waiting["frames"][0]["symbol"], "__lll_lock_wait")
        self.assertEqual(waiting["frames"][0]["module"], "/lib64/libpthread.so.0")
        self.assertEqual(waiting["frames"][1]["symbol"], "_L_lock_812")

    def test_registers(self):
        self.assertEqual(self.report["registers"]["rip"], "0x4012ab")
        self.assertEqual(self.report["registers"]["rax"], "0x0")

    def test_modules_dedup_and_symbol_state(self):
        modules = self.report["modules"]
        paths = [m["path"] for m in modules]
        self.assertEqual(paths.count("/opt/app/bin/order-server"), 1)
        exe = next(m for m in modules if m["path"] == "/opt/app/bin/order-server")
        self.assertTrue(exe["symbolsLoaded"])
        self.assertIn("/lib64/libc.so.6", paths)

    def test_no_false_symbol_diagnostics(self):
        codes = [item["code"] for item in self.report["diagnostics"]]
        self.assertNotIn("SYMBOL_MISSING", codes)


class StrippedReportTest(unittest.TestCase):
    def setUp(self):
        self.report = analyze("gdb-stripped.txt")

    def test_unresolved_crash_frame(self):
        crash = next(t for t in self.report["threads"] if t["id"] == 1)
        self.assertTrue(crash["frames"][0]["unresolved"])
        self.assertEqual(crash["frames"][0]["symbol"], "??")

    def test_symbol_diagnostics(self):
        codes = [item["code"] for item in self.report["diagnostics"]]
        self.assertIn("NO_DEBUG_SYMBOLS", codes)
        self.assertIn("SYMBOL_MISSING", codes)

    def test_libc_symbols_false(self):
        libc = next(m for m in self.report["modules"] if m["path"] == "/lib64/libc.so.6")
        self.assertFalse(libc["symbolsLoaded"])


class CliTest(unittest.TestCase):
    def test_from_gdb_output_cli(self):
        engine = os.path.join(ENGINE_DIR, "cdparse.py")
        result = subprocess.run(
            [sys.executable, engine, "--from-gdb-output", os.path.join(FIXTURES, "gdb-segv.txt"),
             "--core", "/data/core.18422"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        payload = json.loads(result.stdout.decode("utf-8"))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["crashThread"], 2)
        self.assertEqual(payload["signal"]["name"], "SIGSEGV")

    def test_missing_core_is_structured(self):
        engine = os.path.join(ENGINE_DIR, "cdparse.py")
        result = subprocess.run(
            [sys.executable, engine, "--core", "/nonexistent/core"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        payload = json.loads(result.stdout.decode("utf-8"))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "CORE_NOT_FOUND")


class MarkedOutputTest(unittest.TestCase):
    """标记分节后的输出：寄存器只取 reg 段，反汇编进 crash 段。"""

    def setUp(self):
        self.report = analyze("gdb-segv-marked.txt")

    def test_signal_and_threads_still_parse(self):
        self.assertEqual(self.report["signal"]["name"], "SIGSEGV")
        self.assertEqual(self.report["crashThread"], 2)
        self.assertEqual(len(self.report["threads"]), 2)

    def test_registers_come_from_the_register_section(self):
        self.assertEqual(self.report["registers"]["rip"], "0x4012ab")
        self.assertEqual(self.report["registers"]["rax"], "0x0")
        self.assertIn("eflags", self.report["registers"])

    def test_crash_instruction(self):
        instruction = self.report["crash"]["instruction"]
        self.assertEqual(instruction["address"], "0x4012ab")
        self.assertTrue(instruction["current"])
        self.assertIn("(%rax)", instruction["text"])

    def test_disassembly_context(self):
        self.assertEqual(len(self.report["crash"]["disassembly"]), 5)


class FrameDetailTest(unittest.TestCase):
    """--thread/--frame 模式的归一化结果。"""

    def setUp(self):
        self.detail = cdparse.build_frame_report(
            fixture("gdb-frame.txt"),
            {
                "core": "/data/core.18422",
                "exe": "/opt/app/bin/order-server",
                "arch": "x86_64",
                "thread": 2,
                "frame": 1,
            },
        )

    def test_identity(self):
        self.assertEqual(self.detail["mode"], "frame")
        self.assertEqual(self.detail["thread"], 2)
        self.assertEqual(self.detail["frame"], 1)
        self.assertEqual(self.detail["currentFrame"]["symbol"], "worker_loop")
        self.assertEqual(self.detail["frameInfo"]["pc"], "0x4017c2")

    def test_args(self):
        self.assertEqual(
            self.detail["args"],
            [{"name": "ctx", "value": "0x60e010", "truncated": False}],
        )

    def test_locals(self):
        names = [item["name"] for item in self.detail["locals"]]
        self.assertEqual(names, ["worker", "count", "name"])
        self.assertTrue(self.detail["locals"][0]["truncated"])

    def test_source_window_marks_current_line(self):
        lines = self.detail["source"]["lines"]
        self.assertEqual(len(lines), 6)
        current = [line for line in lines if line["current"]]
        self.assertEqual(len(current), 1)
        self.assertEqual(current[0]["number"], 88)

    def test_disassembly_marks_current(self):
        current = [item for item in self.detail["disassembly"] if item["current"]]
        self.assertEqual(len(current), 1)

    def test_no_false_diagnostics(self):
        codes = [item["code"] for item in self.detail["diagnostics"]]
        self.assertNotIn("FRAME_NOT_FOUND", codes)
        self.assertNotIn("SOURCE_UNAVAILABLE", codes)


class FrameMissingTest(unittest.TestCase):
    def test_frame_not_found_is_a_diagnostic(self):
        detail = cdparse.build_frame_report(
            "@@cdparse:select@@\nNo frame at level 99.\n",
            {"thread": 1, "frame": 99},
        )
        codes = [item["code"] for item in detail["diagnostics"]]
        self.assertIn("FRAME_NOT_FOUND", codes)


READELF_NT_FILE = """Displaying notes found at file offset 0x00000628 with length 0x000013f8:
  Owner                Data size \tDescription
  CORE                 0x00000150\tNT_PRSTATUS (prstatus structure)
  CORE                 0x00000371\tNT_FILE (mapped files)
    Page size: 4096
                 Start                 End         Page Offset
    0x000058cac360d000  0x000058cac360e000  0x0000000000000000
        /tmp/cdtest/crash
    0x000058cac360e000  0x000058cac360f000  0x0000000000000001
        /tmp/cdtest/crash
    0x00007a0cbf865000  0x00007a0cbf88d000  0x0000000000000000
        /usr/lib/x86_64-linux-gnu/libc.so.6
    0x00007a0cbf88d000  0x00007a0cbf9f0000  0x0000000000000028
        /usr/lib/x86_64-linux-gnu/libc.so.6
"""

READELF_NT_FILE_OLD = """Mapped address spaces:

\tStart\t\tEnd\t\tOffset\t\tobjfile
\t0x400000\t0x410000\t0x0\t\t/opt/app/bin/order-server
"""


class MappingsTest(unittest.TestCase):
    def test_new_readelf_layout_path_on_next_line(self):
        mappings = cdparse.parse_mappings(READELF_NT_FILE)
        self.assertEqual(len(mappings), 4)
        self.assertEqual(mappings[0]["path"], "/tmp/cdtest/crash")
        self.assertEqual(mappings[0]["start"], "0x000058cac360d000")
        self.assertEqual(mappings[-1]["path"], "/usr/lib/x86_64-linux-gnu/libc.so.6")

    def test_old_readelf_layout_path_on_same_line(self):
        mappings = cdparse.parse_mappings(READELF_NT_FILE_OLD)
        self.assertEqual(len(mappings), 1)
        self.assertEqual(mappings[0]["path"], "/opt/app/bin/order-server")

    def test_module_resolution_uses_mappings(self):
        mappings = cdparse.parse_mappings(READELF_NT_FILE)
        self.assertEqual(
            cdparse.resolve_module("0x000058cac360e1d0", mappings), "/tmp/cdtest/crash"
        )
        self.assertEqual(
            cdparse.resolve_module("0x00007a0cbf88eca8", mappings),
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
