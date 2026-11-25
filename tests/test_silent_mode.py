"""Offline regression tests; no real Steam process or network is accessed."""
import contextlib
import io
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import steambpf as app

BASE = 0x140000000

def pattern_bytes(pattern):
    return bytes(0 if p == '??' else int(p, 16) for p in pattern.split())

def fixture():
    data = bytearray(b'\xcc' * 2048)
    first = pattern_bytes(app.EXTENDED_BRANCH + '0F 84 ?? ?? ?? ??')
    first = first[:-4] + struct.pack('<i', 100)
    second = pattern_bytes(app.RULES[1][1])
    second = second[:6] + struct.pack('<i', 100) + second[10:]
    silent = pattern_bytes(app.SILENT_ORIGINAL)
    silent = silent[:-4] + struct.pack('<i', 100)
    for offset, value in ((64, first), (256, second), (512, silent)):
        data[offset:offset+len(value)] = value
    return data

def apply_plan(data, plan):
    for address, before, after in plan:
        offset = address-BASE
        assert data[offset:offset+len(before)] == before
        data[offset:offset+len(after)] = after

class SilentModeTests(unittest.TestCase):
    def test_enable_repeat_and_restore(self):
        data = fixture()
        original = bytes(data)
        plan = app.plan_patches([(BASE, bytes(data))], silent=True)
        self.assertEqual([len(before) for _, before, _ in plan], [6, 6, 14])
        apply_plan(data, plan)
        self.assertEqual(app.plan_patches([(BASE, bytes(data))], silent=True), [])
        restore = app.plan_patches([(BASE, bytes(data))], silent=False)
        self.assertEqual(len(restore), 1)
        self.assertEqual(restore[0][2], original[547:561])
        apply_plan(data, restore)
        self.assertEqual(app.plan_patches([(BASE, bytes(data))], silent=False), [])

    def test_silent_destination_is_preserved(self):
        for displacement in (-200, -1, 0, 100, 100000):
            old = app.SILENT_COMPARE + struct.pack('<i', displacement)
            new = app.silent_replacement(old)
            self.assertEqual(14+displacement, 5+struct.unpack('<i',new[1:5])[0])
            self.assertEqual(app.silent_original(new), old)

    def test_missing_and_ambiguous_signatures_rejected(self):
        data = fixture()
        data[512] = 0
        with self.assertRaisesRegex(RuntimeError, 'silent branch'):
            app.plan_patches([(BASE, bytes(data))], silent=True)
        data = fixture()
        data[800:849] = data[512:561]
        with self.assertRaisesRegex(RuntimeError, 'exactly one'):
            app.plan_patches([(BASE, bytes(data))], silent=True)

    def test_external_trampoline_rejected(self):
        data = fixture()
        data[547:561] = b'\xe9' + struct.pack('<i',10000) + b'\x90'*9
        with self.assertRaisesRegex(RuntimeError,'Unsupported silent'):
            app.plan_patches([(BASE,bytes(data))],silent=True)

    def test_standard_legacy_signature_still_supported(self):
        data = bytearray(b'\xcc'*1024)
        for offset, rule in zip((64,256),app.RULES):
            value = pattern_bytes(rule[1])
            data[offset:offset+len(value)] = value
        self.assertEqual(len(app.plan_patches([(BASE,bytes(data))])),2)

    def test_write_failure_rolls_back_all_bytes(self):
        memory = fixture()
        initial = bytes(memory)
        class FakeWindows:
            writes = 0
            def find(self,pid):return 123,BASE,len(memory)
            def open(self,*args):return 1
            def close(self,*args):pass
            def code_sections(self,*args):return [(BASE,bytes(memory))]
            def read(self,h,address,size):return bytes(memory[address-BASE:address-BASE+size])
            def write(self,h,address,data):
                self.writes += 1
                if self.writes == 2:raise RuntimeError('simulated failure')
                memory[address-BASE:address-BASE+len(data)] = data
        with patch.object(app,'Windows',FakeWindows), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError,'simulated failure'):
                app.legacy_main(['--apply','--silent'])
        self.assertEqual(bytes(memory),initial)

if __name__ == '__main__':unittest.main()
