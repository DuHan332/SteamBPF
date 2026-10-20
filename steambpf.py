"""Local-only Steam memory patch recreation. No key/token extraction or cloud sync."""
import argparse
import ctypes as C
from ctypes import wintypes as W
import os
import re
import struct
import time

# The original enables these two rules. Its third rule is present but disabled.
RULES = [
    ('branch_1', '41 83 FE FF 0F 84 ?? ?? ?? ?? 66 66 66 0F 1F 84',
     '41 83 FE FF E9 ?? ?? ?? ?? 90 66 66 66 0F 1F 84', 4),
    ('branch_2', '44 39 60 20 0F 8E ?? ?? ?? ?? 48 89 BC 24',
     '44 39 60 20 E9 ?? ?? ?? ?? 90 48 89 BC 24', 4),
]

def matches(data, pattern):
    parts = pattern.split()
    expression = b''.join(b'.' if p == '??' else re.escape(bytes([int(p, 16)])) for p in parts)
    return [m.start() for m in re.finditer(b'(?=' + expression + b')', data, re.DOTALL)]

def replacement(original):
    if len(original) != 6 or original[:2] not in (b'\x0f\x84', b'\x0f\x8e'):
        raise ValueError('Unexpected branch bytes')
    displacement = struct.unpack('<i', original[2:])[0] + 1
    return b'\xe9' + struct.pack('<i', displacement) + b'\x90'

class PROCESSENTRY32W(C.Structure):
    _fields_ = [('dwSize', W.DWORD), ('cntUsage', W.DWORD), ('th32ProcessID', W.DWORD),
                ('th32DefaultHeapID', C.c_size_t), ('th32ModuleID', W.DWORD),
                ('cntThreads', W.DWORD), ('th32ParentProcessID', W.DWORD),
                ('pcPriClassBase', W.LONG), ('dwFlags', W.DWORD), ('szExeFile', W.WCHAR * 260)]

class MODULEENTRY32W(C.Structure):
    _fields_ = [('dwSize', W.DWORD), ('th32ModuleID', W.DWORD), ('th32ProcessID', W.DWORD),
                ('GlblcntUsage', W.DWORD), ('ProccntUsage', W.DWORD), ('modBaseAddr', C.c_void_p),
                ('modBaseSize', W.DWORD), ('hModule', W.HMODULE),
                ('szModule', W.WCHAR * 256), ('szExePath', W.WCHAR * 260)]

class TCPROW(C.Structure):
    _fields_ = [(n, W.DWORD) for n in ('state', 'local_addr', 'local_port', 'remote_addr', 'remote_port')]

def api(dll, name, result, args):
    f = getattr(dll, name)
    f.restype, f.argtypes = result, args
    return f

class Windows:
    def __init__(self):
        self.k = C.WinDLL('kernel32', use_last_error=True)
        self.snapshot = api(self.k, 'CreateToolhelp32Snapshot', W.HANDLE, [W.DWORD, W.DWORD])
        self.close = api(self.k, 'CloseHandle', W.BOOL, [W.HANDLE])
        self.pfirst = api(self.k, 'Process32FirstW', W.BOOL, [W.HANDLE, C.POINTER(PROCESSENTRY32W)])
        self.pnext = api(self.k, 'Process32NextW', W.BOOL, [W.HANDLE, C.POINTER(PROCESSENTRY32W)])
        self.mfirst = api(self.k, 'Module32FirstW', W.BOOL, [W.HANDLE, C.POINTER(MODULEENTRY32W)])
        self.mnext = api(self.k, 'Module32NextW', W.BOOL, [W.HANDLE, C.POINTER(MODULEENTRY32W)])
        self.open = api(self.k, 'OpenProcess', W.HANDLE, [W.DWORD, W.BOOL, W.DWORD])
        self.read_api = api(self.k, 'ReadProcessMemory', W.BOOL,
                            [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)])
        self.write_api = api(self.k, 'WriteProcessMemory', W.BOOL,
                             [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)])
        self.protect = api(self.k, 'VirtualProtectEx', W.BOOL,
                           [W.HANDLE, C.c_void_p, C.c_size_t, W.DWORD, C.POINTER(W.DWORD)])
        self.flush = api(self.k, 'FlushInstructionCache', W.BOOL, [W.HANDLE, C.c_void_p, C.c_size_t])

    def find(self, pid=None):
        snap = self.snapshot(2, 0)
        if snap == C.c_void_p(-1).value:
            raise C.WinError(C.get_last_error())
        found = []
        try:
            row = PROCESSENTRY32W(); row.dwSize = C.sizeof(row)
            ok = self.pfirst(snap, C.byref(row))
            while ok:
                if row.szExeFile.lower() == 'steam.exe' and (pid is None or pid == row.th32ProcessID):
                    found.append(row.th32ProcessID)
                ok = self.pnext(snap, C.byref(row))
        finally:
            self.close(snap)
        if len(found) != 1:
            raise RuntimeError('Expected one Steam process; found %s. Use --pid if needed.' % found)
        pid = found[0]
        snap = self.snapshot(0x18, pid)
        if snap == C.c_void_p(-1).value:
            raise C.WinError(C.get_last_error())
        try:
            row = MODULEENTRY32W(); row.dwSize = C.sizeof(row)
            ok = self.mfirst(snap, C.byref(row))
            while ok:
                if row.szModule.lower() == 'steamclient64.dll':
                    return pid, row.modBaseAddr, row.modBaseSize
                ok = self.mnext(snap, C.byref(row))
        finally:
            self.close(snap)
        raise RuntimeError('steamclient64.dll is not loaded.')

    def read(self, handle, address, size):
        buf = C.create_string_buffer(size); count = C.c_size_t()
        if not self.read_api(handle, address, buf, size, C.byref(count)) or count.value != size:
            raise C.WinError(C.get_last_error())
        return buf.raw

    def write(self, handle, address, data):
        old = W.DWORD(); ignored = W.DWORD(); count = C.c_size_t()
        if not self.protect(handle, address, len(data), 0x40, C.byref(old)):
            raise C.WinError(C.get_last_error())
        try:
            buf = C.create_string_buffer(data)
            if not self.write_api(handle, address, buf, len(data), C.byref(count)) or count.value != len(data):
                raise C.WinError(C.get_last_error())
            if not self.flush(handle, address, len(data)):
                raise C.WinError(C.get_last_error())
        finally:
            if not self.protect(handle, address, len(data), old.value, C.byref(ignored)):
                raise C.WinError(C.get_last_error())

    def code_sections(self, handle, base, module_size):
        dos = self.read(handle, base, 64)
        if dos[:2] != b'MZ': raise RuntimeError('Invalid module DOS header')
        peoff = struct.unpack_from('<I', dos, 60)[0]
        if peoff + 24 > module_size: raise RuntimeError('Invalid PE offset')
        head = self.read(handle, base + peoff, 24)
        if head[:4] != b'PE\0\0': raise RuntimeError('Invalid module PE header')
        sections = struct.unpack_from('<H', head, 6)[0]
        optional_size = struct.unpack_from('<H', head, 20)[0]
        table = peoff + 24 + optional_size
        if sections > 96 or table + sections * 40 > module_size:
            raise RuntimeError('Invalid module sections')
        headers = self.read(handle, base + table, sections * 40)
        for i in range(sections):
            h = headers[i*40:(i+1)*40]
            size, rva = struct.unpack_from('<II', h, 8)
            flags = struct.unpack_from('<I', h, 36)[0]
            if flags & 0x20000020 and size:
                if rva + size > module_size: raise RuntimeError('Section exceeds module')
                yield base + rva, self.read(handle, base + rva, size)

def refresh(pid, mode, progress=None):
    failures = []
    def delay(seconds, start, end):
        if progress is None:
            time.sleep(seconds)
        else:
            for i in range(24):
                time.sleep(seconds / 24)
                progress(start + (end - start) * (i + 1) / 24)
    shell = C.WinDLL('shell32', use_last_error=True)
    execute = api(shell, 'ShellExecuteW', C.c_ssize_t,
                  [W.HWND, W.LPCWSTR, W.LPCWSTR, W.LPCWSTR, W.LPCWSTR, C.c_int])
    def uri(url):
        result = execute(None, 'open', url, None, None, 1)
        if result <= 32: raise RuntimeError('Steam URI launch failed: %s' % result)
    if mode == 'tcp':
        ip = C.WinDLL('iphlpapi', use_last_error=True)
        get = api(ip, 'GetExtendedTcpTable', W.DWORD,
                  [C.c_void_p, C.POINTER(W.DWORD), W.BOOL, W.ULONG, C.c_int, W.ULONG])
        delete = api(ip, 'SetTcpEntry', W.DWORD, [C.POINTER(TCPROW)])
        size = W.DWORD(); result = get(None, C.byref(size), True, 2, 5, 0)
        if result not in (0, 122): raise RuntimeError('TCP inventory failed: %s' % result)
        buf = C.create_string_buffer(max(size.value, 4))
        result = get(buf, C.byref(size), True, 2, 5, 0)
        if result: raise RuntimeError('TCP inventory failed: %s' % result)
        raw = buf.raw; count = struct.unpack_from('<I', raw)[0]
        if 4 + count*24 > len(raw): raise RuntimeError('Invalid TCP inventory')
        disconnected = 0
        skipped = 0
        for i in range(count):
            values = struct.unpack_from('<6I', raw, 4+i*24)
            if values[5] == pid:
                if values[0] in (1, 2, 11, 12):
                    skipped += 1
                    continue
                row = TCPROW(12, *values[1:5])
                result = delete(C.byref(row))
                if result:
                    failures.append(result)
                    print('TCP entry could not be disconnected: code=%s, state=%s, local_port_raw=%s, remote_port_raw=%s' % (
                        result, values[0], values[2], values[4]))
                else:
                    disconnected += 1
        print('Steam TCP connections disconnected: %d' % disconnected)
        print('Skipped closed/listening/TIME_WAIT/deleted entries: %d' % skipped)
        if not disconnected:
            print('No Steam TCP connections were successfully disconnected.')
    else:
        uri('steam://open/gooffline'); time.sleep(0.2)
    uri('steam://open/goonline'); uri('steam://open/library')
    if progress: progress(40)
    # The original window's timers 0x66 and 0x67 repeat these actions later.
    delay(1.2, 40, 65)
    uri('steam://open/goonline')
    delay(1.5, 65, 95)
    uri('steam://open/library')
    print('Reconnect commands sent. Steam connection status has not been verified.')
    if failures:
        detail = '%d TCP entry/entries failed; codes: %s.' % (len(failures), sorted(set(failures)))
        if disconnected:
            print('Partial disconnect completed: %d succeeded; %s' % (disconnected, detail))
        else:
            raise RuntimeError('No TCP disconnect succeeded. ' + detail + ' Reconnect commands were still sent; check connection states and elevation.')

def main(argv=None, progress=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='Apply memory changes; default is read-only scan')
    parser.add_argument('--refresh', choices=['none', 'uri', 'tcp'], default='none')
    parser.add_argument('--pid', type=int)
    args = parser.parse_args(argv)
    if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
        parser.error('Requires Windows and 64-bit Python')
    if args.refresh != 'none' and not args.apply:
        parser.error('--refresh requires --apply')
    if progress: progress(5)
    win = Windows(); pid, base, size = win.find(args.pid)
    if progress: progress(15)
    access = 0x410 | (0x28 if args.apply else 0)
    handle = win.open(access, False, pid)
    if not handle: raise C.WinError(C.get_last_error())
    try:
        sections = list(win.code_sections(handle, base, size))
        plan = []
        for name, original, patched, offset in RULES:
            hits = [(addr+p, data[p+offset:p+offset+6], False)
                    for addr, data in sections for p in matches(data, original)]
            hits += [(addr+p, None, True) for addr, data in sections for p in matches(data, patched)]
            if len(hits) != 1:
                raise RuntimeError('%s: expected exactly one match, got %d; no writes started.' % (name, len(hits)))
            address, before, done = hits[0]
            print('%s at 0x%x: %s' % (name, address, 'already patched' if done else 'matched'))
            if not done: plan.append((address+offset, before, replacement(before)))
        if not args.apply:
            print('Read-only scan complete. Use --apply to write the verified patch plan.')
            return
        changed = []
        try:
            for address, before, after in plan:
                if win.read(handle, address, 6) != before:
                    raise RuntimeError('Target bytes changed since scan')
                changed.append((address, before))
                win.write(handle, address, after)
                if win.read(handle, address, 6) != after:
                    raise RuntimeError('Patch verification failed')
        except Exception:
            for address, before in reversed(changed):
                try: win.write(handle, address, before)
                except Exception as error: print('Rollback failed:', error)
            raise
        print('Applied %d memory changes.' % len(changed))
        if progress: progress(30)
        if args.refresh != 'none': refresh(pid, args.refresh, progress=progress)
        if progress: progress(100)
        return pid
    finally:
        win.close(handle)

if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('Error:', error)
        raise SystemExit(1)
