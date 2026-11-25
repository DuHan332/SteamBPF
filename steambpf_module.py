"""Controller for the independently built SteamBPF native module. No HTTP client."""
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import time

import steambpf

PROTOCOL = '2'
MODULE = 'SteamBPFHook.dll'


def parse_status(response, pid):
    """Require a versioned response from the intended controller endpoint."""
    parts = response.strip().split()
    if not parts or parts[0] != 'OK':
        raise RuntimeError('Module: ' + response.strip())
    result = {}
    for part in parts[1:]:
        key, separator, value = part.partition('=')
        if not separator or key in result:
            raise RuntimeError('Module: malformed status')
        result[key] = value
    if result.get('version') != PROTOCOL or result.get('pid') != str(pid):
        raise RuntimeError('Module: incompatible control endpoint')
    if result.get('ready') != '1':
        raise RuntimeError('Module: ' + result.get('error', 'not_ready'))
    return result


def configuration(silent=False):
    return f'CONFIG protection=1 silent={int(silent)}'


def verified_payload(directory=None):
    root = Path(directory) if directory else Path(__file__).resolve().parent / 'native' / 'bin'
    payload = root / MODULE
    manifest = json.loads((root / 'module.json').read_text(encoding='utf-8'))
    data = payload.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if manifest.get('sha256') != digest or manifest.get('protocol') != 2:
        raise RuntimeError('Module: payload verification failed; rebuild the application')
    # Keep the loaded DLL outside PyInstaller's temporary extraction directory.
    cache = Path(os.environ['LOCALAPPDATA']) / 'SteamBPF' / 'modules' / digest
    cache.mkdir(parents=True, exist_ok=True)
    destination = cache / MODULE
    if destination.exists():
        if hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Module: cached payload verification failed')
    else:
        temporary = cache / f'{os.getpid()}.tmp'
        try:
            with temporary.open('xb') as stream:
                stream.write(data)
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
    return destination


class OVERLAPPED(C.Structure):
    _fields_ = [('Internal', C.c_size_t), ('InternalHigh', C.c_size_t),
                ('Offset', W.DWORD), ('OffsetHigh', W.DWORD), ('hEvent', W.HANDLE)]


class NativeWindows(steambpf.Windows):
    def modules(self, pid):
        snap = self.snapshot(0x18, pid)
        if snap == C.c_void_p(-1).value:
            raise C.WinError(C.get_last_error())
        result = []
        try:
            row = steambpf.MODULEENTRY32W(); row.dwSize = C.sizeof(row)
            ok = self.mfirst(snap, C.byref(row))
            while ok:
                result.append((row.szModule.lower(), row.modBaseAddr, row.modBaseSize, row.szExePath))
                ok = self.mnext(snap, C.byref(row))
        finally:
            self.close(snap)
        return result

    def find(self, pid=None):
        found = []
        for executable in ('steam.exe', 'steamwebhelper.exe'):
            for candidate in self.process_ids(executable):
                if pid is not None and candidate != pid:
                    continue
                try:
                    modules = self.modules(candidate)
                except OSError as error:
                    if getattr(error, 'winerror', None) in (5, 24, 299):
                        continue
                    raise
                for name, base, size, _ in modules:
                    if name == 'steamclient64.dll':
                        found.append((candidate, base, size))
            # Prefer the main client when it hosts the module.
            if found:
                break
        if len(found) != 1:
            raise RuntimeError('Expected one Steam client module; found %d' % len(found))
        return found[0]

    def exchange(self, pid, message, timeout=3000):
        api = steambpf.api
        create = api(self.k, 'CreateFileW', W.HANDLE,
                     [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p, W.DWORD, W.DWORD, W.HANDLE])
        wait_pipe = api(self.k, 'WaitNamedPipeW', W.BOOL, [W.LPCWSTR, W.DWORD])
        server_pid = api(self.k, 'GetNamedPipeServerProcessId', W.BOOL, [W.HANDLE, C.POINTER(W.ULONG)])
        set_mode = api(self.k, 'SetNamedPipeHandleState', W.BOOL,
                       [W.HANDLE, C.POINTER(W.DWORD), C.c_void_p, C.c_void_p])
        event = api(self.k, 'CreateEventW', W.HANDLE, [C.c_void_p, W.BOOL, W.BOOL, W.LPCWSTR])
        transact = api(self.k, 'TransactNamedPipe', W.BOOL,
                       [W.HANDLE, C.c_void_p, W.DWORD, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.POINTER(OVERLAPPED)])
        wait = api(self.k, 'WaitForSingleObject', W.DWORD, [W.HANDLE, W.DWORD])
        complete = api(self.k, 'GetOverlappedResult', W.BOOL,
                       [W.HANDLE, C.POINTER(OVERLAPPED), C.POINTER(W.DWORD), W.BOOL])
        cancel = api(self.k, 'CancelIoEx', W.BOOL, [W.HANDLE, C.POINTER(OVERLAPPED)])
        name = rf'\\.\pipe\SteamBPF.{pid}'
        deadline = time.monotonic() + timeout / 1000
        while True:
            if wait_pipe(name, max(1, int((deadline-time.monotonic())*1000))):
                pipe = create(name, 0xc0000000, 0, None, 3, 0x40000000, None)
                if pipe != C.c_void_p(-1).value:
                    break
            error = C.get_last_error()
            if error not in (2, 121, 231) or time.monotonic() >= deadline:
                raise C.WinError(error)
            time.sleep(.02)
        overlap = OVERLAPPED()
        try:
            actual = W.ULONG()
            if not server_pid(pipe, C.byref(actual)) or actual.value != pid:
                raise RuntimeError('Module: unexpected pipe server')
            mode = W.DWORD(2)
            if not set_mode(pipe, C.byref(mode), None, None):
                raise C.WinError(C.get_last_error())
            overlap.hEvent = event(None, True, False, None)
            if not overlap.hEvent:
                raise C.WinError(C.get_last_error())
            request = message.encode('ascii') + b'\n'
            incoming = C.create_string_buffer(2048); count = W.DWORD()
            pending = not transact(pipe, request, len(request), incoming, len(incoming), C.byref(count), C.byref(overlap))
            if pending:
                error = C.get_last_error()
                if error != 997:
                    raise C.WinError(error)
                if wait(overlap.hEvent, timeout) != 0:
                    cancel(pipe, C.byref(overlap))
                    # Drain cancellation before releasing the OVERLAPPED and buffers.
                    complete(pipe, C.byref(overlap), C.byref(count), True)
                    raise RuntimeError('Module: control timeout')
                if not complete(pipe, C.byref(overlap), C.byref(count), False):
                    raise C.WinError(C.get_last_error())
            return incoming.raw[:count.value].decode('ascii', errors='strict')
        finally:
            self.close(pipe)
            if overlap.hEvent:
                self.close(overlap.hEvent)

    def inject(self, pid, path):
        api = steambpf.api
        create_thread = api(self.k, 'CreateRemoteThread', W.HANDLE,
                            [W.HANDLE, C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p, W.DWORD, C.c_void_p])
        get_module = api(self.k, 'GetModuleHandleW', W.HMODULE, [W.LPCWSTR])
        get_proc = api(self.k, 'GetProcAddress', C.c_void_p, [W.HMODULE, C.c_char_p])
        owner_module = api(self.k, 'GetModuleHandleExW', W.BOOL,
                           [W.DWORD, C.c_void_p, C.POINTER(W.HMODULE)])
        module_path = api(self.k, 'GetModuleFileNameW', W.DWORD, [W.HMODULE, W.LPWSTR, W.DWORD])
        wait = api(self.k, 'WaitForSingleObject', W.DWORD, [W.HANDLE, W.DWORD])
        wow64 = api(self.k, 'IsWow64Process2', W.BOOL,
                    [W.HANDLE, C.POINTER(W.WORD), C.POINTER(W.WORD)])
        handle = self.open(0x43a, False, pid)
        if not handle:
            raise C.WinError(C.get_last_error())
        remote = None; thread = None; finished = False
        try:
            process_machine = W.WORD(); native_machine = W.WORD()
            if not wow64(handle, C.byref(process_machine), C.byref(native_machine)):
                raise C.WinError(C.get_last_error())
            if process_machine.value != 0 or native_machine.value != 0x8664:
                raise RuntimeError('Module: requires an x64 Steam process')
            modules = self.modules(pid)
            for name, _, _, existing in modules:
                if name == 'steamfamily.dll':
                    raise RuntimeError('Module: another module is loaded; restart Steam first')
                if name == MODULE.lower():
                    if Path(existing) != path:
                        raise RuntimeError('Module: older module loaded; restart Steam first')
                    return
            loader = get_proc(get_module('kernel32.dll'), b'LoadLibraryW')
            owner = W.HMODULE()
            if not loader or not owner_module(6, loader, C.byref(owner)):
                raise C.WinError(C.get_last_error())
            local_path = C.create_unicode_buffer(32768)
            if not module_path(owner, local_path, len(local_path)):
                raise C.WinError(C.get_last_error())
            owner_name = Path(local_path.value).name.lower()
            remote_owner = next((base for name, base, _, _ in modules if name == owner_name), None)
            if remote_owner is None:
                raise RuntimeError('Module: remote loader module unavailable')
            remote_loader = remote_owner + loader - owner.value
            data = (str(path) + '\0').encode('utf-16-le')
            remote = self.alloc(handle, None, len(data), 0x3000, 4)
            if not remote:
                raise C.WinError(C.get_last_error())
            count = C.c_size_t()
            if not self.write_api(handle, remote, data, len(data), C.byref(count)) or count.value != len(data):
                raise C.WinError(C.get_last_error())
            thread = create_thread(handle, None, 0, remote_loader, remote, 0, None)
            if not thread:
                raise C.WinError(C.get_last_error())
            if wait(thread, 15000) != 0:
                # A running loader may still use this allocation. Do not free it.
                raise RuntimeError('Module: injection timeout; restart Steam before retrying')
            finished = True
            if not any(name == MODULE.lower() and Path(existing) == path for name, _, _, existing in self.modules(pid)):
                raise RuntimeError('Module: DLL did not load')
        finally:
            if remote and (not thread or finished):
                self.free(handle, remote)
            if thread:
                self.close(thread)
            self.close(handle)


def run(silent=False, cold=False, progress=None, win=None, payload=None):
    """Inject, handshake, and apply one atomic configuration; never disconnect TCP."""
    command = configuration(silent)
    win = win or NativeWindows()
    path = Path(payload) if payload is not None else verified_payload()
    if progress: progress(5)
    if cold:
        from steambpf_startup import cold_start
        pid, _, _ = cold_start(win, progress=progress)
    else:
        pid, _, _ = win.find()
    if progress: progress(20)
    win.inject(pid, path)
    if progress: progress(55)
    deadline = time.monotonic() + 15
    while True:
        try:
            parse_status(win.exchange(pid, 'PING', timeout=500), pid)
            break
        except OSError as error:
            if getattr(error, 'winerror', None) not in (2, 231, 121) or time.monotonic() >= deadline:
                raise
            time.sleep(.1)
    if progress: progress(80)
    state = parse_status(win.exchange(pid, command), pid)
    expected = {'protection': '1', 'silent': str(int(silent))}
    if any(state.get(key) != value for key, value in expected.items()):
        raise RuntimeError('Module: configuration was not acknowledged')
    if progress: progress(100)
    return state
