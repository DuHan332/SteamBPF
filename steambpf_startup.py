"""Graceful Steam cold start using the interactive desktop user's token."""
import ctypes as C
from ctypes import wintypes as W
from pathlib import Path
import time
from steambpf_accounts import steam_directory

class STARTUPINFO(C.Structure):
    _fields_ = [('cb',W.DWORD),('lpReserved',W.LPWSTR),('lpDesktop',W.LPWSTR),('lpTitle',W.LPWSTR),
                ('dwX',W.DWORD),('dwY',W.DWORD),('dwXSize',W.DWORD),('dwYSize',W.DWORD),
                ('dwXCountChars',W.DWORD),('dwYCountChars',W.DWORD),('dwFillAttribute',W.DWORD),
                ('dwFlags',W.DWORD),('wShowWindow',W.WORD),('cbReserved2',W.WORD),
                ('lpReserved2',C.c_void_p),('hStdInput',W.HANDLE),('hStdOutput',W.HANDLE),('hStdError',W.HANDLE)]

class PROCESSINFO(C.Structure):
    _fields_ = [('process',W.HANDLE),('thread',W.HANDLE),('pid',W.DWORD),('tid',W.DWORD)]

def send_steam_uri(uri):
    from steambpf import api
    shell = C.WinDLL('shell32',use_last_error=True)
    execute = api(shell,'ShellExecuteW',C.c_ssize_t,
                  [W.HWND,W.LPCWSTR,W.LPCWSTR,W.LPCWSTR,W.LPCWSTR,C.c_int])
    if execute(None,'open',uri,None,None,1)<=32:raise RuntimeError('Cold start: Steam URI failed')

def launch_on_desktop(executable,win):
    """Launch Steam as the shell user rather than inheriting this tool's elevation."""
    from steambpf import api
    user = C.WinDLL('user32',use_last_error=True)
    adv = C.WinDLL('advapi32',use_last_error=True)
    get_shell = api(user,'GetShellWindow',W.HWND,[])
    get_pid = api(user,'GetWindowThreadProcessId',W.DWORD,[W.HWND,C.POINTER(W.DWORD)])
    open_token = api(adv,'OpenProcessToken',W.BOOL,[W.HANDLE,W.DWORD,C.POINTER(W.HANDLE)])
    duplicate = api(adv,'DuplicateTokenEx',W.BOOL,
                    [W.HANDLE,W.DWORD,C.c_void_p,C.c_int,C.c_int,C.POINTER(W.HANDLE)])
    create = api(adv,'CreateProcessWithTokenW',W.BOOL,
                 [W.HANDLE,W.DWORD,W.LPCWSTR,W.LPWSTR,W.DWORD,C.c_void_p,W.LPCWSTR,
                  C.POINTER(STARTUPINFO),C.POINTER(PROCESSINFO)])
    shell_window = get_shell()
    if not shell_window:raise RuntimeError('Cold start: no interactive desktop shell')
    pid = W.DWORD()
    if not get_pid(shell_window,C.byref(pid)):raise C.WinError(C.get_last_error())
    process = win.open(0x1000,False,pid.value)
    if not process:raise C.WinError(C.get_last_error())
    token = W.HANDLE();primary = W.HANDLE();info = PROCESSINFO()
    try:
        if not open_token(process,0xb,C.byref(token)):raise C.WinError(C.get_last_error())
        if not duplicate(token,0x2000000,None,2,1,C.byref(primary)):raise C.WinError(C.get_last_error())
        startup = STARTUPINFO();startup.cb = C.sizeof(startup);startup.lpDesktop = 'winsta0\\default'
        command = C.create_unicode_buffer('"%s"' % executable)
        if not create(primary,1,str(executable),command,0,None,str(executable.parent),C.byref(startup),C.byref(info)):
            raise C.WinError(C.get_last_error())
    finally:
        for handle in (info.thread,info.process,primary,token,process):
            if handle:win.close(handle)

def cold_start(win,progress=None,directory=None,send_uri=None,launch=None,clock=None,sleep=None):
    """Stop gracefully, start Steam, and wait for its x64 client module, not online state."""
    clock = clock or time.monotonic
    sleep = sleep or time.sleep
    send_uri = send_uri or send_steam_uri
    launch = launch or launch_on_desktop
    directory = Path(directory) if directory is not None else steam_directory()
    executable = directory/'steam.exe'
    if not executable.is_file():raise RuntimeError('Cold start: Steam executable not found')
    pids = win.process_ids()
    if len(pids)>1:raise RuntimeError('Cold start: multiple Steam processes; close extra instances first')
    if pids:
        send_uri('steam://exit')
        deadline = clock()+20
        while win.process_ids():
            if clock()>=deadline:
                raise RuntimeError('Cold start: Steam did not exit; close games and Steam before retrying')
            sleep(.2)
    if progress:progress(8)
    launch(executable,win)
    deadline = clock()+90
    while clock()<deadline:
        try:return win.find()
        except RuntimeError as error:
            if not any(s in str(error) for s in ('Expected one Steam','not loaded')):raise
        except OSError as error:
            if getattr(error,'winerror',None) not in (24,299):raise
        if progress:progress(min(14,8+(90-(deadline-clock()))/15))
        sleep(.2)
    raise RuntimeError('Cold start: timed out waiting for steamclient64.dll')
