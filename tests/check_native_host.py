"""Load the independent DLL into our own disposable Python fixture, never Steam."""
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from steambpf_module import NativeWindows, parse_status

payload=Path(__file__).resolve().parent.parent/'native'/'bin'/'SteamBPFHook.dll'
child=subprocess.Popen([sys.executable,'-u','-c',
    "import sys; print('fixture ready',flush=True); sys.stdin.read()"],
    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
    creationflags=subprocess.CREATE_NO_WINDOW)
try:
    assert child.stdout.readline().strip()==b'fixture ready'
    win=NativeWindows()
    win.inject(child.pid,payload)
    deadline=time.monotonic()+10
    while True:
        try:
            reply=win.exchange(child.pid,'PING',timeout=500)
            break
        except OSError:
            if time.monotonic()>=deadline:raise
    assert f'pid={child.pid}' in reply
    assert 'ready=0' in reply and 'error=client_not_loaded' in reply,reply
    try:parse_status(reply,child.pid)
    except RuntimeError as error:assert 'client_not_loaded' in str(error)
    else:raise AssertionError('Missing client was incorrectly accepted')
    # Verify successive pipe instances and refusal to activate an uninitialized module.
    reply=win.exchange(child.pid,'CONFIG protection=1 silent=1')
    assert reply.strip()=='ERR client_not_loaded',reply
    print('PASS: x64 loader, DLL initialization, pipe identity, repeated requests, and initialization failure.')
finally:
    child.communicate(timeout=10)
