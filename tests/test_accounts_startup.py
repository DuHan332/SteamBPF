"""Offline account-filter and startup tests. All OS side effects are simulated."""
import contextlib
import ctypes as C
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
import steambpf as app
import steambpf_accounts as accounts
import steambpf_startup as startup
from test_silent_mode import BASE,fixture,apply_plan

class AccountTests(unittest.TestCase):
    def test_identifier_validation(self):
        self.assertEqual(accounts.account_id(str(accounts.STEAM_ID_BASE+123)),123)
        self.assertEqual(accounts.account_id('123'),123)
        for value in ('0','-1','4294967296','abc',str(accounts.STEAM_ID_BASE)):
            with self.assertRaises(ValueError):accounts.account_id(value)

    def test_local_labels_and_unicode(self):
        text='''// comment
        "users" { "76561197960265851" { "PersonaName" "名字 \\"Hi\\"" "AccountName" "local" "MostRecent" "1" } }
        '''
        parsed=accounts.parse_vdf(text)
        self.assertEqual(parsed['users']['76561197960265851']['PersonaName'],'名字 "Hi"')
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'config';path.mkdir();(path/'loginusers.vdf').write_text(text,encoding='utf8')
            with patch.object(accounts.winreg,'OpenKey',side_effect=FileNotFoundError):
                result=accounts.local_accounts(directory)
            self.assertEqual([(a.id,a.current) for a in result],[(123,True)])

    def test_filter_control_flow(self):
        site=BASE+547;entry=BASE+0x10000+64
        original=app.SILENT_COMPARE+struct.pack('<i',100)
        code=accounts.filter_code(site,entry,original,123)
        self.assertEqual(code[:8],original[:8])
        self.assertEqual(code[14:23],bytes.fromhex('41 8B 87 04 02 00 00 85 C0'))
        self.assertEqual(code[29:34],b'\x3d'+struct.pack('<I',123))
        def target(op,disp):return entry+disp+4+struct.unpack_from('<i',code,disp)[0]
        taken=site+14+100;normal=site+14
        self.assertEqual(target(8,10),taken)
        self.assertEqual(target(23,25),normal)
        self.assertEqual(target(34,36),normal)
        self.assertEqual(target(40,41),taken)
        # Follow the recovered branch predicates using independently decoded targets.
        for field,owner in ((0,0),(0,123),(0,456),(1,123),(1,456)):
            observed=target(8,10) if field else target(23,25) if owner==0 else target(34,36) if owner==123 else target(40,41)
            self.assertEqual(observed,normal if not field and owner in (0,123) else taken)

    def test_metadata_corruption_rejected(self):
        site=BASE+547;allocation=BASE+0x10000
        original=app.SILENT_COMPARE+struct.pack('<i',100)
        block=accounts.filter_block(site,BASE,allocation,original,123)
        self.assertEqual(accounts.inspect_block(block,site,BASE,allocation),(original,123))
        for offset in (0,8,16,24,28,32,64,100):
            damaged=bytearray(block);damaged[offset]^=1
            with self.assertRaises(ValueError):accounts.inspect_block(bytes(damaged),site,BASE,allocation)

    def test_account_switch_all_games_and_standard_restore(self):
        memory=fixture();initial=bytes(memory);blocks={};freed=[]
        class FakeWindows:
            def read(self,h,address,size):
                if BASE<=address<BASE+len(memory):return bytes(memory[address-BASE:address-BASE+size])
                return blocks[address][:size]
            def allocate_near(self,*args):
                address=BASE+0x10000*(len(blocks)+1);blocks[address]=b'';return address
            def write(self,h,address,data):blocks[address]=data
            def seal(self,*args):pass
            def free(self,h,address):freed.append(address)
        win=FakeWindows()
        def plan(selected=None,silent=False,apply=True):
            return app.prepare_patch_plan(win,1,[(BASE,bytes(memory))],BASE,selected=selected,silent=silent,apply=apply)
        first,allocations,site=plan(123)
        self.assertEqual(site,BASE+547);self.assertEqual(len(allocations),1)
        apply_plan(memory,first)
        self.assertEqual(plan(123)[0],[])
        changed,_,_=plan(456);self.assertEqual(len(changed),1);apply_plan(memory,changed)
        all_games,_,_=plan(silent=True);apply_plan(memory,all_games)
        standard,_,_=plan();apply_plan(memory,standard)
        self.assertEqual(memory[547:561],initial[547:561])
        self.assertEqual(len(blocks),2)
        # Detached published code is retained to avoid freeing a block with an in-flight thread.
        self.assertEqual(freed,[])

    def test_dry_run_does_not_allocate(self):
        class NoWrites:
            def allocate_near(self,*args):raise AssertionError('Dry run allocated memory')
        app.prepare_patch_plan(NoWrites(),1,[(BASE,bytes(fixture()))],BASE,selected=123,apply=False)

class StartupTests(unittest.TestCase):
    def test_desktop_token_launch_and_handle_cleanup(self):
        self.assertEqual(C.sizeof(startup.STARTUPINFO),104)
        self.assertEqual(C.sizeof(startup.PROCESSINFO),24)
        events=[];closed=[]
        class Win:
            def open(self,*args):events.append(('open',args));return 10
            def close(self,handle):closed.append(getattr(handle,'value',handle))
        def shell_pid(hwnd,pid):pid._obj.value=456;return 1
        def open_token(process,access,token):token._obj.value=20;return True
        def duplicate(token,access,attrs,level,kind,primary):primary._obj.value=30;return True
        def create(token,flags,exe,command,creation,env,cwd,si,pi):
            self.assertEqual(token.value,30)
            self.assertEqual(flags,1)
            self.assertEqual(command.value,'"C:\\Steam\\steam.exe"')
            self.assertEqual(si._obj.lpDesktop,'winsta0\\default')
            pi._obj.process=40;pi._obj.thread=50
            events.append('created');return True
        functions={'GetShellWindow':lambda:1,'GetWindowThreadProcessId':shell_pid,
                   'OpenProcessToken':open_token,'DuplicateTokenEx':duplicate,'CreateProcessWithTokenW':create}
        with patch.object(app,'api',side_effect=lambda dll,name,*args:functions[name]),patch.object(startup.C,'WinDLL',return_value=object()):
            startup.launch_on_desktop(Path('C:/Steam/steam.exe'),Win())
        self.assertIn('created',events)
        self.assertCountEqual(closed,[50,40,30,20,10])

    def setup_environment(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        directory=Path(temporary.name);(directory/'steam.exe').touch()
        clock=[0.0];events=[]
        def sleep(seconds):clock[0]+=seconds
        return directory,clock,events,sleep

    def test_graceful_exit_then_start_then_wait_module(self):
        directory,clock,events,sleep=self.setup_environment()
        class Win:
            checks=iter(([123],[123],[]))
            loads=0
            def process_ids(self):return next(self.checks)
            def find(self):
                self.loads+=1;events.append('find')
                if self.loads<3:raise RuntimeError('steamclient64.dll is not loaded.')
                return 456,BASE,2048
        result=startup.cold_start(Win(),directory=directory,clock=lambda:clock[0],sleep=sleep,
            send_uri=lambda uri:events.append(uri),launch=lambda *a:events.append('launch'))
        self.assertEqual(result,(456,BASE,2048))
        self.assertEqual(events[:2],['steam://exit','launch'])

    def test_shutdown_timeout_never_kills_or_launches(self):
        directory,clock,events,sleep=self.setup_environment()
        class Win:
            def process_ids(self):return [123]
        with self.assertRaisesRegex(RuntimeError,'did not exit'):
            startup.cold_start(Win(),directory=directory,clock=lambda:clock[0],sleep=sleep,
                send_uri=lambda uri:events.append(uri),launch=lambda *a:events.append('launch'))
        self.assertEqual(events,['steam://exit'])

    def test_start_without_running_steam(self):
        directory,clock,events,sleep=self.setup_environment()
        class Win:
            def process_ids(self):return []
            def find(self):return 456,BASE,2048
        startup.cold_start(Win(),directory=directory,clock=lambda:clock[0],sleep=sleep,
            send_uri=lambda uri:events.append(uri),launch=lambda *a:events.append('launch'))
        self.assertEqual(events,['launch'])

    def test_module_timeout_is_bounded(self):
        directory,clock,events,sleep=self.setup_environment()
        class Win:
            def process_ids(self):return []
            def find(self):raise RuntimeError('steamclient64.dll is not loaded.')
        with self.assertRaisesRegex(RuntimeError,'timed out'):
            startup.cold_start(Win(),directory=directory,clock=lambda:clock[0],sleep=sleep,
                send_uri=lambda uri:None,launch=lambda *a:None)
        self.assertLess(clock[0],91)

if __name__=='__main__':unittest.main()
