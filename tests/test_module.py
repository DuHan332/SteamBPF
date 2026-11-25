"""Offline controller tests. No Steam process or remote server is accessed."""
import json
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import steambpf_module as module


def status(pid=42, **fields):
    values = dict(version=2, pid=pid, ready=1, protection=1, silent=0)
    values.update(fields)
    return 'OK ' + ' '.join(f'{key}={value}' for key, value in values.items())


class ControllerTests(unittest.TestCase):
    def test_handshake_rejects_wrong_process_version_and_failed_initialization(self):
        for response in (status(43), status(version=1), status(ready=0, error='signature_mismatch'),
                         status()+' pid=42', 'ERR invalid_config', 'OK nonsense'):
            with self.subTest(response=response), self.assertRaises(RuntimeError):
                module.parse_status(response,42)

    def test_silent_configuration(self):
        self.assertEqual(module.configuration(), 'CONFIG protection=1 silent=0')
        self.assertEqual(module.configuration(True), 'CONFIG protection=1 silent=1')

    def test_configuration_acknowledgement_controls_completion(self):
        calls=[]
        class Win:
            def find(self): return 42,0,0
            def inject(self,pid,path): calls.append(('inject',pid))
            def exchange(self,pid,text,**kwargs):
                calls.append(text)
                return status(silent=int(text.startswith('CONFIG')))
        progress=[]
        module.run(silent=True,win=Win(),payload='module.dll',progress=progress.append)
        self.assertEqual(calls, [('inject',42),'PING','CONFIG protection=1 silent=1'])
        self.assertEqual(progress[-1],100)
        with self.assertRaisesRegex(RuntimeError,'not acknowledged'):
            module.run(silent=False,win=Win(),payload='module.dll')

    def test_initialization_failure_never_sends_configuration(self):
        calls=[]
        class Win:
            def find(self): return 42,0,0
            def inject(self,*args): pass
            def exchange(self,pid,text,**kwargs):
                calls.append(text); return status(ready=0,error='signature_mismatch')
        progress=[]
        with self.assertRaisesRegex(RuntimeError,'signature_mismatch'):
            module.run(win=Win(),payload='module.dll',progress=progress.append)
        self.assertEqual(calls,['PING']); self.assertNotIn(100,progress)

    def test_payload_hash_and_persistent_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); data=b'offline test fixture'
            (root/module.MODULE).write_bytes(data)
            (root/'module.json').write_text(json.dumps(dict(protocol=2,sha256=hashlib.sha256(data).hexdigest())))
            with patch.dict(os.environ,LOCALAPPDATA=str(root/'cache')):
                path=module.verified_payload(root)
                self.assertEqual(path.read_bytes(),data)
                self.assertEqual(module.verified_payload(root),path)
                path.write_bytes(b'changed')
                with self.assertRaisesRegex(RuntimeError,'cached payload'):
                    module.verified_payload(root)

    def test_cold_start_does_not_use_legacy_refresh(self):
        class Win:
            def inject(self,*args): pass
            def exchange(self,*args,**kwargs): return status()
        with patch('steambpf_startup.cold_start',return_value=(42,0,0)) as restart, patch('steambpf.refresh') as refresh:
            module.run(cold=True,win=Win(),payload='module.dll')
        restart.assert_called_once(); refresh.assert_not_called()


if __name__=='__main__': unittest.main()
