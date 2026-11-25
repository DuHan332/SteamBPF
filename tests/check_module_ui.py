"""Exercise the GUI with a simulated backend; never load a DLL or access Steam."""
from pathlib import Path
import sys
import time
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
import steambpf_gui as gui

calls=[]
def run(**options):
    calls.append(options)
    for value in (5,20,55,80,100):options['progress'](value)

with patch.object(gui.steambpf_module,'run',side_effect=run):
    root=gui.create_window();root.withdraw();root.update()
    try:
        for silent,restart in ((False,False),(True,False),(False,True),(True,True)):
            root.select_silent(silent)
            root.select_cold(restart)
            root.launch_action()
            deadline=time.monotonic()+3
            while time.monotonic()<deadline:
                root.update()
                if root.console_canvas.itemcget(root.progress_text_id,'text')=='100%':break
                time.sleep(.02)
            assert root.console_canvas.itemcget(root.progress_text_id,'text')=='100%'
            assert calls[-1]['silent']==silent
            assert calls[-1]['cold']==restart
            assert 'account' not in calls[-1]
            root.switch_language();root.update()
            assert 'Complete' in root.console_canvas.itemcget(root.status_text_id,'text')
            root.switch_language()
    finally:root.destroy()
print('PASS: silent checkbox, cold-start combinations, completion, and both languages.')
