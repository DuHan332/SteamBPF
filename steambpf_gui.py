"""Bilingual console interface for the single-action local tool."""
import contextlib
import io
import queue
import sys
import threading
import tkinter as tk
import steambpf

BG='#0b1016'; PANEL='#101923'; EDGE='#263645'; TEXT='#d9e5ef'; MUTED='#728899'; CYAN='#62ddd2'; AMBER='#f7b955'; RED='#e94d44'

def create_window():
    root=tk.Tk()
    root.title('SteamBPF')
    root.geometry('760x540')
    root.resizable(False,False)
    root.configure(bg=BG)
    c=tk.Canvas(root,width=760,height=540,bg=BG,highlightthickness=0)
    c.pack(fill='both',expand=True)
    def text(x,y,value,size=10,color=TEXT,anchor='w',font='Consolas',**kw):
        return c.create_text(x,y,text=value,font=(font,size),fill=color,anchor=anchor,**kw)
    def line(x1,y1,x2,y2,color=EDGE,**kw):return c.create_line(x1,y1,x2,y2,fill=color,**kw)
    def panel(x1,y1,x2,y2):
        c.create_rectangle(x1,y1,x2,y2,fill=PANEL,outline=EDGE)
        for x,y,dx,dy in [(x1,y1,1,1),(x2,y1,-1,1),(x1,y2,1,-1),(x2,y2,-1,-1)]:
            line(x,y,x+dx*10,y,MUTED);line(x,y,x,y+dy*10,MUTED)
    text(28,30,'BPF',20,CYAN)
    text(110,25,'SteamBPF  /  LOCAL CONTROL',13)
    c.create_rectangle(612,17,732,48,fill=PANEL,outline=EDGE,tags='language')
    language_label=text(672,32,'中文  /  EN',10,CYAN,anchor='center',tags='language')
    line(28,67,732,67)
    text(28,93,'本地控制台',23,TEXT,font='Microsoft YaHei')
    panel(28,128,444,404);panel(460,128,732,404)
    text(48,151,'01   操作控制',10,MUTED)
    text(48,174,'一键执行 · 自动刷新',10,TEXT,font='Microsoft YaHei')
    # Mechanical bezel, bolt heads, and a single action button.
    c.create_oval(135,192,337,394,fill='#070c11',outline='#334651',width=2)
    c.create_oval(148,205,324,381,fill='#17212b',outline='#61717a',width=2)
    for x,y in [(163,219),(309,219),(163,365),(309,365)]:
        c.create_oval(x-3,y-3,x+3,y+3,fill='#75838d',outline='')
        line(x-2,y,x+2,y,'#28343e')
    disk=c.create_oval(158,215,314,371,fill=RED,outline='#ff8472',width=3,tags='launch')
    # Neutral power symbol.
    c.create_arc(222,243,250,271,start=135,extent=270,style='arc',outline='#fff1e6',width=3,tags='launch')
    line(236,239,236,256,'#fff1e6',width=3,tags='launch')
    launch_label=text(236,305,'执 行',22,'#fff5eb',anchor='center',font='Microsoft YaHei',tags='launch')
    text(236,335,'EXECUTE',10,'#ffd2c5',anchor='center',tags='launch')
    text(480,151,'02   执行步骤',10,MUTED)
    phases=['定位与检查','应用本地补丁','断线 / 重新上线','完成']
    dots=[];labels=[]
    for i,name in enumerate(phases):
        y=195+i*46
        if i<3:line(491,y+8,491,y+38)
        dots.append(c.create_oval(486,y-5,496,y+5,fill='#273744',outline=''))
        labels.append(text(510,y,name,11,MUTED,font='Microsoft YaHei'))
        text(710,y,'%02d'%(i+1),10,MUTED,anchor='e')
    panel(28,420,732,501)
    status=text(48,443,'就绪 · 请先启动 Steam，然后点击执行',10,TEXT,font='Microsoft YaHei')
    percent=text(712,443,'000%',12,CYAN,anchor='e')
    for i in range(40):
        x=48+i*16.6
        c.create_rectangle(x,466,x+12,478,fill='#23313d',outline='',tags='track')
    bars=[c.create_rectangle(48+i*16.6,466,60+i*16.6,478,fill=CYAN,outline='',state='hidden') for i in range(40)]
    translations = {
        'SteamBPF  /  LOCAL CONTROL': ('SteamBPF  /  本地控制', 'SteamBPF  /  LOCAL CONTROL'),
        '本地控制台': ('本地控制台', 'Local console'),
        '01   操作控制': ('01   操作控制', '01   CONTROL'),
        '一键执行 · 自动刷新': ('一键执行 · 自动刷新', 'One click / automatic refresh'),
        '执 行': ('执 行', 'RUN'),
        'EXECUTE': ('一键操作', 'EXECUTE'),
        '02   执行步骤': ('02   执行步骤', '02   WORKFLOW'),
        '定位与检查': ('定位与检查', 'Locate & check'),
        '应用本地补丁': ('应用本地补丁', 'Apply patch'),
        '断线 / 重新上线': ('断线 / 重新上线', 'Reconnect'),
        '完成': ('完成', 'Complete'),
        'ready': ('就绪 · 请先启动 Steam，然后点击执行', 'Ready / Start Steam, then click RUN'),
        'running': ('正在执行本地操作…', 'Running local operations...'),
        'success': ('执行完成 · 已调用上线与打开库', 'Complete / Online and library commands sent'),
        'missing': ('未找到 Steam · 请先启动 Steam 后重试', 'Steam not found / Start Steam and retry'),
        'mismatch': ('版本不匹配 · 补丁未执行', 'Version mismatch / Patch not applied'),
        'connection': ('连接处理失败 · 请检查权限后重试', 'Connection step failed / Check permissions'),
        'error': ('执行失败 · 请确认 Steam 已启动并允许管理员权限', 'Failed / Start Steam and allow administrator access'),
        'closing': ('正在执行 · 请等待完成后关闭', 'In progress / Please wait before closing'),
        'busy': ('执行中', 'BUSY'),
    }
    language=[0]
    state_key=['ready']
    localized=[]
    for item in c.find_all():
        if c.type(item)=='text':
            original=c.itemcget(item,'text')
            if original in translations: localized.append((item,original))
    events=queue.Queue();running=[False];poll_id=[None]
    def render_language():
        for item,key in localized:
            c.itemconfigure(item,text=translations[key][language[0]],font=('Microsoft YaHei' if language[0]==0 else 'Consolas', c.itemcget(item,'font').split()[-1]))
        c.itemconfigure(launch_label,text=translations['busy' if running[0] else '执 行'][language[0]])
        c.itemconfigure(status,text=translations[state_key[0]][language[0]])
        c.itemconfigure(language_label,text='中文  /  EN' if language[0]==0 else 'EN  /  中文')
        root.title('SteamBPF')
    def switch_language(event=None):
        language[0]=1-language[0]
        render_language()
    c.tag_bind('language','<Button-1>',switch_language)
    c.tag_bind('language','<Enter>',lambda e:c.configure(cursor='hand2'))
    c.tag_bind('language','<Leave>',lambda e:c.configure(cursor=''))
    def set_progress(value):
        value=max(0,min(100,float(value)))
        c.itemconfigure(percent,text='%03d%%'%value)
        for i,b in enumerate(bars):c.itemconfigure(b,state='normal' if i<round(value*.4) else 'hidden')
        stage=0 if value<15 else 1 if value<30 else 2 if value<100 else 3
        for i in range(4):
            c.itemconfigure(dots[i],fill=CYAN if i<=stage else '#273744')
            c.itemconfigure(labels[i],fill=TEXT if i<=stage else MUTED)
    def start(event=None):
        if running[0]:return
        running[0]=True;set_progress(0)
        c.itemconfigure(disk,fill='#983c37',outline='#cd6856')
        state_key[0]='running'
        render_language()
        c.itemconfigure(status,fill=AMBER)
        def work():
            try:
                with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                    steambpf.main(['--apply','--refresh','tcp'],progress=lambda v:events.put(('progress',v)))
                events.put(('success','success'))
            except BaseException as error:
                detail=str(error)
                if 'Expected one Steam' in detail or 'not loaded' in detail:message='missing'
                elif 'match' in detail:message='mismatch'
                elif 'No TCP disconnect' in detail:message='connection'
                else:message='error'
                events.put(('error',message))
        threading.Thread(target=work,daemon=True).start()
    def hover(inside):
        if not running[0]:c.itemconfigure(disk,fill='#ff6254' if inside else RED)
        c.configure(cursor='hand2' if inside and not running[0] else '')
    c.tag_bind('launch','<Button-1>',start)
    c.tag_bind('launch','<Enter>',lambda e:hover(True))
    c.tag_bind('launch','<Leave>',lambda e:hover(False))
    root.bind('<Return>',start)
    root.bind('<space>',start)
    def poll():
        while True:
            try:kind,value=events.get_nowait()
            except queue.Empty:break
            if kind=='progress':set_progress(value);continue
            running[0]=False
            c.itemconfigure(disk,fill=RED,outline='#ff8472')
            state_key[0]=value
            render_language()
            c.itemconfigure(status,fill=CYAN if kind=='success' else AMBER)
            if kind=='success':set_progress(100)
        poll_id[0]=root.after(40,poll)
    def cleanup(event):
        if event.widget==root and poll_id[0] is not None:
            root.after_cancel(poll_id[0]);poll_id[0]=None
    root.bind('<Destroy>',cleanup,add='+')
    def close():
        if running[0]:
            state_key[0]='closing';render_language();c.itemconfigure(status,fill=AMBER)
        else:root.destroy()
    root.protocol('WM_DELETE_WINDOW',close)
    # Expose minimal view hooks for offline UI verification.
    root.launch_action=start
    root.switch_language=switch_language
    root.console_canvas=c
    root.progress_text_id=percent
    root.status_text_id=status
    render_language()
    poll()
    return root

if __name__=='__main__':
    root=create_window()
    if '--ui-self-test' in sys.argv:root.update();root.destroy()
    else:root.mainloop()
