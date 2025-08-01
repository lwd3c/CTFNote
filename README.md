# CTFNote

## 1. Genscr 

```python
#!/usr/bin/python3

import sys, os

script = f'''#!/usr/bin/env python3

from pwn import *

# exe = ELF('', checksec=False)
# libc = ELF('', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript=\'\'\'


        
        \'\'\')

if args.REMOTE:
    p = remote("{'{HOST}'}", int("{'{PORT}'}"))
else:
    {('p = process([exe.path])') if len(sys.argv) >= 2 else ("p = process([''])")}

GDB()

# Gud luk pwn !

p.interactive()
'''

if os.path.exists('exploit.py'):
    script = open('exploit.py', 'r').read()

if len(sys.argv) <= 1:
    print(f"Usage: {sys.argv[0]} BIN [LIBC] [HOST] [PORT]")
    print(f"Example:")
    print(f"    {sys.argv[0]} ./chall")
    print(f"    {sys.argv[0]} ./chall ./libc.so.6")
    print(f"    {sys.argv[0]} ./chall ./libc.so.6 127.0.0.1 1337")
    exit(0)

if len(sys.argv) > 1:
    os.system('chmod +x ' + sys.argv[1])
    script = script.replace("# exe = ELF('', checksec=False)", f"exe = ELF('{sys.argv[1]}', checksec=False)")

if len(sys.argv) > 2:
    os.system('chmod +x ' + sys.argv[2])
    script = script.replace("# libc = ELF('', checksec=False)", f"libc = ELF('{sys.argv[2]}', checksec=False)")

# Replace HOST and PORT placeholders
if len(sys.argv) > 4:
    host = sys.argv[3]
    port = sys.argv[4]
    script = script.replace("{'{HOST}'}", host)
    script = script.replace("{'{PORT}'}", port)
else:
    script = script.replace("{'{HOST}'}", "")
    script = script.replace("{'{PORT}'}", "0")

with open('exploit.py', 'wt') as f:
    f.write(script)

os.chmod('exploit.py', 0o755)
os.system('code . exploit.py')
```
Sau đó copy file này vào /usr/local/bin và chmod+x là có thể sử dụng!
