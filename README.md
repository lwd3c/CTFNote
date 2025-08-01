# CTFNote

## 1. Genscr 

```python
#!/usr/bin/python3

import sys
import os

if len(sys.argv) <= 1:
    print(f"Usage: {sys.argv[0]} BIN [LIBC] [HOST] [PORT]")
    print(f"Examples:")
    print(f"  {sys.argv[0]} ./chall")
    print(f"  {sys.argv[0]} ./chall ./libc.so.6")
    print(f"  {sys.argv[0]} ./chall 127.0.0.1 1337")
    print(f"  {sys.argv[0]} ./chall ./libc.so.6 127.0.0.1 1337")
    exit(1)

bin_path = sys.argv[1]
libc_path = None
host = ""
port = "0"

if len(sys.argv) >= 4 and sys.argv[2].count(".") == 3 and sys.argv[3].isdigit():
    host = sys.argv[2]
    port = sys.argv[3]
elif len(sys.argv) >= 5 and os.path.isfile(sys.argv[2]):
    libc_path = sys.argv[2]
    host = sys.argv[3]
    port = sys.argv[4]
elif len(sys.argv) >= 3 and os.path.isfile(sys.argv[2]):
    libc_path = sys.argv[2]

libc_line = f"libc = ELF('{libc_path}', checksec=False)" if libc_path else "# libc = ELF('', checksec=False)"

remote_line = f'p = remote("{host}", int("{port}"))' if host and port else 'p = remote(" ", " ")'

script = f'''#!/usr/bin/env python3

from pwn import *

exe = ELF('{bin_path}', checksec=False)
{libc_line}
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
r      = lambda n=4096, proc=None: proc.recv(n) if proc else p.recv(n)
rl     = lambda proc=None: proc.recvline() if proc else p.recvline()
ru     = lambda delim=b'\n', proc=None: proc.recvuntil(delim) if proc else p.recvuntil(delim)
ra     = lambda proc=None: proc.recvall() if proc else p.recvall()

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript=\"\"\"


        
        \"\"\")

if args.REMOTE:
    {remote_line}
else:
    p = process([exe.path])

GDB()

# Gud luk pwner !



p.interactive()
'''

if not os.path.exists('exploit.py'):
    with open('exploit.py', 'wt') as f:
        f.write(script)
else:
    print("[*] 'exploit.py' already exists, keeping existing version.")

os.chmod('exploit.py', 0o755)
os.system(f'chmod +x {bin_path}')
if libc_path:
    os.system(f'chmod +x {libc_path}')

os.system('code . exploit.py')

```
Sau đó copy file này vào /usr/local/bin và chmod+x là có thể sử dụng!
