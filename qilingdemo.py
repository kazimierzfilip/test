from unicorn import *
from capstone import *
from timeit import default_timer as timer


import sys
sys.path.append("..")
from qiling import *

md = Cs(CS_ARCH_X86, CS_MODE_32)
stepCount = 0
stepCount2 = 0
blockCount = 0
instStart = timer()
first = 1


def print_asm(ql, address, size):
    global stepCount
    stepCount+=1
    global first
    if first:
        inst = timer()
        global instStart
        print('first instr started', instStart-inst)
        first=0
    #print("pc= ",ql.reg.arch_pc)
    #buf = ql.mem.read(address, size)
    #for i in md.disasm(buf, address):
    #    global stepCount2
    #    stepCount2+=1
        #print(":: 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


#def ql_hook_block_disasm(ql, address, size):
#    global blockCount
#    blockCount+=1
#    #print("[+] Tracing basic block at 0x%x" % (address))


if __name__ == "__main__":

    start = timer()
    stepCount = 0
    ql = Qiling(["rootfs/x86_linux/bin/empty.elf"], "rootfs/x86_linux")
    ql.hook_code(print_asm)
    end = timer()
    print('meanwhile before run',end - start)    
    start = timer()
    ql.run()
    print('Steps: ', stepCount)
    end = timer()
    print('end', end - start)
