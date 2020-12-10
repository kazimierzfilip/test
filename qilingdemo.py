from unicorn import *
from capstone import *

import sys
sys.path.append("..")
from qiling import *

md = Cs(CS_ARCH_X86, CS_MODE_64)
stepCount = 0


def print_asm(ql, address, size):
    global stepCount
    stepCount+=1
    buf = ql.mem.read(address, size)
    for i in md.disasm(buf, address):
        print(":: 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


if __name__ == "__main__":
    ql = Qiling(["rootfs/bin/bubble.elf"], "rootfs")
    ql.hook_code(print_asm)
    ql.run()
    print('Steps: ', stepCount)