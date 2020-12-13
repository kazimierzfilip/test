from unicorn import *
from capstone import *

import sys
sys.path.append("..")
from qiling import *

md = Cs(CS_ARCH_X86, CS_MODE_64)
stepCount = 0
blockCount = 0


def print_asm(ql, address, size):
    global stepCount
    stepCount+=1
    ql.nprint("\npc= ",ql.reg.arch_pc)
    #buf = ql.mem.read(address, size)
    #for i in md.disasm(buf, address):
    #    print(":: 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


def ql_hook_block_disasm(ql, address, size):
    global blockCount
    blockCount+=1
    ql.nprint("\n[+] Tracing basic block at 0x%x" % (address))


if __name__ == "__main__":
    #ql = Qiling(["rootfs/bin/bubble.elf"], "rootfs")
   # ql.hook_code(print_asm)
  #  ql.run()
 #   print('Steps: ', stepCount)
#
    #stepCount = 0
   # ql = Qiling(["rootfs/bin/bubble2.elf"], "rootfs")
   # ql.hook_code(print_asm)
  #  ql.run()
 #   print('Steps: ', stepCount)
#
    #stepCount = 0
    #ql = Qiling(["rootfs/bin/bubble3.elf"], "rootfs")
   # ql.hook_code(print_asm)
  #  ql.run()
 #   print('Steps: ', stepCount)
#
#    stepCount = 0
#    ql = Qiling(["rootfs/bin/testloop1.elf"], "rootfs")
#    ql.hook_code(print_asm)
#    ql.hook_block(ql_hook_block_disasm)
#    print("\npc= ",ql.reg.arch_pc)
#    ql.run()
#    print("\npc= ",ql.reg.arch_pc)
#    print('Steps: ', stepCount)
#    print('Blocks: ', blockCount)

#    stepCount = 0
#    blockCount = 0
#    ql = Qiling(["rootfs/bin/testloop2.elf"], "rootfs")
#    ql.hook_code(print_asm)
#    ql.hook_block(ql_hook_block_disasm)
#    ql.run()
#    print('Steps: ', stepCount)
#    print('Blocks: ', blockCount)

    stepCount = 0
    blockCount = 0
    ql = Qiling(["rootfs/bin/testloop3.elf"], "rootfs")
    ql.hook_code(print_asm)
    ql.hook_block(ql_hook_block_disasm)
    print("\npc= ",ql.reg.arch_pc)
    ql.run()
    print("\npc= ",ql.reg.arch_pc)
    print('loop 3 Steps: ', stepCount)
    print('Blocks: ', blockCount)

    stepCount = 0
    blockCount = 0
    ql = Qiling(["rootfs/bin/testloop4.elf"], "rootfs")
    ql.hook_code(print_asm)
    ql.hook_block(ql_hook_block_disasm)
    print("\npc= ",ql.reg.arch_pc)
    ql.run()
    print("\npc= ",ql.reg.arch_pc)
    print('Steps: ', stepCount)
    print('Blocks: ', blockCount)
