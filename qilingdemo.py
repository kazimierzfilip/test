from unicorn import *
from capstone import *

import sys
sys.path.append("..")
from qiling import *

md = Cs(CS_ARCH_X86, CS_MODE_32)
stepCount = 0
stepCount2 = 0
blockCount = 0


def print_asm(ql, address, size):
    global stepCount
    stepCount+=1
    #print("pc= ",ql.reg.arch_pc)
    buf = ql.mem.read(address, size)
    for i in md.disasm(buf, address):
        global stepCount2
        stepCount2+=1
        #print(":: 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


def ql_hook_block_disasm(ql, address, size):
    global blockCount
    blockCount+=1
    #print("[+] Tracing basic block at 0x%x" % (address))


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
    ql = Qiling(["rootfs/x86_linux/bin/testloopCoutNotOptDouble.elf"], "rootfs/x86_linux")
    ql.hook_code(print_asm)
    ql.run()
    print('loop Steps: ', stepCount)

    stepCount = 0
    ql = Qiling(["rootfs/x86_linux/bin/testloopCoutNotOptDouble2.elf"], "rootfs/x86_linux")
    ql.hook_code(print_asm)
    ql.run()
    print('Steps: ', stepCount)

    stepCount = 0
    ql = Qiling(["rootfs/x86_linux/bin/testloopCoutNotOptDouble3.elf"], "rootfs/x86_linux")
    ql.hook_code(print_asm)
    ql.run()
    print('Steps: ', stepCount)
