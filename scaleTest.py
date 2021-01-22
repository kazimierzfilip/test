import sys
sys.path.append("..")
from qiling import *

stepCount = 0

def hook(ql, address, size):
    global stepCount
    stepCount+=1


if __name__ == "__main__":

    stepCount = 0
    ql = Qiling(["rootfs/x86_linux/bin/test1.elf"], "rootfs/x86_linux")
    ql.hook_code(hook)
    ql.run()
    print('Steps empty: ', stepCount)

    stepCount = 0
    ql = Qiling(["rootfs/x86_linux/bin/test2.elf"], "rootfs/x86_linux")
    ql.hook_code(hook)
    ql.run()
    print('Steps 100: ', stepCount)

    stepCount = 0
    ql = Qiling(["rootfs/x86_linux/bin/test3.elf"], "rootfs/x86_linux")
    ql.hook_code(hook)
    ql.run()
    print('Steps 10 000: ', stepCount)

    stepCount = 0
    ql = Qiling(["rootfs/x86_linux/bin/test4.elf"], "rootfs/x86_linux")
    ql.hook_code(hook)
    ql.run()
    print('Steps 1 000 000: ', stepCount)
