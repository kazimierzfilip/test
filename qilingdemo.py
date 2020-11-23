from qiling import *

root = "./"
path = "./test.elf"


def print_asm(ql, address, size):
    buf = ql.mem.read(address, size)
    for i in md.disasm(buf, address):
        print(":: 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


if __name__ == "__main__":
	ql = Qiling(path, rootfs)
	ql.hook_code(print_asm)
	ql.run()

#pip3 install qiling