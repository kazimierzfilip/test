from qiling import *
import sys
sys.path.append("..")

stepCount = 0


class StringBuffer:
    def __init__(self):
        self.buffer = b''

    def read(self, n):
        ret = self.buffer[:n]
        self.buffer = self.buffer[n:]
        print('reading', ret)
        return ret

    def readline(self, end=b'\n'):
        ret = b''
        while True:
            c = self.read(1)
            ret += c
            if c == end:
                break
        return ret

    def write(self, string):
        self.buffer += string
        print('writing', string)
        return len(string)


def hook(ql, address, size):
    global stepCount
    stepCount += 1


class Fake_stdin:
    def read(self, size, *args, **kwargs):
    	with open('in.txt', 'r') as f:
        	return f.read().encode('utf-8')

    def fstat(fd, *args, **kwargs):
        return stat()

    def fileno(self, *args, **kwargs):
        # return file descriptor
        return 0


class stat:
    st_dev = 0
    st_ino = 0
    st_mode = 0
    st_nlink = 0
    st_uid = 0
    st_gid = 0
    st_rdev = 0
    st_size = 0
    st_blksize = 0
    st_blocks = 0
    st_atime = 0
    st_mtime = 0
    st_ctime = 0


if __name__ == "__main__":

    stepCount = 0
    ql = Qiling(["rootfs/x86_linux/bin/alg.elf"],
                "rootfs/x86_linux", stdin=Fake_stdin())
    ql.hook_code(hook)
    # ql.stdin.write(b'x')
    ql.run()
    print('Steps: ', stepCount)
