#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <cerrno>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>
#include <linux/sysctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/net.h>

#define WORK_DIR    "/checker/rundir/"
#define TEST_DIR    WORK_DIR "../tests/"
#define TEST_IN     TEST_DIR "in.txt"
#define TEST_OUT    TEST_DIR "out.txt"

#define STANDARD_MAX_OUTPUT (1024*1024)
#define WORK_UID    1001

using namespace std;

#include <iostream>
#include <iomanip>
#include <map>
#include <string>

#define DE
#ifdef DEB
#define D (cout << __LINE__ << endl)
#else
#define D 0
#endif

char * prog_name;

void help(){
  cerr << "Help for " << prog_name << endl
       << "\t-s stack - max rozmiar stosu w kB [int]" << endl
       << "\t-h heap - max rozmiar sterty w kB [int]" << endl
       << "\t-t time - max czas działania w s [int]" << endl
       << "\t-o num - max rozmiar wyjścia w B [int] (zlicza bajty wypisane za pomocą write(2), standardowo "
            << STANDARD_MAX_OUTPUT/1024 << "kB)" << endl
       ;
}

int get_mem_usage_kb(pid_t pid){
  const int line_size = 200;
  char fname[30], line[line_size];
  FILE *file;
  int retval = -1;
  sprintf(fname, "/proc/%d/status", pid);
  file = fopen(fname, "r");
  if(!file){
    cerr << "no such pid " << pid << endl;
    return -1;
  }
  while(fgets(line, line_size, file)){
    if(strstr(line, "VmPeak:")){
      sscanf(line, "VmPeak: %d kB", &retval);
      break;
    }
  }
  fclose(file);
  return retval;
}

int main(int argc, char **argv){
    prog_name = argv[0];
    pid_t child;

    map<string, int> sys_n2v;
map<int, string> sys_v2n;
sys_n2v["SYS__sysctl"] = SYS__sysctl;
sys_n2v["SYS_access"] = SYS_access;
sys_n2v["SYS_acct"] = SYS_acct;
sys_n2v["SYS_add_key"] = SYS_add_key;
sys_n2v["SYS_adjtimex"] = SYS_adjtimex;
sys_n2v["SYS_afs_syscall"] = SYS_afs_syscall;
sys_n2v["SYS_alarm"] = SYS_alarm;
sys_n2v["SYS_brk"] = SYS_brk;
sys_n2v["SYS_capget"] = SYS_capget;
sys_n2v["SYS_capset"] = SYS_capset;
sys_n2v["SYS_chdir"] = SYS_chdir;
sys_n2v["SYS_chmod"] = SYS_chmod;
sys_n2v["SYS_chown"] = SYS_chown;
sys_n2v["SYS_chroot"] = SYS_chroot;
sys_n2v["SYS_clock_getres"] = SYS_clock_getres;
sys_n2v["SYS_clock_gettime"] = SYS_clock_gettime;
sys_n2v["SYS_clock_nanosleep"] = SYS_clock_nanosleep;
sys_n2v["SYS_clock_settime"] = SYS_clock_settime;
sys_n2v["SYS_clone"] = SYS_clone;
sys_n2v["SYS_close"] = SYS_close;
sys_n2v["SYS_creat"] = SYS_creat;
sys_n2v["SYS_create_module"] = SYS_create_module;
sys_n2v["SYS_delete_module"] = SYS_delete_module;
sys_n2v["SYS_dup"] = SYS_dup;
sys_n2v["SYS_dup2"] = SYS_dup2;
sys_n2v["SYS_dup3"] = SYS_dup3;
sys_n2v["SYS_epoll_create"] = SYS_epoll_create;
sys_n2v["SYS_epoll_create1"] = SYS_epoll_create1;
sys_n2v["SYS_epoll_ctl"] = SYS_epoll_ctl;
sys_n2v["SYS_epoll_pwait"] = SYS_epoll_pwait;
sys_n2v["SYS_epoll_wait"] = SYS_epoll_wait;
sys_n2v["SYS_eventfd"] = SYS_eventfd;
sys_n2v["SYS_eventfd2"] = SYS_eventfd2;
sys_n2v["SYS_execve"] = SYS_execve;
sys_n2v["SYS_exit"] = SYS_exit;
sys_n2v["SYS_exit_group"] = SYS_exit_group;
sys_n2v["SYS_faccessat"] = SYS_faccessat;
sys_n2v["SYS_fadvise64"] = SYS_fadvise64;
sys_n2v["SYS_fallocate"] = SYS_fallocate;
sys_n2v["SYS_fchdir"] = SYS_fchdir;
sys_n2v["SYS_fchmod"] = SYS_fchmod;
sys_n2v["SYS_fchmodat"] = SYS_fchmodat;
sys_n2v["SYS_fchown"] = SYS_fchown;
sys_n2v["SYS_fchownat"] = SYS_fchownat;
sys_n2v["SYS_fcntl"] = SYS_fcntl;
sys_n2v["SYS_fdatasync"] = SYS_fdatasync;
sys_n2v["SYS_fgetxattr"] = SYS_fgetxattr;
sys_n2v["SYS_flistxattr"] = SYS_flistxattr;
sys_n2v["SYS_flock"] = SYS_flock;
sys_n2v["SYS_fork"] = SYS_fork;
sys_n2v["SYS_fremovexattr"] = SYS_fremovexattr;
sys_n2v["SYS_fsetxattr"] = SYS_fsetxattr;
sys_n2v["SYS_fstat"] = SYS_fstat;
sys_n2v["SYS_fstatfs"] = SYS_fstatfs;
sys_n2v["SYS_fsync"] = SYS_fsync;
sys_n2v["SYS_ftruncate"] = SYS_ftruncate;
sys_n2v["SYS_futex"] = SYS_futex;
sys_n2v["SYS_futimesat"] = SYS_futimesat;
sys_n2v["SYS_get_kernel_syms"] = SYS_get_kernel_syms;
sys_n2v["SYS_get_mempolicy"] = SYS_get_mempolicy;
sys_n2v["SYS_get_robust_list"] = SYS_get_robust_list;
sys_n2v["SYS_get_thread_area"] = SYS_get_thread_area;
sys_n2v["SYS_getcwd"] = SYS_getcwd;
sys_n2v["SYS_getdents"] = SYS_getdents;
sys_n2v["SYS_getdents64"] = SYS_getdents64;
sys_n2v["SYS_getegid"] = SYS_getegid;
sys_n2v["SYS_geteuid"] = SYS_geteuid;
sys_n2v["SYS_getgid"] = SYS_getgid;
sys_n2v["SYS_getgroups"] = SYS_getgroups;
sys_n2v["SYS_getitimer"] = SYS_getitimer;
sys_n2v["SYS_getpgid"] = SYS_getpgid;
sys_n2v["SYS_getpgrp"] = SYS_getpgrp;
sys_n2v["SYS_getpid"] = SYS_getpid;
sys_n2v["SYS_getpmsg"] = SYS_getpmsg;
sys_n2v["SYS_getppid"] = SYS_getppid;
sys_n2v["SYS_getpriority"] = SYS_getpriority;
sys_n2v["SYS_getresgid"] = SYS_getresgid;
sys_n2v["SYS_getresuid"] = SYS_getresuid;
sys_n2v["SYS_getrlimit"] = SYS_getrlimit;
sys_n2v["SYS_getrusage"] = SYS_getrusage;
sys_n2v["SYS_getsid"] = SYS_getsid;
sys_n2v["SYS_gettid"] = SYS_gettid;
sys_n2v["SYS_gettimeofday"] = SYS_gettimeofday;
sys_n2v["SYS_getuid"] = SYS_getuid;
sys_n2v["SYS_getxattr"] = SYS_getxattr;
sys_n2v["SYS_init_module"] = SYS_init_module;
sys_n2v["SYS_inotify_add_watch"] = SYS_inotify_add_watch;
sys_n2v["SYS_inotify_init"] = SYS_inotify_init;
sys_n2v["SYS_inotify_init1"] = SYS_inotify_init1;
sys_n2v["SYS_inotify_rm_watch"] = SYS_inotify_rm_watch;
sys_n2v["SYS_io_cancel"] = SYS_io_cancel;
sys_n2v["SYS_io_destroy"] = SYS_io_destroy;
sys_n2v["SYS_io_getevents"] = SYS_io_getevents;
sys_n2v["SYS_io_setup"] = SYS_io_setup;
sys_n2v["SYS_io_submit"] = SYS_io_submit;
sys_n2v["SYS_ioctl"] = SYS_ioctl;
sys_n2v["SYS_ioperm"] = SYS_ioperm;
sys_n2v["SYS_iopl"] = SYS_iopl;
sys_n2v["SYS_ioprio_get"] = SYS_ioprio_get;
sys_n2v["SYS_ioprio_set"] = SYS_ioprio_set;
sys_n2v["SYS_kexec_load"] = SYS_kexec_load;
sys_n2v["SYS_keyctl"] = SYS_keyctl;
sys_n2v["SYS_kill"] = SYS_kill;
sys_n2v["SYS_lchown"] = SYS_lchown;
sys_n2v["SYS_lgetxattr"] = SYS_lgetxattr;
sys_n2v["SYS_link"] = SYS_link;
sys_n2v["SYS_linkat"] = SYS_linkat;
sys_n2v["SYS_listxattr"] = SYS_listxattr;
sys_n2v["SYS_llistxattr"] = SYS_llistxattr;
sys_n2v["SYS_lookup_dcookie"] = SYS_lookup_dcookie;
sys_n2v["SYS_lremovexattr"] = SYS_lremovexattr;
sys_n2v["SYS_lseek"] = SYS_lseek;
sys_n2v["SYS_lsetxattr"] = SYS_lsetxattr;
sys_n2v["SYS_lstat"] = SYS_lstat;
sys_n2v["SYS_madvise"] = SYS_madvise;
sys_n2v["SYS_mbind"] = SYS_mbind;
sys_n2v["SYS_migrate_pages"] = SYS_migrate_pages;
sys_n2v["SYS_mincore"] = SYS_mincore;
sys_n2v["SYS_mkdir"] = SYS_mkdir;
sys_n2v["SYS_mkdirat"] = SYS_mkdirat;
sys_n2v["SYS_mknod"] = SYS_mknod;
sys_n2v["SYS_mknodat"] = SYS_mknodat;
sys_n2v["SYS_mlock"] = SYS_mlock;
sys_n2v["SYS_mlockall"] = SYS_mlockall;
sys_n2v["SYS_mmap"] = SYS_mmap;
sys_n2v["SYS_modify_ldt"] = SYS_modify_ldt;
sys_n2v["SYS_mount"] = SYS_mount;
sys_n2v["SYS_move_pages"] = SYS_move_pages;
sys_n2v["SYS_mprotect"] = SYS_mprotect;
sys_n2v["SYS_mq_getsetattr"] = SYS_mq_getsetattr;
sys_n2v["SYS_mq_notify"] = SYS_mq_notify;
sys_n2v["SYS_mq_open"] = SYS_mq_open;
sys_n2v["SYS_mq_timedreceive"] = SYS_mq_timedreceive;
sys_n2v["SYS_mq_timedsend"] = SYS_mq_timedsend;
sys_n2v["SYS_mq_unlink"] = SYS_mq_unlink;
sys_n2v["SYS_mremap"] = SYS_mremap;
sys_n2v["SYS_msync"] = SYS_msync;
sys_n2v["SYS_munlock"] = SYS_munlock;
sys_n2v["SYS_munlockall"] = SYS_munlockall;
sys_n2v["SYS_munmap"] = SYS_munmap;
sys_n2v["SYS_nanosleep"] = SYS_nanosleep;
sys_n2v["SYS_nfsservctl"] = SYS_nfsservctl;
sys_n2v["SYS_open"] = SYS_open;
sys_n2v["SYS_openat"] = SYS_openat;
sys_n2v["SYS_pause"] = SYS_pause;
sys_n2v["SYS_perf_event_open"] = SYS_perf_event_open;
sys_n2v["SYS_personality"] = SYS_personality;
sys_n2v["SYS_pipe"] = SYS_pipe;
sys_n2v["SYS_pipe2"] = SYS_pipe2;
sys_n2v["SYS_pivot_root"] = SYS_pivot_root;
sys_n2v["SYS_poll"] = SYS_poll;
sys_n2v["SYS_ppoll"] = SYS_ppoll;
sys_n2v["SYS_prctl"] = SYS_prctl;
sys_n2v["SYS_pread64"] = SYS_pread64;
sys_n2v["SYS_preadv"] = SYS_preadv;
sys_n2v["SYS_pselect6"] = SYS_pselect6;
sys_n2v["SYS_ptrace"] = SYS_ptrace;
sys_n2v["SYS_putpmsg"] = SYS_putpmsg;
sys_n2v["SYS_pwrite64"] = SYS_pwrite64;
sys_n2v["SYS_pwritev"] = SYS_pwritev;
sys_n2v["SYS_query_module"] = SYS_query_module;
sys_n2v["SYS_quotactl"] = SYS_quotactl;
sys_n2v["SYS_read"] = SYS_read;
sys_n2v["SYS_readahead"] = SYS_readahead;
sys_n2v["SYS_readlink"] = SYS_readlink;
sys_n2v["SYS_readlinkat"] = SYS_readlinkat;
sys_n2v["SYS_readv"] = SYS_readv;
sys_n2v["SYS_reboot"] = SYS_reboot;
sys_n2v["SYS_remap_file_pages"] = SYS_remap_file_pages;
sys_n2v["SYS_removexattr"] = SYS_removexattr;
sys_n2v["SYS_rename"] = SYS_rename;
sys_n2v["SYS_renameat"] = SYS_renameat;
sys_n2v["SYS_request_key"] = SYS_request_key;
sys_n2v["SYS_restart_syscall"] = SYS_restart_syscall;
sys_n2v["SYS_rmdir"] = SYS_rmdir;
sys_n2v["SYS_rt_sigaction"] = SYS_rt_sigaction;
sys_n2v["SYS_rt_sigpending"] = SYS_rt_sigpending;
sys_n2v["SYS_rt_sigprocmask"] = SYS_rt_sigprocmask;
sys_n2v["SYS_rt_sigqueueinfo"] = SYS_rt_sigqueueinfo;
sys_n2v["SYS_rt_sigreturn"] = SYS_rt_sigreturn;
sys_n2v["SYS_rt_sigsuspend"] = SYS_rt_sigsuspend;
sys_n2v["SYS_rt_sigtimedwait"] = SYS_rt_sigtimedwait;
sys_n2v["SYS_rt_tgsigqueueinfo"] = SYS_rt_tgsigqueueinfo;
sys_n2v["SYS_sched_get_priority_max"] = SYS_sched_get_priority_max;
sys_n2v["SYS_sched_get_priority_min"] = SYS_sched_get_priority_min;
sys_n2v["SYS_sched_getaffinity"] = SYS_sched_getaffinity;
sys_n2v["SYS_sched_getparam"] = SYS_sched_getparam;
sys_n2v["SYS_sched_getscheduler"] = SYS_sched_getscheduler;
sys_n2v["SYS_sched_rr_get_interval"] = SYS_sched_rr_get_interval;
sys_n2v["SYS_sched_setaffinity"] = SYS_sched_setaffinity;
sys_n2v["SYS_sched_setparam"] = SYS_sched_setparam;
sys_n2v["SYS_sched_setscheduler"] = SYS_sched_setscheduler;
sys_n2v["SYS_sched_yield"] = SYS_sched_yield;
sys_n2v["SYS_select"] = SYS_select;
sys_n2v["SYS_sendfile"] = SYS_sendfile;
sys_n2v["SYS_set_mempolicy"] = SYS_set_mempolicy;
sys_n2v["SYS_set_robust_list"] = SYS_set_robust_list;
sys_n2v["SYS_set_thread_area"] = SYS_set_thread_area;
sys_n2v["SYS_set_tid_address"] = SYS_set_tid_address;
sys_n2v["SYS_setdomainname"] = SYS_setdomainname;
sys_n2v["SYS_setfsgid"] = SYS_setfsgid;
sys_n2v["SYS_setfsuid"] = SYS_setfsuid;
sys_n2v["SYS_setgid"] = SYS_setgid;
sys_n2v["SYS_setgroups"] = SYS_setgroups;
sys_n2v["SYS_sethostname"] = SYS_sethostname;
sys_n2v["SYS_setitimer"] = SYS_setitimer;
sys_n2v["SYS_setpgid"] = SYS_setpgid;
sys_n2v["SYS_setpriority"] = SYS_setpriority;
sys_n2v["SYS_setregid"] = SYS_setregid;
sys_n2v["SYS_setresgid"] = SYS_setresgid;
sys_n2v["SYS_setresuid"] = SYS_setresuid;
sys_n2v["SYS_setreuid"] = SYS_setreuid;
sys_n2v["SYS_setrlimit"] = SYS_setrlimit;
sys_n2v["SYS_setsid"] = SYS_setsid;
sys_n2v["SYS_settimeofday"] = SYS_settimeofday;
sys_n2v["SYS_setuid"] = SYS_setuid;
sys_n2v["SYS_setxattr"] = SYS_setxattr;
sys_n2v["SYS_sigaltstack"] = SYS_sigaltstack;
sys_n2v["SYS_signalfd"] = SYS_signalfd;
sys_n2v["SYS_signalfd4"] = SYS_signalfd4;
sys_n2v["SYS_splice"] = SYS_splice;
sys_n2v["SYS_stat"] = SYS_stat;
sys_n2v["SYS_statfs"] = SYS_statfs;
sys_n2v["SYS_swapoff"] = SYS_swapoff;
sys_n2v["SYS_swapon"] = SYS_swapon;
sys_n2v["SYS_symlink"] = SYS_symlink;
sys_n2v["SYS_symlinkat"] = SYS_symlinkat;
sys_n2v["SYS_sync"] = SYS_sync;
sys_n2v["SYS_sync_file_range"] = SYS_sync_file_range;
sys_n2v["SYS_sysfs"] = SYS_sysfs;
sys_n2v["SYS_sysinfo"] = SYS_sysinfo;
sys_n2v["SYS_syslog"] = SYS_syslog;
sys_n2v["SYS_tee"] = SYS_tee;
sys_n2v["SYS_tgkill"] = SYS_tgkill;
sys_n2v["SYS_time"] = SYS_time;
sys_n2v["SYS_timer_create"] = SYS_timer_create;
sys_n2v["SYS_timer_delete"] = SYS_timer_delete;
sys_n2v["SYS_timer_getoverrun"] = SYS_timer_getoverrun;
sys_n2v["SYS_timer_gettime"] = SYS_timer_gettime;
sys_n2v["SYS_timer_settime"] = SYS_timer_settime;
sys_n2v["SYS_timerfd_create"] = SYS_timerfd_create;
sys_n2v["SYS_timerfd_gettime"] = SYS_timerfd_gettime;
sys_n2v["SYS_timerfd_settime"] = SYS_timerfd_settime;
sys_n2v["SYS_times"] = SYS_times;
sys_n2v["SYS_tkill"] = SYS_tkill;
sys_n2v["SYS_truncate"] = SYS_truncate;
sys_n2v["SYS_umask"] = SYS_umask;
sys_n2v["SYS_umount2"] = SYS_umount2;
sys_n2v["SYS_uname"] = SYS_uname;
sys_n2v["SYS_unlink"] = SYS_unlink;
sys_n2v["SYS_unlinkat"] = SYS_unlinkat;
sys_n2v["SYS_unshare"] = SYS_unshare;
sys_n2v["SYS_uselib"] = SYS_uselib;
sys_n2v["SYS_ustat"] = SYS_ustat;
sys_n2v["SYS_utime"] = SYS_utime;
sys_n2v["SYS_utimensat"] = SYS_utimensat;
sys_n2v["SYS_utimes"] = SYS_utimes;
sys_n2v["SYS_vfork"] = SYS_vfork;
sys_n2v["SYS_vhangup"] = SYS_vhangup;
sys_n2v["SYS_vmsplice"] = SYS_vmsplice;
sys_n2v["SYS_vserver"] = SYS_vserver;
sys_n2v["SYS_wait4"] = SYS_wait4;
sys_n2v["SYS_waitid"] = SYS_waitid;
sys_n2v["SYS_write"] = SYS_write;
sys_n2v["SYS_writev"] = SYS_writev;
sys_n2v["SYS_accept"] = SYS_accept;
sys_n2v["SYS_accept4"] = SYS_accept4;
sys_n2v["SYS_arch_prctl"] = SYS_arch_prctl;
sys_n2v["SYS_bind"] = SYS_bind;
sys_n2v["SYS_connect"] = SYS_connect;
sys_n2v["SYS_epoll_ctl_old"] = SYS_epoll_ctl_old;
sys_n2v["SYS_epoll_wait_old"] = SYS_epoll_wait_old;
sys_n2v["SYS_getpeername"] = SYS_getpeername;
sys_n2v["SYS_getsockname"] = SYS_getsockname;
sys_n2v["SYS_getsockopt"] = SYS_getsockopt;
sys_n2v["SYS_listen"] = SYS_listen;
sys_n2v["SYS_msgctl"] = SYS_msgctl;
sys_n2v["SYS_msgget"] = SYS_msgget;
sys_n2v["SYS_msgrcv"] = SYS_msgrcv;
sys_n2v["SYS_msgsnd"] = SYS_msgsnd;
sys_n2v["SYS_newfstatat"] = SYS_newfstatat;
sys_n2v["SYS_recvfrom"] = SYS_recvfrom;
sys_n2v["SYS_recvmsg"] = SYS_recvmsg;
sys_n2v["SYS_security"] = SYS_security;
sys_n2v["SYS_semctl"] = SYS_semctl;
sys_n2v["SYS_semget"] = SYS_semget;
sys_n2v["SYS_semop"] = SYS_semop;
sys_n2v["SYS_semtimedop"] = SYS_semtimedop;
sys_n2v["SYS_sendmsg"] = SYS_sendmsg;
sys_n2v["SYS_sendto"] = SYS_sendto;
sys_n2v["SYS_setsockopt"] = SYS_setsockopt;
sys_n2v["SYS_shmat"] = SYS_shmat;
sys_n2v["SYS_shmctl"] = SYS_shmctl;
sys_n2v["SYS_shmdt"] = SYS_shmdt;
sys_n2v["SYS_shmget"] = SYS_shmget;
sys_n2v["SYS_shutdown"] = SYS_shutdown;
sys_n2v["SYS_socket"] = SYS_socket;
sys_n2v["SYS_socketpair"] = SYS_socketpair;
sys_n2v["SYS_tuxcall"] = SYS_tuxcall; 
sys_n2v["SYS_getcpu"] = SYS_getcpu;

for(map<string,int>::iterator it = sys_n2v.begin(); it != sys_n2v.end(); ++it){
  sys_v2n[it->second] = it->first;
}

int good_syscalls_temp[] = {
    SYS_read,
    SYS_write,
    SYS_open,
    SYS_close,
//    SYS_execve,
    SYS_access,
    SYS_brk,
    SYS_mprotect,
    SYS_set_thread_area,
    SYS_exit_group,
    
    /* nasm */
    SYS_exit,

    /* fpc */
    SYS_rt_sigaction,
    SYS_ioctl,
    SYS_readlink,

    SYS_munmap,
    SYS_writev,
    
    SYS_time,
    SYS_getpid,

    SYS_openat,
    SYS_stat,
    SYS_lseek,
    SYS_fstat,
    SYS_mmap,
    SYS_arch_prctl,
    SYS_uname,
};
char sys_ok[0xffff];
for(unsigned i=0; i < sizeof(sys_ok)/sizeof(sys_ok[0]); ++i)
  sys_ok[i] = 0;
for(unsigned i=0; i < sizeof(good_syscalls_temp)/sizeof(good_syscalls_temp[0]); ++i){
  sys_ok[good_syscalls_temp[i]] = 1;
  //cout << sys_v2n[good_syscalls_temp[i]] << endl;
}

map<string, int> sig_n2v;
map<int, string> sig_v2n;

sig_n2v["SIGHUP"] = SIGHUP;
sig_n2v["SIGINT"] = SIGINT;
sig_n2v["SIGQUIT"] = SIGQUIT;
sig_n2v["SIGILL"] = SIGILL;
sig_n2v["SIGTRAP"] = SIGTRAP;
sig_n2v["SIGABRT"] = SIGABRT;
sig_n2v["SIGIOT"] = SIGIOT;
sig_n2v["SIGBUS"] = SIGBUS;
sig_n2v["SIGFPE"] = SIGFPE;
sig_n2v["SIGKILL"] = SIGKILL;
sig_n2v["SIGUSR1"] = SIGUSR1;
sig_n2v["SIGSEGV"] = SIGSEGV;
sig_n2v["SIGUSR2"] = SIGUSR2;
sig_n2v["SIGPIPE"] = SIGPIPE;
sig_n2v["SIGALRM"] = SIGALRM;
sig_n2v["SIGTERM"] = SIGTERM;
sig_n2v["SIGSTKFLT"] = SIGSTKFLT;
sig_n2v["SIGCHLD"] = SIGCHLD;
sig_n2v["SIGCONT"] = SIGCONT;
sig_n2v["SIGSTOP"] = SIGSTOP;
sig_n2v["SIGTSTP"] = SIGTSTP;
sig_n2v["SIGTTIN"] = SIGTTIN;
sig_n2v["SIGTTOU"] = SIGTTOU;
sig_n2v["SIGURG"] = SIGURG;
sig_n2v["SIGXCPU"] = SIGXCPU;
sig_n2v["SIGXFSZ"] = SIGXFSZ;
sig_n2v["SIGVTALRM"] = SIGVTALRM;
sig_n2v["SIGPROF"] = SIGPROF;
sig_n2v["SIGWINCH"] = SIGWINCH;
sig_n2v["SIGIO"] = SIGIO;
sig_n2v["SIGPOLL"] = SIGPOLL;
//sig_n2v["SIGLOST"] = SIGLOST;
sig_n2v["SIGPWR"] = SIGPWR;
sig_n2v["SIGSYS"] = SIGSYS;
sig_n2v["SIGRTMIN"] = SIGRTMIN;

for(map<string,int>::iterator it = sig_n2v.begin(); it != sig_n2v.end(); ++it){
  sig_v2n[it->second] = it->first;
}


    int max_stack_size = -1, max_heap_size = -1;
    int max_time = -1;
    int max_output = STANDARD_MAX_OUTPUT;
    int opt;
    //enter program arguments
	while( (opt = getopt(argc, argv, "s:h:t:o:")) != -1 ){
      switch(opt){
        case 's':
          sscanf(optarg, "%d", &max_stack_size);
          max_stack_size *= 1024;
          break;
        case 'h':
          sscanf(optarg, "%d", &max_heap_size);
          max_heap_size *= 1024;
          break;
        case 't':
          sscanf(optarg, "%d", &max_time);
          break;
        case 'o':
          sscanf(optarg, "%d", &max_output);
          break;
      }
    }
    if(max_heap_size == -1 || max_stack_size == -1 || max_time == -1){
      cerr << "Nieprawidłowe lub brakujące parametry" << endl;
      help();
      return 1;
    }

	//split threads
    child = fork();

    if(-1 == child){
      perror("fork");
      return 1;
    }

//child thread
    if(child == 0) {

      close(2); // Close stderr, so a tested program cannot mess in output.

//not in work dir "/checker/rundir/"
      if(0 != chdir(WORK_DIR)){
        perror("chdir " WORK_DIR);
        return 1;
      }
	  //open file "/checker/rundir/..tests/in.txt"
      int fd_test_in = open(TEST_IN, O_RDONLY);
      if(-1 == fd_test_in){
        perror("open " TEST_IN);
        return 2;
      }
	  //duplicate file descriptor
      if(-1 == dup2(fd_test_in, 0)){
        perror("dup2 " TEST_IN " fd");
        return 3;
      }
	  //open file "/checker/rundir/..tests/out.txt"
      int fd_test_out = open(TEST_OUT, O_WRONLY | O_CREAT | O_TRUNC, S_IRGRP | S_IROTH | S_IRUSR);
      if(-1 == fd_test_out){
        perror("open " TEST_OUT);
        return 4;
      }
	  //duplicate file descriptor
      if(-1 == dup2(fd_test_out, 1)){
        perror("dup2 " TEST_OUT " fd");
        return 5;
      }
	  //change root dir of current process to "/checker/rundir/"
      if(-1 == chroot(WORK_DIR)){
        perror("chroot");
        return 6;
      }

      // limity
      struct rlimit lim;
	  //set soft and hard resource limit
      lim.rlim_cur = lim.rlim_max = max_heap_size + max_stack_size;
	  //set maximum address space
      if (-1 == setrlimit(RLIMIT_AS, &lim) ){
        perror("setrlimit");
        return 7;
      }

      lim.rlim_cur = lim.rlim_max = 0;
	  //no core dump files are created
      if (-1 == setrlimit(RLIMIT_CORE, &lim) ){
        perror("setrlimit");
        return 7;
      }

      lim.rlim_cur = lim.rlim_max = max_time+1;
	  //set CPU time limit in seconds
      if (-1 == setrlimit(RLIMIT_CPU, &lim) ){
        perror("setrlimit");
        return 7;
      }

      lim.rlim_cur = lim.rlim_max = max_heap_size;
	  //The maximum size of the process's data segment
      if (-1 == setrlimit(RLIMIT_DATA, &lim) ){
        perror("setrlimit");
        return 7;
      };

      lim.rlim_cur = lim.rlim_max = max_stack_size;
	  //set The maximum size of the process stack, in bytes.
      if (-1 == setrlimit(RLIMIT_STACK, &lim) ){
        perror("setrlimit");
        return 7;
      };

      lim.rlim_cur = lim.rlim_max = 1;
	  //The maximum number of processes
      if (-1 == setrlimit(RLIMIT_NPROC, &lim) ){
        perror("setrlimit");
        return 7;
      };

//set real user id, effective user id, and set-user-ID to 1001
      if(-1 == setresgid(WORK_UID, WORK_UID, WORK_UID)){
        perror("setresgid");
        return 8;
      }
	  //set user identifier bit to 1001
      if(-1 == setuid(WORK_UID)){
        perror("setuid");
        return 7;
      }
	  
      if(-1 == setresuid(WORK_UID, WORK_UID, WORK_UID)){
        perror("setresuid");
        return 8;
      }
	  //set process tracing by parent thread
      if(-1 == ptrace(PTRACE_TRACEME, 0, NULL, NULL)){
        perror("ptrace PTRACE_TRACEME");
        return 8;
      }
      char *cargv[2] = {(char*)"./a.out", NULL};
      char *cenvp[2] = {(char*)"I_CAN_HAS_HACK=NOWAI!", NULL};
	  //execute program /a.out
      if(-1 == execve("/a.out", cargv, cenvp)){
        perror("execle");
        return 9;
      }
    } else { // parent (it is ptracing)
        int exec_count = 0;
        long long int syscall_counter = 0;
        int child_wrote = 0;
        long orig_eax;
        int status;
        int insyscall = 0;
        int memusage = -1;
        struct user_regs_struct regs;

        while(1) {
			//wait for child process to change state
          waitpid(child, &status, 0);

			//This macro returns a nonzero value if the child process terminated normally with exit or _exit.
          if(WIFEXITED(status)){
            break;
			//go to line 222
          }
          orig_eax = ptrace(PTRACE_PEEKUSER, child, 8 * ORIG_RAX, NULL);
          syscall_counter += 1;
          if(-1 == orig_eax){
            // skończył się czas - SIGKILL wysłany automatycznie do procesu
            if(WEXITSTATUS(status))
              cout << "killing_signal: " << sig_v2n[WEXITSTATUS(status)] << "(" << WEXITSTATUS(status) << ")" << endl;
            break;
          } else if(! sys_ok[orig_eax]){
            // jakiś niedozwolony syscall
            if( (orig_eax != SYS_execve) || (exec_count > 1)){
              // syscall != execve lub kolejne użycie execve
              cout << "bad_syscall: " << sys_v2n[orig_eax] << "(" << orig_eax << ")" << endl;
              memusage = get_mem_usage_kb(child);
              ptrace(PTRACE_KILL, child, 0, 0);
              if(-1 == waitpid(child, &status, 0))
                perror("waitpid");
              break;
            } else { // pierwsze użycie execve
              ++exec_count;
            }
          } else if( orig_eax == SYS_exit_group || orig_eax == SYS_exit ){
            // wzorowe wyjście z programu
            cout << "end: ok" << endl;
            memusage = get_mem_usage_kb(child);
          }

          if(orig_eax == SYS_write){
            // proces coś pisze
            if(insyscall == 0)
              insyscall = 1;
            else {
              // sprawdzamy, ile zapisał
              insyscall = 0;
              child_wrote += ptrace(PTRACE_PEEKUSER, child, 8 * RAX, NULL);
              if( child_wrote > max_output){ // wyczerpał się limit
                cout << "end: too_big_output" << endl;
                memusage = get_mem_usage_kb(child);
                ptrace(PTRACE_KILL, child, 0, 0);
                if(-1 == waitpid(child, &status, 0))
                  perror("waitpid");
                break;
              }
            }
          }
          if(orig_eax == SYS_open) {
            // proces otwiera plik
            if(insyscall == 0) {
              /* Syscall entry */
              insyscall = 1;
              ptrace(PTRACE_GETREGS, child, NULL, &regs);
              long int flags = regs.rcx & 3;
              if( flags == O_WRONLY || flags == O_RDWR){
                // nie pozwalamu mu otworzyć pliku do zapisu
                cout << "end: write" << endl;
                memusage = get_mem_usage_kb(child);
                ptrace(PTRACE_KILL, child, 0, 0);
                if(-1 == waitpid(child, &status, 0))
                  perror("waitpid");
                break;
              }
              //printf(" - - Write called with %ld, %ld, %ld, %ld\n", regs.eax, regs.ebx, regs.ecx, regs.edx);
            } else { /* Syscall exit */
              //eax = ptrace(PTRACE_PEEKUSER, child, 8 * RAX, NULL);
              //printf(" - - Write returned with %ld\n", eax);
              insyscall = 0;
            }
          }
          errno = 0;
          if(-1 == ptrace(PTRACE_SYSCALL, child, NULL, NULL)){
            if(errno == ESRCH ) // child is dead
              break;
            // czekamy na następny syscall
            perror("ptrace PTRACE_SYSCALL");
            return 101;
          }
       }
	   
       struct rusage ru;
       if(-1 == getrusage(RUSAGE_CHILDREN, &ru)){
         // sprawdzamy użyte przez child zasoby - tutaj możemy zobaczyć tylko czas
         perror("getrusage");
         return 20;
       }
       cout << setfill('0');
       cout << "time_user: " << ru.ru_utime.tv_sec << '.' << setw(6) << ru.ru_utime.tv_usec << endl;
       cout << "time_system: " << ru.ru_stime.tv_sec << '.' << setw(6) << ru.ru_stime.tv_usec << endl;
       cout << "syscalls_executed: " << syscall_counter/2 << endl;
       if(WIFSIGNALED(status))
          cout << "killing_signal: " << sig_v2n[WTERMSIG(status)] << "(" << WTERMSIG(status) << ")" << endl;

       if(WIFEXITED(status))
          cout << "returned_code: " << WEXITSTATUS(status) << endl;

       if(memusage > -1)
          cout << "memory_usage: " << memusage << endl;
   }
   return 0;
}

