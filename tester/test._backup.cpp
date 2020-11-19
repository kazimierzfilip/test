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

#include "sys.c"

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

