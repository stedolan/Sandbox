//  sandbox.cpp - Linux grading program
//  (c) Stephen Dolan 2007-2009 (stedolan@gmail.com)
//
//  Standard input/output of the program being graded remains on stdio
//  
//  stderr produces lines of the form:
//  <type (single char)>: <message>
//  
//  If fd 3 is open, the standard output of the program being graded
//  goes there. Otherwise, it is discarded
//  
//  
//  The grader output is meant to be easily parseable, while remaining
//  human-readable.
//  
//  This is accomplished by putting all the easily-parsed information
//  in the first few characters, and reserving the rest for
//  human-readable output that can be ignored by grading programs.
//  
//  So, ignore all output on the line after the first character and
//  possibly a digit/small piece of text (see below)
//  
//  Possible types:
//
//  D -- debug information, only if -d is used
//
//  Exactly one of the following is produced:
//  P -- Couldn't start program. (insufficient permissions
//       or misspelled filename)
//  O -- program ran OK. format "O: %d" (exit code)
//  T -- timed out
//  M -- used too much memory*
//  H -- hung waiting for input
//  W -- wallclock timeout**
//  X -- tried to do something forbidden (illegal system 
//       call). format: "X: %s" (str is the name of the 
//       illegal syscall)
//       look it up, consult /usr/include/asm/i486/unistd.h)
//  S -- signal received (i.e. crash). format "S: %s" (str
//       is signal received e.g. SIGSEGV)
//  B -- something *really* stupid happened, probably a bug
//       in grader (should never appear)
//
//  The following are also produced for O,T,M,H,W,X,S:
//  t -- CPU time used in milliseconds. Equal to timelimit
//       in case of timeout. format "t: %d"
//  m -- memory used, in KB. Equal to memlimit in case of
//       too much mem. format "m: %d"
//  
//  
//  * It's difficult to determine when a program has been killed for
//    going over its memory limit.  If a program uses up all the
//    memory available to it, when it tries to allocate more the
//    allocation call fails with ENOMEM, but the program continues
//    (and probably crashes unless written very carefully). If the
//    stack expands beyond the memory limit, the program is sent a
//    SIGSEGV which is impossible to distinguish from the SIGSEGV
//    produced by, say, dereferencing a null pointer. So, this sandbox
//    uses the following heuristic: If the program terminates
//    abnormally, and any system call had ever failed with ENOMEM, the
//    cause of death is given as exceeding the memory limit. If the
//    program terminates with SIGSEGV, then the program is marked as
//    exceeding its memory limit if it ever came within 32k of the
//    memory limit.  These heuristics work quite well. The only case
//    I've found where they fail is when the program tries to allocate
//    too large a data structure on the stack. (note: allocating lots
//    of small data structures on the stack is no problem, because the
//    SIGSEGV will be generated only when the program is very near its
//    limit. This problem only shows up when a single stack allocation
//    takes the program from well below the memory limit to above it)
//  
//  **The wallclock timeout is triggered if the program being graded
//    manages to spend 3/2*T +1 seconds (where T is the timelimit,
//    also in seconds), without doing more than T seconds of
//    computation, and without waiting for input indefinitely (that
//    comes out as "Hung"). As such, I'm not even sure that it's
//    possible, and if anyone comes up with a program that produces a
//    wallclock timeout, please email it to me.
//  
//  Options:
//  -d        Enable debug mode. Produces a pile of output on stderr
//  -d -d     Enable more debug mode. Produces an even bigger pile of output on stderr
//  -m %d     Memory limit in KB
//  -t %d     Time limit in ms
//  progname  Name of program to run.
//            All further args are passed to the program
//  
//  
//  
//  ./sandbox -m 8192 -t 2000 ./test  --- runs "test" for at most 2s with at most 8MB RAM
//  
//  
//  
//  ***IMPORTANT***
//
//  Programs being graded must be compiled as a single,
//  statically-linked binary, e.g. gcc prog.c -o prog -static. If they
//  are not, the Linux dynamic linker runs every time the program is
//  started. The dynamic linker needs to read libraries from various
//  points on the hard disk, and this grading program will kill it as
//  soon as it attempts to (this grader prevents all hard disk /
//  filesystem access)
//
//  If a program exits as soon as its started and the grader complains
//  about disallowed syscall "access" or "open", you've probably
//  forgotten to statically compile the program.
//

#ifndef __linux__
  #error "Linux not detected. Other OSes are not currently supported"
#endif
#ifdef __i386__
  #define x32
  #define VALID_SYSTEM
#endif
#ifdef __x86_64__
  #define x64
  #define VALID_SYSTEM
#endif
#ifndef VALID_SYSTEM
  #error "Unsupported architecture. Only x86 and x86-64 are supported at the moment"
#endif

#ifdef __GNUC__
  #define NORETURN __attribute__((noreturn))
#else
  #define NORETURN
#endif


#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <string.h>





#define PTRACE_EVENT_FORK 1
#define PTRACE_EVENT_VFORK 2
#define PTRACE_EVENT_CLONE 3
#define PTRACE_EVENT_EXEC 4
#define PTRACE_EVENT_VFORK_DONE 5
#define PTRACE_EVENT_EXIT 6
#define PTRACE_SETOPTIONS 0x4200
#define PTRACE_GETEVENTMSG 0x4201
#define PTRACE_GETSIGINFO 0x4202
#define PTRACE_O_TRACESYSGOOD 0x00000001
#define PTRACE_O_TRACEFORK 0x00000002
#define PTRACE_O_TRACEVFORK 0x00000004
#define PTRACE_O_TRACECLONE 0x00000008
#define PTRACE_O_TRACEEXEC 0x00000010
#define PTRACE_O_TRACEVFORKDONE 0x00000020
#define PTRACE_O_TRACEEXIT 0x00000040


const char* signals[] = {"Unknown",
"SIGHUP",
"SIGINT",
"SIGQUIT",
"SIGILL",
"SIGTRAP",
"SIGABRT",
"SIGBUS",
"SIGFPE",
"SIGKILL",
"SIGUSR",
"SIGSEGV",
"SIGUSR",
"SIGPIPE",
"SIGALRM",
"SIGTERM",
"SIGSTKFLT",
"SIGCHLD",
"SIGCONT",
"SIGSTOP",
"SIGTSTP",
"SIGTTIN",
"SIGTTOU",
"SIGURG",
"SIGXCPU",
"SIGXFSZ",
"SIGVTALRM",
"SIGPROF",
"SIGWINCH",
"SIGIO",
"SIGPWR",
"SIGSYS",
"Unknown"};



// The following mess is generated by
/*
cat unistd* | grep -o '__NR_[a-zA-Z0-9_]*' | sort -u | perl -ne 'chomp; /__NR_(.*)/; print qq{#ifdef $_\n [$_] = "$1",\n#endif\n}'

in the directory /usr/include/asm
*/

const char* syscall_names[] = {
#ifdef __NR_accept
 [__NR_accept] = "accept",
#endif
#ifdef __NR_access
 [__NR_access] = "access",
#endif
#ifdef __NR_acct
 [__NR_acct] = "acct",
#endif
#ifdef __NR_add_key
 [__NR_add_key] = "add_key",
#endif
#ifdef __NR_adjtimex
 [__NR_adjtimex] = "adjtimex",
#endif
#ifdef __NR_afs_syscall
 [__NR_afs_syscall] = "afs_syscall",
#endif
#ifdef __NR_alarm
 [__NR_alarm] = "alarm",
#endif
#ifdef __NR_arch_prctl
 [__NR_arch_prctl] = "arch_prctl",
#endif
#ifdef __NR_bdflush
 [__NR_bdflush] = "bdflush",
#endif
#ifdef __NR_bind
 [__NR_bind] = "bind",
#endif
#ifdef __NR_break
 [__NR_break] = "break",
#endif
#ifdef __NR_brk
 [__NR_brk] = "brk",
#endif
#ifdef __NR_capget
 [__NR_capget] = "capget",
#endif
#ifdef __NR_capset
 [__NR_capset] = "capset",
#endif
#ifdef __NR_chdir
 [__NR_chdir] = "chdir",
#endif
#ifdef __NR_chmod
 [__NR_chmod] = "chmod",
#endif
#ifdef __NR_chown
 [__NR_chown] = "chown",
#endif
#ifdef __NR_chown32
 [__NR_chown32] = "chown32",
#endif
#ifdef __NR_chroot
 [__NR_chroot] = "chroot",
#endif
#ifdef __NR_clock_getres
 [__NR_clock_getres] = "clock_getres",
#endif
#ifdef __NR_clock_gettime
 [__NR_clock_gettime] = "clock_gettime",
#endif
#ifdef __NR_clock_nanosleep
 [__NR_clock_nanosleep] = "clock_nanosleep",
#endif
#ifdef __NR_clock_settime
 [__NR_clock_settime] = "clock_settime",
#endif
#ifdef __NR_clone
 [__NR_clone] = "clone",
#endif
#ifdef __NR_close
 [__NR_close] = "close",
#endif
#ifdef __NR_connect
 [__NR_connect] = "connect",
#endif
#ifdef __NR_creat
 [__NR_creat] = "creat",
#endif
#ifdef __NR_create_module
 [__NR_create_module] = "create_module",
#endif
#ifdef __NR_delete_module
 [__NR_delete_module] = "delete_module",
#endif
#ifdef __NR_dup
 [__NR_dup] = "dup",
#endif
#ifdef __NR_dup2
 [__NR_dup2] = "dup2",
#endif
#ifdef __NR_epoll_create
 [__NR_epoll_create] = "epoll_create",
#endif
#ifdef __NR_epoll_ctl
 [__NR_epoll_ctl] = "epoll_ctl",
#endif
#ifdef __NR_epoll_ctl_old
 [__NR_epoll_ctl_old] = "epoll_ctl_old",
#endif
#ifdef __NR_epoll_pwait
 [__NR_epoll_pwait] = "epoll_pwait",
#endif
#ifdef __NR_epoll_wait
 [__NR_epoll_wait] = "epoll_wait",
#endif
#ifdef __NR_epoll_wait_old
 [__NR_epoll_wait_old] = "epoll_wait_old",
#endif
#ifdef __NR_eventfd
 [__NR_eventfd] = "eventfd",
#endif
#ifdef __NR_execve
 [__NR_execve] = "execve",
#endif
#ifdef __NR_exit
 [__NR_exit] = "exit",
#endif
#ifdef __NR_exit_group
 [__NR_exit_group] = "exit_group",
#endif
#ifdef __NR_faccessat
 [__NR_faccessat] = "faccessat",
#endif
#ifdef __NR_fadvise64
 [__NR_fadvise64] = "fadvise64",
#endif
#ifdef __NR_fadvise64_64
 [__NR_fadvise64_64] = "fadvise64_64",
#endif
#ifdef __NR_fallocate
 [__NR_fallocate] = "fallocate",
#endif
#ifdef __NR_fchdir
 [__NR_fchdir] = "fchdir",
#endif
#ifdef __NR_fchmod
 [__NR_fchmod] = "fchmod",
#endif
#ifdef __NR_fchmodat
 [__NR_fchmodat] = "fchmodat",
#endif
#ifdef __NR_fchown
 [__NR_fchown] = "fchown",
#endif
#ifdef __NR_fchown32
 [__NR_fchown32] = "fchown32",
#endif
#ifdef __NR_fchownat
 [__NR_fchownat] = "fchownat",
#endif
#ifdef __NR_fcntl
 [__NR_fcntl] = "fcntl",
#endif
#ifdef __NR_fcntl64
 [__NR_fcntl64] = "fcntl64",
#endif
#ifdef __NR_fdatasync
 [__NR_fdatasync] = "fdatasync",
#endif
#ifdef __NR_fgetxattr
 [__NR_fgetxattr] = "fgetxattr",
#endif
#ifdef __NR_flistxattr
 [__NR_flistxattr] = "flistxattr",
#endif
#ifdef __NR_flock
 [__NR_flock] = "flock",
#endif
#ifdef __NR_fork
 [__NR_fork] = "fork",
#endif
#ifdef __NR_fremovexattr
 [__NR_fremovexattr] = "fremovexattr",
#endif
#ifdef __NR_fsetxattr
 [__NR_fsetxattr] = "fsetxattr",
#endif
#ifdef __NR_fstat
 [__NR_fstat] = "fstat",
#endif
#ifdef __NR_fstat64
 [__NR_fstat64] = "fstat64",
#endif
#ifdef __NR_fstatat64
 [__NR_fstatat64] = "fstatat64",
#endif
#ifdef __NR_fstatfs
 [__NR_fstatfs] = "fstatfs",
#endif
#ifdef __NR_fstatfs64
 [__NR_fstatfs64] = "fstatfs64",
#endif
#ifdef __NR_fsync
 [__NR_fsync] = "fsync",
#endif
#ifdef __NR_ftime
 [__NR_ftime] = "ftime",
#endif
#ifdef __NR_ftruncate
 [__NR_ftruncate] = "ftruncate",
#endif
#ifdef __NR_ftruncate64
 [__NR_ftruncate64] = "ftruncate64",
#endif
#ifdef __NR_futex
 [__NR_futex] = "futex",
#endif
#ifdef __NR_futimesat
 [__NR_futimesat] = "futimesat",
#endif
#ifdef __NR_getcpu
 [__NR_getcpu] = "getcpu",
#endif
#ifdef __NR_getcwd
 [__NR_getcwd] = "getcwd",
#endif
#ifdef __NR_getdents
 [__NR_getdents] = "getdents",
#endif
#ifdef __NR_getdents64
 [__NR_getdents64] = "getdents64",
#endif
#ifdef __NR_getegid
 [__NR_getegid] = "getegid",
#endif
#ifdef __NR_getegid32
 [__NR_getegid32] = "getegid32",
#endif
#ifdef __NR_geteuid
 [__NR_geteuid] = "geteuid",
#endif
#ifdef __NR_geteuid32
 [__NR_geteuid32] = "geteuid32",
#endif
#ifdef __NR_getgid
 [__NR_getgid] = "getgid",
#endif
#ifdef __NR_getgid32
 [__NR_getgid32] = "getgid32",
#endif
#ifdef __NR_getgroups
 [__NR_getgroups] = "getgroups",
#endif
#ifdef __NR_getgroups32
 [__NR_getgroups32] = "getgroups32",
#endif
#ifdef __NR_getitimer
 [__NR_getitimer] = "getitimer",
#endif
#ifdef __NR_get_kernel_syms
 [__NR_get_kernel_syms] = "get_kernel_syms",
#endif
#ifdef __NR_get_mempolicy
 [__NR_get_mempolicy] = "get_mempolicy",
#endif
#ifdef __NR_getpeername
 [__NR_getpeername] = "getpeername",
#endif
#ifdef __NR_getpgid
 [__NR_getpgid] = "getpgid",
#endif
#ifdef __NR_getpgrp
 [__NR_getpgrp] = "getpgrp",
#endif
#ifdef __NR_getpid
 [__NR_getpid] = "getpid",
#endif
#ifdef __NR_getpmsg
 [__NR_getpmsg] = "getpmsg",
#endif
#ifdef __NR_getppid
 [__NR_getppid] = "getppid",
#endif
#ifdef __NR_getpriority
 [__NR_getpriority] = "getpriority",
#endif
#ifdef __NR_getresgid
 [__NR_getresgid] = "getresgid",
#endif
#ifdef __NR_getresgid32
 [__NR_getresgid32] = "getresgid32",
#endif
#ifdef __NR_getresuid
 [__NR_getresuid] = "getresuid",
#endif
#ifdef __NR_getresuid32
 [__NR_getresuid32] = "getresuid32",
#endif
#ifdef __NR_getrlimit
 [__NR_getrlimit] = "getrlimit",
#endif
#ifdef __NR_get_robust_list
 [__NR_get_robust_list] = "get_robust_list",
#endif
#ifdef __NR_getrusage
 [__NR_getrusage] = "getrusage",
#endif
#ifdef __NR_getsid
 [__NR_getsid] = "getsid",
#endif
#ifdef __NR_getsockname
 [__NR_getsockname] = "getsockname",
#endif
#ifdef __NR_getsockopt
 [__NR_getsockopt] = "getsockopt",
#endif
#ifdef __NR_get_thread_area
 [__NR_get_thread_area] = "get_thread_area",
#endif
#ifdef __NR_gettid
 [__NR_gettid] = "gettid",
#endif
#ifdef __NR_gettimeofday
 [__NR_gettimeofday] = "gettimeofday",
#endif
#ifdef __NR_getuid
 [__NR_getuid] = "getuid",
#endif
#ifdef __NR_getuid32
 [__NR_getuid32] = "getuid32",
#endif
#ifdef __NR_getxattr
 [__NR_getxattr] = "getxattr",
#endif
#ifdef __NR_gtty
 [__NR_gtty] = "gtty",
#endif
#ifdef __NR_idle
 [__NR_idle] = "idle",
#endif
#ifdef __NR_init_module
 [__NR_init_module] = "init_module",
#endif
#ifdef __NR_inotify_add_watch
 [__NR_inotify_add_watch] = "inotify_add_watch",
#endif
#ifdef __NR_inotify_init
 [__NR_inotify_init] = "inotify_init",
#endif
#ifdef __NR_inotify_rm_watch
 [__NR_inotify_rm_watch] = "inotify_rm_watch",
#endif
#ifdef __NR_io_cancel
 [__NR_io_cancel] = "io_cancel",
#endif
#ifdef __NR_ioctl
 [__NR_ioctl] = "ioctl",
#endif
#ifdef __NR_io_destroy
 [__NR_io_destroy] = "io_destroy",
#endif
#ifdef __NR_io_getevents
 [__NR_io_getevents] = "io_getevents",
#endif
#ifdef __NR_ioperm
 [__NR_ioperm] = "ioperm",
#endif
#ifdef __NR_iopl
 [__NR_iopl] = "iopl",
#endif
#ifdef __NR_ioprio_get
 [__NR_ioprio_get] = "ioprio_get",
#endif
#ifdef __NR_ioprio_set
 [__NR_ioprio_set] = "ioprio_set",
#endif
#ifdef __NR_io_setup
 [__NR_io_setup] = "io_setup",
#endif
#ifdef __NR_io_submit
 [__NR_io_submit] = "io_submit",
#endif
#ifdef __NR_ipc
 [__NR_ipc] = "ipc",
#endif
#ifdef __NR_kexec_load
 [__NR_kexec_load] = "kexec_load",
#endif
#ifdef __NR_keyctl
 [__NR_keyctl] = "keyctl",
#endif
#ifdef __NR_kill
 [__NR_kill] = "kill",
#endif
#ifdef __NR_lchown
 [__NR_lchown] = "lchown",
#endif
#ifdef __NR_lchown32
 [__NR_lchown32] = "lchown32",
#endif
#ifdef __NR_lgetxattr
 [__NR_lgetxattr] = "lgetxattr",
#endif
#ifdef __NR_link
 [__NR_link] = "link",
#endif
#ifdef __NR_linkat
 [__NR_linkat] = "linkat",
#endif
#ifdef __NR_listen
 [__NR_listen] = "listen",
#endif
#ifdef __NR_listxattr
 [__NR_listxattr] = "listxattr",
#endif
#ifdef __NR_llistxattr
 [__NR_llistxattr] = "llistxattr",
#endif
#ifdef __NR__llseek
 [__NR__llseek] = "_llseek",
#endif
#ifdef __NR_lock
 [__NR_lock] = "lock",
#endif
#ifdef __NR_lookup_dcookie
 [__NR_lookup_dcookie] = "lookup_dcookie",
#endif
#ifdef __NR_lremovexattr
 [__NR_lremovexattr] = "lremovexattr",
#endif
#ifdef __NR_lseek
 [__NR_lseek] = "lseek",
#endif
#ifdef __NR_lsetxattr
 [__NR_lsetxattr] = "lsetxattr",
#endif
#ifdef __NR_lstat
 [__NR_lstat] = "lstat",
#endif
#ifdef __NR_lstat64
 [__NR_lstat64] = "lstat64",
#endif
#ifdef __NR_madvise
 [__NR_madvise] = "madvise",
#endif
#ifdef __NR_madvise1
 [__NR_madvise1] = "madvise1",
#endif
#ifdef __NR_mbind
 [__NR_mbind] = "mbind",
#endif
#ifdef __NR_migrate_pages
 [__NR_migrate_pages] = "migrate_pages",
#endif
#ifdef __NR_mincore
 [__NR_mincore] = "mincore",
#endif
#ifdef __NR_mkdir
 [__NR_mkdir] = "mkdir",
#endif
#ifdef __NR_mkdirat
 [__NR_mkdirat] = "mkdirat",
#endif
#ifdef __NR_mknod
 [__NR_mknod] = "mknod",
#endif
#ifdef __NR_mknodat
 [__NR_mknodat] = "mknodat",
#endif
#ifdef __NR_mlock
 [__NR_mlock] = "mlock",
#endif
#ifdef __NR_mlockall
 [__NR_mlockall] = "mlockall",
#endif
#ifdef __NR_mmap
 [__NR_mmap] = "mmap",
#endif
#ifdef __NR_mmap2
 [__NR_mmap2] = "mmap2",
#endif
#ifdef __NR_modify_ldt
 [__NR_modify_ldt] = "modify_ldt",
#endif
#ifdef __NR_mount
 [__NR_mount] = "mount",
#endif
#ifdef __NR_move_pages
 [__NR_move_pages] = "move_pages",
#endif
#ifdef __NR_mprotect
 [__NR_mprotect] = "mprotect",
#endif
#ifdef __NR_mpx
 [__NR_mpx] = "mpx",
#endif
#ifdef __NR_mq_getsetattr
 [__NR_mq_getsetattr] = "mq_getsetattr",
#endif
#ifdef __NR_mq_notify
 [__NR_mq_notify] = "mq_notify",
#endif
#ifdef __NR_mq_open
 [__NR_mq_open] = "mq_open",
#endif
#ifdef __NR_mq_timedreceive
 [__NR_mq_timedreceive] = "mq_timedreceive",
#endif
#ifdef __NR_mq_timedsend
 [__NR_mq_timedsend] = "mq_timedsend",
#endif
#ifdef __NR_mq_unlink
 [__NR_mq_unlink] = "mq_unlink",
#endif
#ifdef __NR_mremap
 [__NR_mremap] = "mremap",
#endif
#ifdef __NR_msgctl
 [__NR_msgctl] = "msgctl",
#endif
#ifdef __NR_msgget
 [__NR_msgget] = "msgget",
#endif
#ifdef __NR_msgrcv
 [__NR_msgrcv] = "msgrcv",
#endif
#ifdef __NR_msgsnd
 [__NR_msgsnd] = "msgsnd",
#endif
#ifdef __NR_msync
 [__NR_msync] = "msync",
#endif
#ifdef __NR_munlock
 [__NR_munlock] = "munlock",
#endif
#ifdef __NR_munlockall
 [__NR_munlockall] = "munlockall",
#endif
#ifdef __NR_munmap
 [__NR_munmap] = "munmap",
#endif
#ifdef __NR_nanosleep
 [__NR_nanosleep] = "nanosleep",
#endif
#ifdef __NR_newfstatat
 [__NR_newfstatat] = "newfstatat",
#endif
#ifdef __NR__newselect
 [__NR__newselect] = "_newselect",
#endif
#ifdef __NR_nfsservctl
 [__NR_nfsservctl] = "nfsservctl",
#endif
#ifdef __NR_nice
 [__NR_nice] = "nice",
#endif
#ifdef __NR_oldfstat
 [__NR_oldfstat] = "oldfstat",
#endif
#ifdef __NR_oldlstat
 [__NR_oldlstat] = "oldlstat",
#endif
#ifdef __NR_oldolduname
 [__NR_oldolduname] = "oldolduname",
#endif
#ifdef __NR_oldstat
 [__NR_oldstat] = "oldstat",
#endif
#ifdef __NR_olduname
 [__NR_olduname] = "olduname",
#endif
#ifdef __NR_open
 [__NR_open] = "open",
#endif
#ifdef __NR_openat
 [__NR_openat] = "openat",
#endif
#ifdef __NR_pause
 [__NR_pause] = "pause",
#endif
#ifdef __NR_personality
 [__NR_personality] = "personality",
#endif
#ifdef __NR_pipe
 [__NR_pipe] = "pipe",
#endif
#ifdef __NR_pivot_root
 [__NR_pivot_root] = "pivot_root",
#endif
#ifdef __NR_poll
 [__NR_poll] = "poll",
#endif
#ifdef __NR_ppoll
 [__NR_ppoll] = "ppoll",
#endif
#ifdef __NR_prctl
 [__NR_prctl] = "prctl",
#endif
#ifdef __NR_pread64
 [__NR_pread64] = "pread64",
#endif
#ifdef __NR_prof
 [__NR_prof] = "prof",
#endif
#ifdef __NR_profil
 [__NR_profil] = "profil",
#endif
#ifdef __NR_pselect6
 [__NR_pselect6] = "pselect6",
#endif
#ifdef __NR_ptrace
 [__NR_ptrace] = "ptrace",
#endif
#ifdef __NR_putpmsg
 [__NR_putpmsg] = "putpmsg",
#endif
#ifdef __NR_pwrite64
 [__NR_pwrite64] = "pwrite64",
#endif
#ifdef __NR_query_module
 [__NR_query_module] = "query_module",
#endif
#ifdef __NR_quotactl
 [__NR_quotactl] = "quotactl",
#endif
#ifdef __NR_read
 [__NR_read] = "read",
#endif
#ifdef __NR_readahead
 [__NR_readahead] = "readahead",
#endif
#ifdef __NR_readdir
 [__NR_readdir] = "readdir",
#endif
#ifdef __NR_readlink
 [__NR_readlink] = "readlink",
#endif
#ifdef __NR_readlinkat
 [__NR_readlinkat] = "readlinkat",
#endif
#ifdef __NR_readv
 [__NR_readv] = "readv",
#endif
#ifdef __NR_reboot
 [__NR_reboot] = "reboot",
#endif
#ifdef __NR_recvfrom
 [__NR_recvfrom] = "recvfrom",
#endif
#ifdef __NR_recvmsg
 [__NR_recvmsg] = "recvmsg",
#endif
#ifdef __NR_remap_file_pages
 [__NR_remap_file_pages] = "remap_file_pages",
#endif
#ifdef __NR_removexattr
 [__NR_removexattr] = "removexattr",
#endif
#ifdef __NR_rename
 [__NR_rename] = "rename",
#endif
#ifdef __NR_renameat
 [__NR_renameat] = "renameat",
#endif
#ifdef __NR_request_key
 [__NR_request_key] = "request_key",
#endif
#ifdef __NR_restart_syscall
 [__NR_restart_syscall] = "restart_syscall",
#endif
#ifdef __NR_rmdir
 [__NR_rmdir] = "rmdir",
#endif
#ifdef __NR_rt_sigaction
 [__NR_rt_sigaction] = "rt_sigaction",
#endif
#ifdef __NR_rt_sigpending
 [__NR_rt_sigpending] = "rt_sigpending",
#endif
#ifdef __NR_rt_sigprocmask
 [__NR_rt_sigprocmask] = "rt_sigprocmask",
#endif
#ifdef __NR_rt_sigqueueinfo
 [__NR_rt_sigqueueinfo] = "rt_sigqueueinfo",
#endif
#ifdef __NR_rt_sigreturn
 [__NR_rt_sigreturn] = "rt_sigreturn",
#endif
#ifdef __NR_rt_sigsuspend
 [__NR_rt_sigsuspend] = "rt_sigsuspend",
#endif
#ifdef __NR_rt_sigtimedwait
 [__NR_rt_sigtimedwait] = "rt_sigtimedwait",
#endif
#ifdef __NR_sched_getaffinity
 [__NR_sched_getaffinity] = "sched_getaffinity",
#endif
#ifdef __NR_sched_getparam
 [__NR_sched_getparam] = "sched_getparam",
#endif
#ifdef __NR_sched_get_priority_max
 [__NR_sched_get_priority_max] = "sched_get_priority_max",
#endif
#ifdef __NR_sched_get_priority_min
 [__NR_sched_get_priority_min] = "sched_get_priority_min",
#endif
#ifdef __NR_sched_getscheduler
 [__NR_sched_getscheduler] = "sched_getscheduler",
#endif
#ifdef __NR_sched_rr_get_interval
 [__NR_sched_rr_get_interval] = "sched_rr_get_interval",
#endif
#ifdef __NR_sched_setaffinity
 [__NR_sched_setaffinity] = "sched_setaffinity",
#endif
#ifdef __NR_sched_setparam
 [__NR_sched_setparam] = "sched_setparam",
#endif
#ifdef __NR_sched_setscheduler
 [__NR_sched_setscheduler] = "sched_setscheduler",
#endif
#ifdef __NR_sched_yield
 [__NR_sched_yield] = "sched_yield",
#endif
#ifdef __NR_security
 [__NR_security] = "security",
#endif
#ifdef __NR_select
 [__NR_select] = "select",
#endif
#ifdef __NR_semctl
 [__NR_semctl] = "semctl",
#endif
#ifdef __NR_semget
 [__NR_semget] = "semget",
#endif
#ifdef __NR_semop
 [__NR_semop] = "semop",
#endif
#ifdef __NR_semtimedop
 [__NR_semtimedop] = "semtimedop",
#endif
#ifdef __NR_sendfile
 [__NR_sendfile] = "sendfile",
#endif
#ifdef __NR_sendfile64
 [__NR_sendfile64] = "sendfile64",
#endif
#ifdef __NR_sendmsg
 [__NR_sendmsg] = "sendmsg",
#endif
#ifdef __NR_sendto
 [__NR_sendto] = "sendto",
#endif
#ifdef __NR_setdomainname
 [__NR_setdomainname] = "setdomainname",
#endif
#ifdef __NR_setfsgid
 [__NR_setfsgid] = "setfsgid",
#endif
#ifdef __NR_setfsgid32
 [__NR_setfsgid32] = "setfsgid32",
#endif
#ifdef __NR_setfsuid
 [__NR_setfsuid] = "setfsuid",
#endif
#ifdef __NR_setfsuid32
 [__NR_setfsuid32] = "setfsuid32",
#endif
#ifdef __NR_setgid
 [__NR_setgid] = "setgid",
#endif
#ifdef __NR_setgid32
 [__NR_setgid32] = "setgid32",
#endif
#ifdef __NR_setgroups
 [__NR_setgroups] = "setgroups",
#endif
#ifdef __NR_setgroups32
 [__NR_setgroups32] = "setgroups32",
#endif
#ifdef __NR_sethostname
 [__NR_sethostname] = "sethostname",
#endif
#ifdef __NR_setitimer
 [__NR_setitimer] = "setitimer",
#endif
#ifdef __NR_set_mempolicy
 [__NR_set_mempolicy] = "set_mempolicy",
#endif
#ifdef __NR_setpgid
 [__NR_setpgid] = "setpgid",
#endif
#ifdef __NR_setpriority
 [__NR_setpriority] = "setpriority",
#endif
#ifdef __NR_setregid
 [__NR_setregid] = "setregid",
#endif
#ifdef __NR_setregid32
 [__NR_setregid32] = "setregid32",
#endif
#ifdef __NR_setresgid
 [__NR_setresgid] = "setresgid",
#endif
#ifdef __NR_setresgid32
 [__NR_setresgid32] = "setresgid32",
#endif
#ifdef __NR_setresuid
 [__NR_setresuid] = "setresuid",
#endif
#ifdef __NR_setresuid32
 [__NR_setresuid32] = "setresuid32",
#endif
#ifdef __NR_setreuid
 [__NR_setreuid] = "setreuid",
#endif
#ifdef __NR_setreuid32
 [__NR_setreuid32] = "setreuid32",
#endif
#ifdef __NR_setrlimit
 [__NR_setrlimit] = "setrlimit",
#endif
#ifdef __NR_set_robust_list
 [__NR_set_robust_list] = "set_robust_list",
#endif
#ifdef __NR_setsid
 [__NR_setsid] = "setsid",
#endif
#ifdef __NR_setsockopt
 [__NR_setsockopt] = "setsockopt",
#endif
#ifdef __NR_set_thread_area
 [__NR_set_thread_area] = "set_thread_area",
#endif
#ifdef __NR_set_tid_address
 [__NR_set_tid_address] = "set_tid_address",
#endif
#ifdef __NR_settimeofday
 [__NR_settimeofday] = "settimeofday",
#endif
#ifdef __NR_setuid
 [__NR_setuid] = "setuid",
#endif
#ifdef __NR_setuid32
 [__NR_setuid32] = "setuid32",
#endif
#ifdef __NR_setxattr
 [__NR_setxattr] = "setxattr",
#endif
#ifdef __NR_sgetmask
 [__NR_sgetmask] = "sgetmask",
#endif
#ifdef __NR_shmat
 [__NR_shmat] = "shmat",
#endif
#ifdef __NR_shmctl
 [__NR_shmctl] = "shmctl",
#endif
#ifdef __NR_shmdt
 [__NR_shmdt] = "shmdt",
#endif
#ifdef __NR_shmget
 [__NR_shmget] = "shmget",
#endif
#ifdef __NR_shutdown
 [__NR_shutdown] = "shutdown",
#endif
#ifdef __NR_sigaction
 [__NR_sigaction] = "sigaction",
#endif
#ifdef __NR_sigaltstack
 [__NR_sigaltstack] = "sigaltstack",
#endif
#ifdef __NR_signal
 [__NR_signal] = "signal",
#endif
#ifdef __NR_signalfd
 [__NR_signalfd] = "signalfd",
#endif
#ifdef __NR_sigpending
 [__NR_sigpending] = "sigpending",
#endif
#ifdef __NR_sigprocmask
 [__NR_sigprocmask] = "sigprocmask",
#endif
#ifdef __NR_sigreturn
 [__NR_sigreturn] = "sigreturn",
#endif
#ifdef __NR_sigsuspend
 [__NR_sigsuspend] = "sigsuspend",
#endif
#ifdef __NR_socket
 [__NR_socket] = "socket",
#endif
#ifdef __NR_socketcall
 [__NR_socketcall] = "socketcall",
#endif
#ifdef __NR_socketpair
 [__NR_socketpair] = "socketpair",
#endif
#ifdef __NR_splice
 [__NR_splice] = "splice",
#endif
#ifdef __NR_ssetmask
 [__NR_ssetmask] = "ssetmask",
#endif
#ifdef __NR_stat
 [__NR_stat] = "stat",
#endif
#ifdef __NR_stat64
 [__NR_stat64] = "stat64",
#endif
#ifdef __NR_statfs
 [__NR_statfs] = "statfs",
#endif
#ifdef __NR_statfs64
 [__NR_statfs64] = "statfs64",
#endif
#ifdef __NR_stime
 [__NR_stime] = "stime",
#endif
#ifdef __NR_stty
 [__NR_stty] = "stty",
#endif
#ifdef __NR_swapoff
 [__NR_swapoff] = "swapoff",
#endif
#ifdef __NR_swapon
 [__NR_swapon] = "swapon",
#endif
#ifdef __NR_symlink
 [__NR_symlink] = "symlink",
#endif
#ifdef __NR_symlinkat
 [__NR_symlinkat] = "symlinkat",
#endif
#ifdef __NR_sync
 [__NR_sync] = "sync",
#endif
#ifdef __NR_sync_file_range
 [__NR_sync_file_range] = "sync_file_range",
#endif
#ifdef __NR__sysctl
 [__NR__sysctl] = "_sysctl",
#endif
#ifdef __NR_sysfs
 [__NR_sysfs] = "sysfs",
#endif
#ifdef __NR_sysinfo
 [__NR_sysinfo] = "sysinfo",
#endif
#ifdef __NR_syslog
 [__NR_syslog] = "syslog",
#endif
#ifdef __NR_sys_setaltroot
 [__NR_sys_setaltroot] = "sys_setaltroot",
#endif
#ifdef __NR_tee
 [__NR_tee] = "tee",
#endif
#ifdef __NR_tgkill
 [__NR_tgkill] = "tgkill",
#endif
#ifdef __NR_time
 [__NR_time] = "time",
#endif
#ifdef __NR_timer_create
 [__NR_timer_create] = "timer_create",
#endif
#ifdef __NR_timer_delete
 [__NR_timer_delete] = "timer_delete",
#endif
#ifdef __NR_timerfd_create
 [__NR_timerfd_create] = "timerfd_create",
#endif
#ifdef __NR_timerfd_gettime
 [__NR_timerfd_gettime] = "timerfd_gettime",
#endif
#ifdef __NR_timerfd_settime
 [__NR_timerfd_settime] = "timerfd_settime",
#endif
#ifdef __NR_timer_getoverrun
 [__NR_timer_getoverrun] = "timer_getoverrun",
#endif
#ifdef __NR_timer_gettime
 [__NR_timer_gettime] = "timer_gettime",
#endif
#ifdef __NR_timer_settime
 [__NR_timer_settime] = "timer_settime",
#endif
#ifdef __NR_times
 [__NR_times] = "times",
#endif
#ifdef __NR_tkill
 [__NR_tkill] = "tkill",
#endif
#ifdef __NR_truncate
 [__NR_truncate] = "truncate",
#endif
#ifdef __NR_truncate64
 [__NR_truncate64] = "truncate64",
#endif
#ifdef __NR_tuxcall
 [__NR_tuxcall] = "tuxcall",
#endif
#ifdef __NR_ugetrlimit
 [__NR_ugetrlimit] = "ugetrlimit",
#endif
#ifdef __NR_ulimit
 [__NR_ulimit] = "ulimit",
#endif
#ifdef __NR_umask
 [__NR_umask] = "umask",
#endif
#ifdef __NR_umount
 [__NR_umount] = "umount",
#endif
#ifdef __NR_umount2
 [__NR_umount2] = "umount2",
#endif
#ifdef __NR_uname
 [__NR_uname] = "uname",
#endif
#ifdef __NR_unlink
 [__NR_unlink] = "unlink",
#endif
#ifdef __NR_unlinkat
 [__NR_unlinkat] = "unlinkat",
#endif
#ifdef __NR_unshare
 [__NR_unshare] = "unshare",
#endif
#ifdef __NR_uselib
 [__NR_uselib] = "uselib",
#endif
#ifdef __NR_ustat
 [__NR_ustat] = "ustat",
#endif
#ifdef __NR_utime
 [__NR_utime] = "utime",
#endif
#ifdef __NR_utimensat
 [__NR_utimensat] = "utimensat",
#endif
#ifdef __NR_utimes
 [__NR_utimes] = "utimes",
#endif
#ifdef __NR_vfork
 [__NR_vfork] = "vfork",
#endif
#ifdef __NR_vhangup
 [__NR_vhangup] = "vhangup",
#endif
#ifdef __NR_vm86
 [__NR_vm86] = "vm86",
#endif
#ifdef __NR_vm86old
 [__NR_vm86old] = "vm86old",
#endif
#ifdef __NR_vmsplice
 [__NR_vmsplice] = "vmsplice",
#endif
#ifdef __NR_vserver
 [__NR_vserver] = "vserver",
#endif
#ifdef __NR_wait4
 [__NR_wait4] = "wait4",
#endif
#ifdef __NR_waitid
 [__NR_waitid] = "waitid",
#endif
#ifdef __NR_waitpid
 [__NR_waitpid] = "waitpid",
#endif
#ifdef __NR_write
 [__NR_write] = "write",
#endif
#ifdef __NR_writev
 [__NR_writev] = "writev",
#endif

};

const char* get_syscall_name(int n){
  if (n >= 0 && n < (int)(sizeof(syscall_names) / sizeof(syscall_names[0]))){
    if (syscall_names[n]){
      return syscall_names[n];
    }else{
      return "[unknown syscall - gap in table]";
    }
  }else{
    return "[unknown syscall]";
  }
}






pid_t pid;

void bug(const char*) NORETURN;
static inline int attempt_impl(int x, const char* err){
  if (x>=0)return x;
  char buf[500];
  snprintf(buf, 500, "%s: %s", err, strerror(errno));
  bug(buf);
}

#define attempt(x) attempt_impl(x, #x)


int debug_on = 0;
#define debug(...) if(debug_on)fprintf(stderr, "D: " __VA_ARGS__)
#define debug2(...) if(debug_on>1)fprintf(stderr, "D: " __VA_ARGS__)


volatile int curr_syscall = 0;

typedef enum {C_unknown, C_ok, C_time, C_mem, C_wallclock, C_syscall, C_signal} cause_of_death;

typedef struct{
  cause_of_death cause;
  int arg;
} exit_type;



int limit_millis;
int limit_KBytes;
int memory_exceeded;
int time_exceeded;
volatile int timeout;
volatile time_t endtime;
volatile int exited_syscall;
int ramsize;

  
void limits_check(struct rusage* usage, int signal, exit_type* ex){
  debug("checking lims - %d %d\n", (int)usage->ru_utime.tv_sec, (int)usage->ru_utime.tv_usec);
  debug("Program used %.2f secs and %d kB\n", (double)(usage->ru_utime.tv_usec + 1000000*usage->ru_utime.tv_sec)/1000000.0, ramsize);
  if (usage->ru_utime.tv_sec *1000000 + usage->ru_utime.tv_usec > limit_millis*1000){
    debug("Time limit exceeded\n");
    time_exceeded = 1;
  }else{
    limit_millis = usage->ru_utime.tv_sec * 1000 + usage->ru_utime.tv_usec / 1000;
  }
  
  if (ramsize >= limit_KBytes || memory_exceeded){
    memory_exceeded = 1;
    ramsize = limit_KBytes;
  }else if (ramsize + 32 >= limit_KBytes && signal == SIGSEGV){
    debug("Memory limit probably exceeded, since we died by SIGSEGV\n");
    memory_exceeded = 1;
    ramsize = limit_KBytes;
  }else{
    limit_KBytes = ramsize;
  }
  
  if (memory_exceeded)ex->cause = C_mem;
  if (time_exceeded)ex->cause = C_time;
}


int setlim(int limit, rlim_t val){
  struct rlimit lim;
  lim.rlim_cur = val;
  lim.rlim_max = val;
  return setrlimit(limit, &lim);
}
void limits_set(){
  attempt(setlim(RLIMIT_CPU, (1000+limit_millis)/1000));
  attempt(setlim(RLIMIT_AS, limit_KBytes * 1024));
  attempt(setlim(RLIMIT_CORE, 0));
  setlim(RLIMIT_STACK, RLIM_INFINITY);
  //possibly unset more limits
}

void handle_alarm(int sig){
  if (sig != SIGALRM)return;
  struct timeval tv;
  gettimeofday(&tv, 0);
  if (tv.tv_sec >= endtime){
    timeout=1;
    exited_syscall = curr_syscall;
  }else{
    alarm(endtime - tv.tv_sec);
  }
}

void setalarm(){
  struct sigaction act;
  act.sa_handler = &handle_alarm;
  act.sa_flags=0;
  act.sa_restorer=0;
  sigemptyset(&act.sa_mask);
  sigaddset(&act.sa_mask, SIGALRM);
  struct timeval tv;
  gettimeofday(&tv, 0);
  endtime = tv.tv_sec + (limit_millis*3/2000) + 1;
  attempt(sigaction(SIGALRM, &act, 0));
  alarm(limit_millis/1000 + 2);
}
void find_memusage(){
  char buf[4002];
  sprintf(buf, "/proc/%d/status", pid);
  int f = attempt(open(buf, O_RDONLY));
  int len = attempt(read(f, buf, 4000));
  attempt(close(f));
  buf[len]=0;
  char* p = strstr(buf, "\nVmPeak:");
  
  attempt(p?0:-1);
  sscanf(p, "\nVmPeak: %d", &ramsize);
  debug("Max ram usage: %d\n", ramsize);
}
int timed_out(){
  return timeout;
}
int get_exited_syscall(){return exited_syscall;}



void kill_the_bastard(){
  static int killing = 0;
  if (killing){
    debug("Avoiding recursive killing\n");
    return;
  }
  killing = 1;
  //program has attempted something annoying
  debug("Killing process\n");
  find_memusage();
  if (kill(pid, SIGKILL) < 0){
    if (errno!=ESRCH){
      bug("Can't kill child?!?");
    }
  }
  killing = 0;
}




void bug(const char* msg){
  fprintf(stderr, "B: %s\n", msg);
  kill_the_bastard();
  exit(128);
}




#define allow(a) [__NR_##a] = 1
const int syscall_permitted[] = {
  allow(read),
  allow(write),
  allow(exit),
  allow(brk),
  allow(fstat),
  allow(mmap),
  allow(munmap),
  allow(uname),
  allow(mprotect),
#ifdef __NR_sigprocmask
  allow(sigprocmask),
#endif
  allow(rt_sigprocmask),
  allow(set_thread_area),
  allow(exit_group),
  allow(time),
  allow(gettimeofday),
#ifdef __NR_fstat64
  allow(fstat64),
#endif
#ifdef __NR_mmap2
  allow(mmap2),
#endif
#ifdef __NR_arch_prctl
  allow(arch_prctl)
#endif
};
#undef allow

#ifdef x32
#define PT_SYSCALL_POS (4 * ORIG_EAX)
#define PT_SYSCALL_RET (4 * EAX)
#endif
#ifdef x64
#define PT_SYSCALL_POS (8 * ORIG_RAX)
#define PT_SYSCALL_RET (8 * RAX)
#endif
int check_syscall(){
  static int in_syscall = 0;

  int call = ptrace(PTRACE_PEEKUSER, pid, PT_SYSCALL_POS, 0);
  if (errno)attempt(call);

  debug2("System call %s: %s [#%d]\n", in_syscall?"exit":"entry", get_syscall_name(call), call);
  if (in_syscall){
    int ret = ptrace(PTRACE_PEEKUSER, pid, PT_SYSCALL_RET,0);
    if (errno)attempt(ret);
    if (ret == -ENOMEM){
      debug("Out of memory in system call %d\n", call);
      memory_exceeded = 1;
    }
    curr_syscall=0;
  }else{
    curr_syscall=call;
  }

  in_syscall=!in_syscall;


  int allowed;
  if (call >= 0 && call < sizeof(syscall_permitted)/sizeof(syscall_permitted[0])){
    allowed = syscall_permitted[call];
  }else{
    allowed = 0;
  }
  if (!allowed){
    debug("Disallowed syscall\n");
    kill_the_bastard();
    return call;
  }else{
    return 0;
  }



}



int main(int argc, char* argv[]){
  if (argc>=100){
    fprintf(stderr,"Too many arguments\n");
    return 1;
  }
  limit_millis = -1;
  limit_KBytes = -1;
  int c;
  errno=0;
  int print_usage = 0;
  while ((c=getopt(argc, argv, "+dt:m:")) != -1){
    if (c=='d')debug_on ++;
    else if (c=='t'){
      char* x;
      limit_millis = strtol(optarg, &x, 10);
      if (errno==ERANGE || *x){
	fprintf(stderr, "%s is not a valid number of milliseconds\n", optarg);
	return 1;
      }
    }else if (c=='m'){
      char* x;
      limit_KBytes = strtol(optarg, &x, 10);
      if (errno==ERANGE || *x){
	fprintf(stderr, "%s is not a valid number of kilobytes\n", optarg);
	return 1;
      }
    }else if (c=='?'){
      print_usage = 1;
      break;
    }
  }
  if (limit_millis == -1){
    fprintf(stderr, "Please specify time limit\n");
    print_usage = 1;
  }
  if (limit_KBytes == -1){
    fprintf(stderr, "Please specify memory limit\n");
    print_usage = 1;
  }
  if (optind >= argc || print_usage){
    fprintf(stderr, "Usage: %s [-d] [-d] [-t msecs] [-m KB] progname options...\n", argv[0]);
    return 1;
  }
  
  char* ch_prog = argv[optind];
  char* ch_args[110];
  int i;
  for (i=optind+1;i<argc;i++){
    ch_args[i-optind-1] = argv[i];
  }
  ch_args[argc-optind]=0;
  char* ch_env[1] = {NULL};
  



  debug("Starting, pid: %d\n",getpid());
  int kill_stderr = fcntl(3, F_GETFD) < 0;
  if (kill_stderr){debug("stderr will not be outputted\n");}
  else {debug("stderr will be sent to fd 3\n");}
  if ((pid = attempt(fork()))==0){
    debug("Child starting, pid: %d\n",getpid());
    int stderrfd = 3;
    if (kill_stderr){
      stderrfd = open("/dev/null", O_WRONLY);
    }
    if (dup2(stderrfd, 2) < 0){
      fprintf(stderr, "B: Can't redirect stderr to %d. If you can read this message, the world is even more bizzare and unfair than I thought it was\n", stderrfd);
      exit(128);
    }
    if (ptrace(PTRACE_TRACEME, 0, 0, 0)<0){
      exit(128);
    }
    limits_set();
    
    execve(ch_prog, ch_args, ch_env);
  }

  struct rusage usage;
  exit_type exit_data;
  exit_data.arg = -1;
  exit_data.cause=C_unknown;


  debug("Waiting for child\n");
  int status;
  attempt(wait4(pid, &status, 0, &usage));
  if (WIFSTOPPED(status)){
    if (WSTOPSIG(status) != SIGTRAP){
      debug("Child stopped by unusual signal %d\n", WSTOPSIG(status));
    }else{
      debug("Child stopped\n");
    }
    attempt(ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXIT));
  }else if (WIFSIGNALED(status)){
    //Assume it's because the executable image is too big
    //This happens if more than <memlimit> bytes are declared as globals
    debug("Child already dead from signal %d\n", WTERMSIG(status));
    memory_exceeded = 1;
    exit_data.cause = C_mem;
  }else{
    fprintf(stderr, "P: Couldn't start child %s\n", ch_prog);
    return 2;
  }
  setalarm();
  int signal = 0;

  




  while (1){
    int res = ptrace(PTRACE_SYSCALL, pid, 0, signal);
    if (res < 0 && errno == ESRCH) break;
    else attempt(res);
    if (wait4(pid, &status, 0, &usage) < 0){
      if (errno != EINTR || !timed_out()){
	attempt(-1 /* wait4 */);
      }
    }
    if (timed_out() && exit_data.cause != C_wallclock){
      debug("Wallclock timeout\n");
      exit_data.cause = C_wallclock;
      exit_data.arg = get_exited_syscall();
      kill_the_bastard();
    }else if (WIFSTOPPED(status) && WSTOPSIG(status)==SIGTRAP && status>>16 == PTRACE_EVENT_EXIT){
      debug("Program exiting, checking mem...\n");
      find_memusage();
      signal=0;
    }else if (WIFSTOPPED(status) && WSTOPSIG(status)==SIGTRAP){
      int call;
      if ((call = check_syscall())){
	exit_data.cause = C_syscall;
	exit_data.arg = call;
      }
      signal=0;
    }else if (WIFEXITED(status)){
      exit_data.cause = C_ok;
      exit_data.arg = WEXITSTATUS(status);
      signal=0;
    }else if (WIFSIGNALED(status)){
      debug("Program terminated by signal %d\n", WTERMSIG(status));
      if (exit_data.cause == C_unknown){
	exit_data.cause = C_signal;
	exit_data.arg = WTERMSIG(status);
      }
      signal = WTERMSIG(status);
    }else if (WIFSTOPPED(status)){
      debug("Signal %d received\n",WSTOPSIG(status));
      signal = WSTOPSIG(status);
    }else{
      bug("Unknown reason for program stop");
    }
  }
  limits_check(&usage, signal, &exit_data);




  switch(exit_data.cause){
  case C_unknown:
    bug("unknown program exit cause\n");
  case C_ok:
    fprintf(stderr, "O: %d was exit code\n", exit_data.arg);
    break;
  case C_time:
    fprintf(stderr, "T: Program timed out\n");
    break;
  case C_mem:
    fprintf(stderr, "M: Memory limit exceeded\n");
    break;
  case C_wallclock:
    if (exit_data.arg == __NR_read){
      fprintf(stderr, "H: Program hung waiting for input\n");
    }else{
      fprintf(stderr, "W: Wallclock timeout in syscall %s\n", get_syscall_name(exit_data.arg));
    }
    break;
  case C_syscall:
    fprintf(stderr,"X: %s (syscall #%d) was called by the program (disallowed syscall)\n", get_syscall_name(exit_data.arg), exit_data.arg);
    break;
  case C_signal:
    if (exit_data.arg>32)exit_data.arg=32;
    const char* signame;
    if (exit_data.arg >= 0 && exit_data.arg < sizeof(signals)/sizeof(signals[0])){
      signame = signals[exit_data.arg];
    }else{
      signame = "[unknown signal]";
    }
    fprintf(stderr,"S: %s %s\n", signame, strsignal(exit_data.arg));
    break;
  }
  fprintf(stderr,"t: %d milliseconds of CPU time used\nm: %d KB used (peak)\n", limit_millis, limit_KBytes);
  return 0;
}



