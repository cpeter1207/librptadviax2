#define _GNU_SOURCE
/** @file
 * @brief Child-thread-only real kernel error fixture; never loaded by production.
 */
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static _Thread_local int realtime_failure;
static _Thread_local unsigned realtime_reads;
static _Thread_local unsigned realtime_fail_after;
static _Thread_local int truncated_control;
static _Thread_local int truncated_payload;
/** Force a real kernel truncation using a smaller valid receive capacity once. */
void rptadv_test_truncate_receive(int control) {
  if (control) truncated_control = 1;
  else truncated_payload = 1;
}
ssize_t recvmsg(int fd, struct msghdr *message, int flags) {
  if (truncated_control) {
    message->msg_controllen = sizeof(struct cmsghdr);
    truncated_control = 0;
  }
  if (truncated_payload && message->msg_iovlen) {
    message->msg_iov[0].iov_len = 1;
    truncated_payload = 0;
  }
  return (ssize_t)syscall(SYS_recvmsg, fd, message, flags);
}
/** Child preload only; all unselected clocks/threads use the real kernel syscall. */
int clock_gettime(clockid_t clock, struct timespec *value) {
  if (clock == CLOCK_REALTIME && (realtime_failure ||
      (realtime_fail_after && ++realtime_reads > realtime_fail_after))) {
    errno = EIO;
    return -1;
  }
  return (int)syscall(SYS_clock_gettime, clock, value);
}
/** Affect only this child test thread's subsequent actual realtime reads. */
void rptadv_test_fail_realtime(void) { realtime_failure = 1; }
/** Fail only after this many real reads on this child thread. */
void rptadv_test_fail_realtime_after(unsigned reads) { realtime_fail_after = reads; realtime_reads = 0; }

/** Install only after real socket/account construction in an owned test child. */
int rptadv_test_fail_syscall(unsigned selection) {
  unsigned target;
  switch (selection) {
  case 0: target = SYS_getrandom; break;
  case 1: target = SYS_getsockname; break;
  case 2: target = SYS_sendto; break;
  case 3: target = SYS_timerfd_create; break;
  case 4: target = SYS_setsockopt; break;
  case 5: target = SYS_timerfd_settime; break;
  default: target = SYS_recvmsg; break;
  }
  struct sock_filter rules[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
               (unsigned)offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, target, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EIO),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog program = {
      .len = (unsigned short)(sizeof(rules) / sizeof(rules[0])), .filter = rules};
  if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) != 0)
    return -1;
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

/** Make only this child thread's actual owned timerfd read report cancellation. */
int rptadv_test_cancel_timerfd(int fd) {
  struct sock_filter rules[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (unsigned)offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 0, 3),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (unsigned)offsetof(struct seccomp_data, args[0])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)fd, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ECANCELED),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog program = {
      .len = (unsigned short)(sizeof(rules) / sizeof(rules[0])), .filter = rules};
  if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) != 0)
    return -1;
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}
