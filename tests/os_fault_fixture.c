/** @file
 * @brief Child-thread-only real kernel error fixture; never loaded by production.
 */
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

/** Install only after real socket/account construction in an owned test child. */
int rptadv_test_fail_syscall(unsigned selection) {
  unsigned target = selection == 0 ? SYS_getrandom : selection == 1 ? SYS_getsockname : SYS_sendto;
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
