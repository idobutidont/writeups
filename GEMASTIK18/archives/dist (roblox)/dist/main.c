#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>

static void seccomp_roblox(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) _exit(1);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(pivot_root), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(chroot), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(mount), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(unshare), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(reboot), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ptrace), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open_by_handle_at), 0);
    if (seccomp_load(ctx) < 0) _exit(1);
    seccomp_release(ctx);
}

int main(){
    if (chroot("penjara")){
        perror("chroot");
        _exit(EXIT_FAILURE);
    }
    if (chdir("/")){
        perror("chdir");
        _exit(EXIT_FAILURE);
    }
    seccomp_roblox();
    return execve("/bin/sh", (char *const []){"/bin/sh", NULL}, NULL);
}
