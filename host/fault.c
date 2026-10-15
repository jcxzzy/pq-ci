// 崩溃现场转储（独立编译单元：ucontext.h 在 macOS 需要 _XOPEN_SOURCE，
// 放这里定义避免影响主文件的符号可见性）。
#define _XOPEN_SOURCE 700
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>

typedef struct { char name[16]; uint8_t *base; size_t size; } mod_ref_t;
extern mod_ref_t g_mod_ref[8];
extern int g_nmod_ref;
extern int g_last_svc;

static void fault_dump(int sig, siginfo_t *si, void *uc_) {
    ucontext_t *uc = uc_;
    uint64_t pc = uc->uc_mcontext->__ss.__pc, lr = uc->uc_mcontext->__ss.__lr;
    char where[64] = "非模块区";
    for (int i = 0; i < g_nmod_ref; i++) {
        uint64_t b = (uint64_t)g_mod_ref[i].base;
        if (pc >= b && pc < b + g_mod_ref[i].size) {
            snprintf(where, sizeof where, "%s+%#llx", g_mod_ref[i].name, (unsigned long long)(pc - b));
            break;
        }
    }
    fprintf(stderr, "[dm] FAULT sig=%d addr=%p pc=%#llx(%s) lr=%#llx 最近svc#%d\n",
            sig, si->si_addr, (unsigned long long)pc, where, (unsigned long long)lr, g_last_svc);
    _exit(70);
}

static void watchdog(int sig) {
    (void)sig;
    fprintf(stderr, "[dm] 看门狗 120 秒到期（最近svc#%d）\n", g_last_svc);
    _exit(71);
}

void diag_install(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = fault_dump;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    struct sigaction sw = {0};
    sw.sa_handler = watchdog;
    sigaction(SIGALRM, &sw, NULL);
}
