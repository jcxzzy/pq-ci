// 崩溃现场转储（独立编译单元：ucontext.h 在 macOS 需要 _XOPEN_SOURCE，
// 放这里定义避免影响主文件的符号可见性）。
#define _XOPEN_SOURCE 700
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>
#include <unistd.h>

typedef struct { char name[16]; uint8_t *base; size_t size; } mod_ref_t;
extern mod_ref_t g_mod_ref[8];
extern int g_nmod_ref;
extern int g_last_svc;
extern uint64_t g_guest_lo, g_guest_hi;   // dmhost 预留块区间（客体堆在内）

static void where_of(uint64_t a, char *out, size_t n) {
    for (int j = 0; j < g_nmod_ref; j++) {
        uint64_t b = (uint64_t)g_mod_ref[j].base;
        if (a >= b && a < b + g_mod_ref[j].size) { snprintf(out, n, "%s+%#llx", g_mod_ref[j].name, (unsigned long long)(a - b)); return; }
    }
    snprintf(out, n, "非模块区");
}

// 帧链回溯（x29 链），最多 8 层：LR 归属到模块。供 fault_dump 与 svc Break 共用。
void guest_backtrace(uint64_t fp) {
    uint64_t f = fp;
    for (int i = 0; i < 8 && f; i++) {
        uint64_t nxt = *(uint64_t *)f, ret = *(uint64_t *)(f + 8);
        char w2[64] = "";
        where_of(ret, w2, sizeof w2);
        fprintf(stderr, "[dm]   帧%d fp=%#llx lr=%#llx(%s)\n", i, (unsigned long long)f, (unsigned long long)ret, w2);
        if (nxt <= f) break;
        f = nxt;
    }
}

static void fault_dump(int sig, siginfo_t *si, void *uc_) {
    ucontext_t *uc = uc_;
    uint64_t pc = uc->uc_mcontext->__ss.__pc, lr = uc->uc_mcontext->__ss.__lr;
    uint64_t sp = uc->uc_mcontext->__ss.__sp, fp = uc->uc_mcontext->__ss.__fp;
    uint64_t x0 = uc->uc_mcontext->__ss.__x[0], x1 = uc->uc_mcontext->__ss.__x[1];
    uint64_t x2 = uc->uc_mcontext->__ss.__x[2], x3 = uc->uc_mcontext->__ss.__x[3];
    uint64_t x19 = uc->uc_mcontext->__ss.__x[19], x20 = uc->uc_mcontext->__ss.__x[20];
    char where[64];
    where_of(pc, where, sizeof where);
    fprintf(stderr, "[dm] FAULT sig=%d addr=%p pc=%#llx(%s) lr=%#llx sp=%#llx fp=%#llx x0=%#llx x1=%#llx x2=%#llx x3=%#llx 最近svc#%d\n",
            sig, si->si_addr, (unsigned long long)pc, where, (unsigned long long)lr,
            (unsigned long long)sp, (unsigned long long)fp,
            (unsigned long long)x0, (unsigned long long)x1, (unsigned long long)x2, (unsigned long long)x3, g_last_svc);
    fprintf(stderr, "[dm]   x19=%#llx x20=%#llx", (unsigned long long)x19, (unsigned long long)x20);
    if (x19 >= g_guest_lo && x19 < g_guest_hi) {   // 客体堆里的 ctx 对象：直接转储关键字段
        fprintf(stderr, "  [x19+0x90..0xc0]:");
        for (int o = 0x90; o <= 0xc0; o += 8)
            fprintf(stderr, " +%#x:%#llx", o, (unsigned long long)*(uint64_t *)(x19 + o));
    }
    fputc('\n', stderr);
    guest_backtrace(fp);
    _exit(70);
}

static void watchdog(int sig) {
    (void)sig;
    fprintf(stderr, "[dm] 看门狗 120 秒到期（最近svc#%d）\n", g_last_svc);
    _exit(71);
}

static void on_host_exit(void) {
    fprintf(stderr, "[dm] 进程正常退出（exit/main 返回；最近svc#%d）\n", g_last_svc);
}
static void on_abort(int sig, siginfo_t *si, void *uc_) {
    // SIGTRAP = 客体 brk 指令（clang 的 trap/unreachable/断言）；带上现场再退
    if (sig == SIGTRAP && uc_) {
        ucontext_t *uc = uc_;
        uint64_t pc = uc->uc_mcontext->__ss.__pc, lr = uc->uc_mcontext->__ss.__lr;
        uint64_t sp = uc->uc_mcontext->__ss.__sp, fp = uc->uc_mcontext->__ss.__fp;
        uint64_t x0 = uc->uc_mcontext->__ss.__x[0], x1 = uc->uc_mcontext->__ss.__x[1];
        uint64_t x2 = uc->uc_mcontext->__ss.__x[2], x3 = uc->uc_mcontext->__ss.__x[3];
        char w[64];
        where_of(pc, w, sizeof w);
        fprintf(stderr, "[dm] HOST SIGTRAP pc=%#llx(%s) lr=%#llx sp=%#llx fp=%#llx x0=%#llx x1=%#llx x2=%#llx x3=%#llx 最近svc#%d\n",
                (unsigned long long)pc, w, (unsigned long long)lr, (unsigned long long)sp,
                (unsigned long long)fp, (unsigned long long)x0, (unsigned long long)x1,
                (unsigned long long)x2, (unsigned long long)x3, g_last_svc);
        guest_backtrace(fp);
        _exit(89);
    }
    fprintf(stderr, "[dm] HOST SIGABRT（最近svc#%d）\n", g_last_svc);
    _exit(88);
}

void diag_install(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = fault_dump;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    struct sigaction sw = {0};
    sw.sa_handler = watchdog;
    sigaction(SIGALRM, &sw, NULL);
    struct sigaction ab = {0};
    ab.sa_sigaction = on_abort;
    ab.sa_flags = SA_SIGINFO;
    sigaction(SIGABRT, &ab, NULL);
    sigaction(SIGTRAP, &ab, NULL);
    atexit(on_host_exit);
}
