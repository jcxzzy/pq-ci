// pq-port 宿主（Apple silicon / arm64）：装载改写后的三模块，按 d2r-mobile 宿主的启动序引导。
// 架构照抄 d2r-mobile dm/host（MIT）：
//   装载（loader.c 的多模块 + 键页 + 门登记 + 跨模块重定位）· 门 ABI（entry.S dm_gate）
//   · 线程槽（pthread_setspecific × tpidrro_el0 直接 TSD）· 启动序（main.c guest_main）
// 本文件是 Apple silicon 上跑通「SDK 初始化 → nnMain」的最小骨架；svc 处理器按
// bootsim 的实证清单逐个补齐（hle_svc_dispatch 里未实现的记名返回错误码）。
// 构建：make -C host （clang -arch arm64；本仓库的 Intel Mac 只做交叉编译验证）
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_MOD 8
#define PAGE 0x4000
#define LOG(...) do { fprintf(stderr, "[dm] " __VA_ARGS__); fputc('\n', stderr); } while (0)
#define die(...) do { LOG("FATAL " __VA_ARGS__); abort(); } while (0)

typedef struct { uint32_t st_name; uint8_t st_info, st_other; uint16_t st_shndx; uint64_t st_value, st_size; } Elf64_Sym;
typedef struct { int64_t d_tag; union { uint64_t d_val, d_ptr; } d_un; } Elf64_Dyn;
typedef struct { uint64_t r_offset, r_info; int64_t r_addend; } Elf64_Rela;
#define ELF64_R_SYM(i) ((i) >> 32)
#define ELF64_R_TYPE(i) ((i) & 0xffffffff)
enum { DT_INIT = 12, DT_RELA = 7, DT_RELASZ = 8, DT_JMPREL = 23, DT_PLTRELSZ = 2,
       DT_SYMTAB = 6, DT_STRTAB = 5, DT_INIT_ARRAY = 25, DT_INIT_ARRAYSZ = 27 };
enum { R_AARCH64_ABS64 = 257, R_AARCH64_GLOB_DAT = 1025, R_AARCH64_JUMP_SLOT = 1026, R_AARCH64_RELATIVE = 1027 };

typedef struct {
    char name[16];
    uint8_t *base;
    size_t size;
    uint64_t text_end, patch_off, key_page_off, key_page_size;
    unsigned key_idx[4];
    const Elf64_Dyn *dyn;
    const Elf64_Sym *symtab;
    const char *strtab;
    unsigned nsym;
    uint64_t init;
} module_t;

static module_t g_mod[MAX_MOD];
static int g_nmod;
static pthread_key_t g_key18, g_keytls, g_keytlr, g_keygate;
extern void dm_gate(void);          // entry.S

// ---------- 未实现导入：记名桩（entry.S 静态桩表）----------
#define MAX_STUB 2048
static unsigned g_nstub;
static const char *g_stub_name[MAX_STUB];
static uint8_t g_stub_seen[MAX_STUB];
extern uint8_t unimpl_stubs[MAX_STUB][8];

uint64_t unimpl_c(unsigned idx, uint64_t *regs) {
    if (!g_stub_seen[idx]++) {
        LOG("UNIMPL %s (x0=%#llx x1=%#llx)", g_stub_name[idx], (unsigned long long)regs[0], (unsigned long long)regs[1]);
        // OBSS_ 前缀站点：把 x1 当 C 串打印（观测传给回退读取的路径）
        if (!strncmp(g_stub_name[idx], "OBSS_", 5) && regs[1] > 0x10000) {
            char buf[130];
            size_t n = 0;
            uint8_t *q = (uint8_t *)(uintptr_t)regs[1];
            while (n < 128) { uint8_t c = q[n]; if (!c) break; buf[n] = (c >= 32 && c < 127) ? (char)c : '?'; n++; }
            buf[n] = 0;
            LOG("  [OBSS] x1=%s", buf);
        }
        // OBSD_ 前缀站点：转储 x0 指向的对象头（观测归档管理器等运行时结构）
        if (!strncmp(g_stub_name[idx], "OBSD_", 5) && regs[0] > 0x10000) {
            uint64_t p = regs[0];
            fprintf(stderr, "[dm]   [x0]=%#llx [%#llx]:", (unsigned long long)p, (unsigned long long)p);
            for (int o = 0; o <= 0x38; o += 8) {
                uint64_t v = 0;
                memcpy(&v, (void *)(uintptr_t)(p + o), 8);
                fprintf(stderr, " +%#x:%#llx", o, (unsigned long long)v);
            }
            fputc('\n', stderr);
        }
    }
    return 0;
}

static uint64_t resolve_import(module_t *m, const char *name) {
    for (unsigned k = 0; k < g_nstub; k++)
        if (!strcmp(g_stub_name[k], name)) return (uint64_t)&unimpl_stubs[k];
    if (g_nstub >= MAX_STUB) die("stub overflow");
    unsigned k = g_nstub++;
    g_stub_name[k] = name;
    return (uint64_t)&unimpl_stubs[k];
}

// ---------- 符号 ----------
static void *module_sym(module_t *m, const char *name) {
    for (unsigned i = 1; i < m->nsym; i++) {
        const Elf64_Sym *s = &m->symtab[i];
        if (s->st_shndx && !strcmp(m->strtab + s->st_name, name)) return m->base + s->st_value;
    }
    return NULL;
}
static void *guest_sym(const char *name) {
    for (int i = 0; i < g_nmod; i++) { void *p = module_sym(&g_mod[i], name); if (p) return p; }
    return NULL;
}
static void *req(const char *n) { void *p = guest_sym(n); if (!p) die("缺符号 %s", n); return p; }

// ---------- 门表 ----------
enum { G_SVC, G_CNTPCT, G_CNTVCT };
typedef struct { uint64_t ret; int kind, arg; } gate_t;
#define GATE_BITS 12
static gate_t g_gate[1u << GATE_BITS];
static int g_ngate;
static inline unsigned gate_h(uint64_t a) { return (unsigned)(((a >> 2) * 0x9E3779B97F4A7C15ull) >> (64 - GATE_BITS)); }
static void gate_register(uint64_t ret, const char *kind, int arg) {
    int k = !strcmp(kind, "svc") ? G_SVC : !strcmp(kind, "cntpct") ? G_CNTPCT : !strcmp(kind, "cntvct") ? G_CNTVCT : -1;
    if (k < 0) die("未知门类 %s", kind);
    if (++g_ngate > (1 << GATE_BITS) / 4) die("gate overflow");
    unsigned i = gate_h(ret);
    while (g_gate[i].ret) { if (g_gate[i].ret == ret) die("门重复登记 %#llx", (unsigned long long)ret); i = (i + 1) & ((1u << GATE_BITS) - 1); }
    g_gate[i] = (gate_t){ret, k, arg};
}

static uint64_t now_ns(void) { return (uint64_t)clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW); }

// ---------- 客体地址空间（照 d2r-mobile hle_svc.c 的架构：预留一整块，按 Horizon 分区） ----------
// SDK 的 AddressRegionManager 以 alias 基址为起点硬扫 1 GB（sdk+0x8cc3c +0x24 实证
// mov w9,#0x40000000），alias 区给足 1 GB；GetAslrSpaceEnd = GetInfo(12)+13、
// GetStackGuardEnd = GetInfo(14)+15（sdk+0x8fb80 / 0x8fc04 实证，均为基址+大小）。
#define RESERVE (6ull << 30)          // 6 GB：d2r 实测 iOS 无扩展寻址权限时的单次预留上限
#define ALIAS_CAP 0x40000000ull       // alias 1 GB（g_as+0x10000000 … g_as+0x50000000）
#define STACK_CAP 0x10000000ull       // 栈区 256 MB（g_as+0x50000000 …）
#define HEAP_CAP  (RESERVE - 0x60000000ull)   // 堆区从 g_as+0x60000000 到块尾
static uint8_t *g_as;                 // 客体地址空间基址（= ASLR 区基址）
static uint8_t *g_alias, *g_stack, *g_heap;
static size_t g_heap_cur;             // SetHeapSize 已提交大小
uint64_t g_guest_lo, g_guest_hi;      // 预留块区间（fault.c 转储客体对象用）
static void mem_init(void) {
    if (g_as) return;
    g_as = mmap(NULL, RESERVE, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (g_as == MAP_FAILED) die("预留客体地址空间失败");
    g_alias = g_as + 0x10000000;
    g_stack = g_as + 0x50000000;
    g_heap  = g_as + 0x60000000;
    g_guest_lo = (uint64_t)g_as;
    g_guest_hi = (uint64_t)g_as + RESERVE;
    LOG("客体地址空间 %p +%#llx（alias %p / stack %p / heap %p）", g_as, (unsigned long long)RESERVE, g_alias, g_stack, g_heap);
}

// 已映射区间登记（MapMemory 线程栈），QueryMemory 据此回报（d2r 配方）
#define MAX_MAP 256
static struct { uint64_t base, size, src; } g_map[MAX_MAP];
static int g_nmap;
static int map_find(uint64_t a, uint64_t n) {
    for (int i = 0; i < g_nmap; i++) if (a < g_map[i].base + g_map[i].size && g_map[i].base < a + n) return i + 1;
    return 0;
}

// ---------- 客体线程与同步（d2r hle_thread.c 的最小版） ----------
// Apple Silicon 上宿主客体同构：客体线程 = 装好四线程槽（K18/KTLS/KTLR/KGATE）
// 后由 dm_thread_enter 切到客体栈的 pthread。互斥/条件变量用「全局锁 + 单条件
// 变量广播」实现——惊群可忍，条件由客体重查，语义与 futex 一致。
#define R_TIMEOUT 0xEA01u
#define R_BAD_HANDLE 0xE401u
typedef struct thr {
    pthread_t pt;
    uint64_t entry, arg, stack_top;
    int prio, core, started, exited, closed;
    uint32_t handle;
    struct thr *all;
} thr_t;
typedef struct { int signaled; } ev_t;
enum { H_NONE = 0, H_THREAD, H_EVENT, H_FAKE };
#define MAX_H 512
static struct { int type; void *obj; } g_htab[MAX_H];
static pthread_mutex_t G = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t GV = PTHREAD_COND_INITIALIZER;
static thr_t *g_thr_all;
static thr_t *g_thr_main;
static __thread thr_t *t_cur;
extern void dm_thread_enter(uint64_t, uint64_t, uint64_t);
void dm_thread_returned(void) { die("客体线程入口返回（须经 ExitThread 退出）"); }
void guest_thread_init(void);

static uint32_t h_alloc(int type, void *obj) {
    for (uint32_t i = 1; i < MAX_H; i++)
        if (!g_htab[i].type) { g_htab[i].type = type; g_htab[i].obj = obj; return i + 0x100; }
    die("句柄表满");
}
static void *h_get(uint32_t h, int type) {
    uint32_t i = h - 0x100;
    return (i && i < MAX_H && g_htab[i].type == type) ? g_htab[i].obj : NULL;
}
static int h_signaled(uint32_t h) {
    if (h == 0xffff8000u) return 0;                       // 当前线程句柄
    void *o;
    if ((o = h_get(h, H_THREAD))) return ((thr_t *)o)->exited;
    if ((o = h_get(h, H_EVENT))) return ((ev_t *)o)->signaled;
    return g_htab[h - 0x100].type != H_NONE;              // 假句柄（服务会话）：视为已触发
}
static struct timespec deadline_from(int64_t tmo_ns) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    if (tmo_ns >= 0) {
        ts.tv_sec += (time_t)(tmo_ns / 1000000000);
        ts.tv_nsec += (long)(tmo_ns % 1000000000);
        if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
    } else ts.tv_sec += 3600;   // 无限：睡长觉，看门狗兜底
    return ts;
}
static void *thread_main(void *p) {
    thr_t *t = p;
    t_cur = t;
    guest_thread_init();
    pthread_mutex_lock(&G);
    while (!t->started) pthread_cond_wait(&GV, &G);
    pthread_mutex_unlock(&G);
    dm_thread_enter(t->entry, t->arg, t->stack_top);
    die("不可达");
}
static void thread_exit_current(void) {
    thr_t *t = t_cur;
    void guest_backtrace(uint64_t);
    if (t) LOG("ExitThread h=%#x%s", t->handle, t == g_thr_main ? "（主线程：进程随之结束）" : "");
    else LOG("ExitThread（无登记线程）");
    guest_backtrace((uint64_t)__builtin_frame_address(0));
    pthread_mutex_lock(&G);
    if (t) {
        t->exited = 1;
        pthread_cond_broadcast(&GV);
    }
    pthread_mutex_unlock(&G);
    pthread_exit(NULL);
}
static uint32_t main_thread_register(void) {
    static thr_t mt;
    mt.pt = pthread_self(); mt.started = 1; mt.prio = 44; mt.core = 0;
    pthread_mutex_lock(&G);
    mt.handle = h_alloc(H_THREAD, &mt);
    mt.all = g_thr_all; g_thr_all = &mt;
    pthread_mutex_unlock(&G);
    t_cur = &mt;
    g_thr_main = &mt;
    return mt.handle;
}
// 出参契约按各包装函数 svc 后指令实证（全量扫描 106 个门）：小标量一律从寄存器回——
// 包装函数自己 str x1/w1（GetInfo 值=x1、SetHeapSize 基址=x1、句柄=w1、PageInfo=w1、
// GetThreadCoreMask=core w1 + mask x2、资源限值=x1）；只有大结构体（MemoryInfo、
// ThreadContext）由本层直接写指针。此前把值写进 out 指针会被包装函数用残留寄存器
// 覆盖——addr=2 正是 GetInfo 残留 x1=InfoType 常量被当地址用。
static uint8_t g_svc_seen[256];   // 首次命中记录（文件域，防重复打印异常）

static uint64_t image_bytes(void) {
    uint64_t n = 0;
    for (int i = 0; i < g_nmod; i++) n += (g_mod[i].size + 0xfff) & ~0xfffull;
    return n;
}

static uint64_t svc_impl(int num, uint64_t *x) {
    switch (num) {
    case 1: {  // SetHeapSize(size) → x1 = 堆地址（在预留块堆区内提交 RW）
        mem_init();
        uint64_t size = x[1];
        if (size > HEAP_CAP) return 0xCE011;   // 超出堆区：让 SDK 按原版步进减 2 MB 重试
        if (size > g_heap_cur) { if (mprotect(g_heap + g_heap_cur, size - g_heap_cur, PROT_READ | PROT_WRITE)) die("SetHeapSize mprotect"); }
        else if (size < g_heap_cur) mprotect(g_heap + size, g_heap_cur - size, PROT_NONE);
        g_heap_cur = size;
        x[1] = (uint64_t)g_heap;
        return 0;
    }
    case 2: case 3: return 0;   // SetMemoryPermission / SetMemoryAttribute
    case 4: {  // MapMemory(dst, src, size)：SDK 建线程时把堆上的栈搬进栈区
        mem_init();
        uint64_t dst = x[0], src = x[1], size = x[2];
        if ((uint8_t *)(uintptr_t)dst < g_stack || (uint8_t *)(uintptr_t)dst + size > g_stack + STACK_CAP || map_find(dst, size)) return 0xDC01;
        uint64_t lo = dst & ~0x3FFFull, hi = (dst + size + 0x3FFF) & ~0x3FFFull;
        if (mprotect((void *)(uintptr_t)lo, hi - lo, PROT_READ | PROT_WRITE)) die("MapMemory mprotect");
        memcpy((void *)(uintptr_t)dst, (void *)(uintptr_t)src, size);
        if (g_nmap >= MAX_MAP) die("映射表满");
        g_map[g_nmap++] = (typeof(g_map[0])){dst, size, src};
        return 0;
    }
    case 5: {  // UnmapMemory(dst, src, size)：内容搬回源区
        uint64_t dst = x[0], src = x[1], size = x[2];
        int k = map_find(dst, size);
        if (!k || g_map[k - 1].base != dst || g_map[k - 1].size != size || g_map[k - 1].src != src) return 0xD401;
        memcpy((void *)(uintptr_t)src, (void *)(uintptr_t)dst, size);
        g_map[k - 1] = g_map[--g_nmap];
        return 0;
    }
    case 6: {  // QueryMemory(MemoryInfo* x0, PageInfo*, addr x2) → w1 = pageinfo
        mem_init();   // 结构体布局按 d2r：base(0x00) size(0x08) state(0x10) attr(0x14) perm(0x18) ipc(0x1c)
        uint64_t mi = x[0], addr = x[2];
        uint8_t *a = (uint8_t *)(uintptr_t)addr;
        uint64_t base = 0, esz = 0, state = 0, perm = 0;
        int k;
        if (a >= g_heap && a < g_heap + g_heap_cur) { base = (uint64_t)g_heap; esz = g_heap_cur; state = 5; perm = 3; }
        else if ((k = map_find(addr, 1))) { base = g_map[k - 1].base; esz = g_map[k - 1].size; state = 0xB; perm = 3; }
        else if (a >= g_as && a < g_as + RESERVE) {   // 预留块内未提交：回报到相邻边界为止的空闲区
            uint64_t lo = (uint64_t)g_as, hi = (uint64_t)g_as + RESERVE;
            if (a >= g_heap) lo = (uint64_t)g_heap + g_heap_cur;
            else if (hi > (uint64_t)g_heap) hi = (uint64_t)g_heap;
            for (int i = 0; i < g_nmap; i++) {
                uint64_t e = g_map[i].base + g_map[i].size;
                if (e <= addr && e > lo) lo = e;
                if (g_map[i].base > addr && g_map[i].base < hi) hi = g_map[i].base;
            }
            base = lo; esz = hi - lo;
        } else {
            for (int i = 0; i < g_nmod && !esz; i++) {   // 模块映像 = 代码区
                uint64_t b = (uint64_t)g_mod[i].base;
                if (addr >= b && addr < b + g_mod[i].size) { base = b; esz = g_mod[i].size; state = 3; perm = 5; }
            }
            if (!esz) {   // 宿主当前线程栈 → 状态 0xB（SDK 主线程记录拿 sp 查这里，见 d2r 注释）
                uint64_t top = (uint64_t)pthread_get_stackaddr_np(pthread_self());
                uint64_t ssz = pthread_get_stacksize_np(pthread_self());
                if (addr < top && addr >= top - ssz) { base = top - ssz; esz = ssz; state = 0xB; perm = 3; }
                else { base = addr & ~0x3FFFull; esz = 0x4000; state = 3; perm = 5; }
            }
        }
        if (mi) {
            memset((void *)(uintptr_t)mi, 0, 0x28);
            uint64_t *m = (uint64_t *)(uintptr_t)mi;
            m[0] = base; m[1] = esz;
            ((uint32_t *)m)[4] = (uint32_t)state; ((uint32_t *)m)[6] = (uint32_t)perm;
        }
        x[1] = 0;   // PageInfo
        return 0;
    }
    case 7:  // ExitProcess
        LOG("svc#7 ExitProcess");
        _exit(0);
    case 8: {  // CreateThread(→w1 h; x1 入口, x2 参数, x3 栈顶, w4 优先级, w5 核)：真 pthread
        thr_t *t = calloc(1, sizeof *t);
        t->entry = x[1]; t->arg = x[2]; t->stack_top = x[3];
        t->prio = (int)(int32_t)x[4]; t->core = (int)(int32_t)x[5];
        pthread_attr_t a; pthread_attr_init(&a);
        pthread_attr_setstacksize(&a, 1 << 20);   // 宿主栈只垫门框；真正的栈由 dm_thread_enter 切成客体栈
        if (pthread_create(&t->pt, &a, thread_main, t)) die("pthread_create");
        pthread_mutex_lock(&G);
        t->handle = h_alloc(H_THREAD, t);
        t->all = g_thr_all; g_thr_all = t;
        pthread_mutex_unlock(&G);
        x[1] = t->handle;
        return 0;
    }
    case 9: {  // StartThread(h)
        thr_t *t = h_get((uint32_t)x[0], H_THREAD);
        if (!t) return R_BAD_HANDLE;
        pthread_mutex_lock(&G); t->started = 1; pthread_cond_broadcast(&GV); pthread_mutex_unlock(&G);
        return 0;
    }
    case 10:  // ExitThread(退出码)：当前客体线程收尾退出
        thread_exit_current();
        return 0;
    case 11: {  // SleepThread(ns)：真睡，避免轮询空转烧看门狗
        uint64_t ns = x[0];
        struct timespec ts = { (time_t)(ns / 1000000000), (long)(ns % 1000000000) };
        nanosleep(&ts, NULL);
        return 0;
    }
    case 12: {  // GetThreadPriority(→w1, h)
        thr_t *t = h_get((uint32_t)x[1], H_THREAD);
        x[1] = t ? (uint32_t)t->prio : 44;
        return 0;
    }
    case 13: {  // SetThreadPriority(h, prio)
        thr_t *t = h_get((uint32_t)x[0], H_THREAD);
        if (t) t->prio = (int)(int32_t)x[1];
        return 0;
    }
    case 14: {  // GetThreadCoreMask(→w1 core, →x2 mask, h)
        thr_t *t = h_get((uint32_t)x[2], H_THREAD);
        x[1] = t ? (uint32_t)t->core : 0;
        x[2] = 7;
        return 0;
    }
    case 15: return 0;                        // SetThreadCoreMask
    case 16: return 0;                        // GetCurrentProcessorNumber
    case 17: {  // SignalEvent(h)
        ev_t *e = h_get((uint32_t)x[0], H_EVENT);
        if (!e) return R_BAD_HANDLE;
        pthread_mutex_lock(&G); e->signaled = 1; pthread_cond_broadcast(&GV); pthread_mutex_unlock(&G);
        return 0;
    }
    case 18: {  // ClearEvent(h)
        ev_t *e = h_get((uint32_t)x[0], H_EVENT);
        if (!e) return R_BAD_HANDLE;
        pthread_mutex_lock(&G); e->signaled = 0; pthread_mutex_unlock(&G);
        return 0;
    }
    case 21: {  // CreateTransferMemory(→w1 h)：假句柄（传输内存仅 NVN 数据流用）
        pthread_mutex_lock(&G); x[1] = h_alloc(H_FAKE, NULL); pthread_mutex_unlock(&G);
        return 0;
    }
    case 22: {  // CloseHandle(h)
        uint32_t i = (uint32_t)x[0] - 0x100;
        pthread_mutex_lock(&G);
        if (i && i < MAX_H) { g_htab[i].type = H_NONE; g_htab[i].obj = NULL; }
        pthread_mutex_unlock(&G);
        return 0;
    }
    case 23: {  // ResetSignal(h)
        ev_t *e = h_get((uint32_t)x[0], H_EVENT);
        if (e) { pthread_mutex_lock(&G); e->signaled = 0; pthread_mutex_unlock(&G); }
        return 0;
    }
    case 24: {  // WaitSynchronization(→w1 下标; x1 句柄数组, w2 个数, x3 超时)
        uint32_t *hs = (uint32_t *)(uintptr_t)x[1];
        uint32_t n = (uint32_t)x[2];
        int64_t tmo = (int64_t)x[3];
        struct timespec dl = deadline_from(tmo);
        pthread_mutex_lock(&G);
        int64_t idx = -1;
        for (;;) {
            for (uint32_t i = 0; i < n; i++) { uint32_t h = hs[i]; if (h && h_signaled(h)) { idx = i; break; } }
            if (idx >= 0) break;
            int rc = pthread_cond_timedwait(&GV, &G, &dl);
            if (rc == ETIMEDOUT && tmo >= 0) break;
        }
        pthread_mutex_unlock(&G);
        x[1] = (uint32_t)idx;   // -1 = 超时
        return idx >= 0 ? 0 : R_TIMEOUT;
    }
    case 25: return 0;                        // CancelSynchronization：全局广播下天然可重试
    case 26: {  // ArbitrateLock(owner_h, x1 锁地址, w2 标签)：等锁归零后原子占为己有
        volatile uint32_t *m = (volatile uint32_t *)(uintptr_t)x[1];
        uint32_t tag = (uint32_t)x[2];
        pthread_mutex_lock(&G);
        for (;;) {
            uint32_t v = *m;
            if (v == 0 && __sync_bool_compare_and_swap(m, 0, tag)) break;
            pthread_cond_wait(&GV, &G);   // 假醒无害：醒来重查锁字
        }
        pthread_mutex_unlock(&G);
        return 0;
    }
    case 27: {  // ArbitrateUnlock(x0 锁地址)：清锁 + 广播
        pthread_mutex_lock(&G);
        *(volatile uint32_t *)(uintptr_t)x[0] = 0;
        pthread_cond_broadcast(&GV);
        pthread_mutex_unlock(&G);
        return 0;
    }
    case 28: {  // WaitProcessWideKeyAtomic(x0 互斥地址, x1 键, w2 标签, x3 超时)：原子放锁再睡
        struct timespec dl = deadline_from((int64_t)x[3]);
        pthread_mutex_lock(&G);
        volatile uint32_t *m = (volatile uint32_t *)(uintptr_t)x[0];
        if (*m) { *m = 0; pthread_cond_broadcast(&GV); }
        pthread_cond_timedwait(&GV, &G, &dl);   // 假醒无害：客体条件变量循环自己重查谓词
        pthread_mutex_unlock(&G);
        return 0;
    }
    case 29: {  // SignalProcessWideKey(x0 键, w1 唤醒数)：广播（超集，谓词重查保证正确性）
        pthread_mutex_lock(&G);
        pthread_cond_broadcast(&GV);
        pthread_mutex_unlock(&G);
        return 0;
    }
    case 30: return now_ns() * 12 / 625;     // GetSystemTick（19.2 MHz）
    case 31: {  // ConnectToNamedPort(out h, name) → w1
        char nm[64] = {0};
        for (int i = 0; i < 63; i++) {
            uint8_t c = *(const uint8_t *)(uintptr_t)(x[1] + i);
            if (!c) break;
            nm[i] = (char)c;
        }
        LOG("svc#31 ConnectToNamedPort → %s", nm);
        pthread_mutex_lock(&G); x[1] = h_alloc(H_FAKE, NULL); pthread_mutex_unlock(&G);
        return 0;
    }
    case 33: LOG("svc#33 SendSyncRequest h=%#llx（IPC 未接管）", (unsigned long long)x[0]); return 0xF601;
    case 36: x[1] = 0x50; return 0;                   // GetProcessId(out u64, h) → x1
    case 37: {  // GetThreadId(out u64, h) → x1
        uint32_t i = (uint32_t)x[1] - 0x100;
        x[1] = 0x6000 + (i < MAX_H ? i : 0);
        return 0;
    }
    case 38: {  // Break(reason, addr, size)：Debug 断点继续，致命断点退出
        uint64_t reason = x[0];
        LOG("svc#38 Break reason=%#llx addr=%#llx size=%#llx", (unsigned long long)reason,
            (unsigned long long)x[1], (unsigned long long)x[2]);
        if (reason & 1) return 0;   // BreakReason_Debug：仅停一下，继续
        void guest_backtrace(uint64_t);
        guest_backtrace(x[29]);     // 从门保存的客体 fp 走帧链（包装函数无栈帧）
        _exit(81);
    }
    case 39: {  // OutputDebugString(ptr, len)：打出客体自己的诊断文本
        size_t len = (size_t)x[1];
        if (len > 512) len = 512;
        char buf[513];
        memcpy(buf, (void *)(uintptr_t)x[0], len);
        buf[len] = 0;
        LOG("客体调试串: %s", buf);
        return 0;
    }
    case 40: return 0;   // ReturnFromException
    case 41: {  // GetInfo(InfoType, handle, key) → x1 = 值（包装函数存回 out 指针）
        mem_init();
        uint64_t t = x[1], v = 0;
        switch (t) {
        case 0:  v = 7; break;                      // CoreMask：3 个应用核
        case 1:  v = 0x3f; break;                   // PriorityMask
        case 2:  v = (uint64_t)g_alias; break;      // AliasRegionAddress（GetReservedRegionImpl，sdk+0x8cae0 实证）
        case 3:  v = ALIAS_CAP; break;              // AliasRegionSize
        case 4:  v = (uint64_t)g_heap; break;       // HeapRegionAddress
        case 5:  v = HEAP_CAP; break;               // HeapRegionSize
        case 6:  v = 0x100000000ull; break;         // TotalMemoryAvailable
        case 7:  v = image_bytes() + g_heap_cur; break;   // TotalMemoryUsage
        case 11: v = now_ns() ^ (uint64_t)(uintptr_t)&t; break;   // RandomEntropy（RngManager 播种）
        case 12: v = (uint64_t)g_as; break;         // AslrRegionAddress（OsResourceManager 实证）
        case 13: v = RESERVE; break;                // AslrRegionSize
        case 14: v = (uint64_t)g_stack; break;      // StackRegionAddress
        case 15: v = STACK_CAP; break;              // StackRegionSize
        case 16: v = 1; break;                      // IsVirtualAddressMemoryEnabled（InitializeIfEnabled 实证）
        default: LOG("svc#41 GetInfo type=%llu → 0", (unsigned long long)t); break;
        }
        x[1] = v;
        return 0;
    }
    case 42: case 43: return 0;   // FlushEntireDataCache / FlushDataCache
    case 44: {  // MapPhysicalMemory(addr, size)：只许在 alias 区内（d2r 配方：mprotect 提交）
        mem_init();
        uint8_t *a = (uint8_t *)(uintptr_t)x[0];
        size_t size = (size_t)x[1];
        if (a < g_alias || a + size > g_alias + ALIAS_CAP) {
            LOG("svc#44 MapPhysicalMemory 越出 alias 区：%p+%#zx", a, size);
            return 0xD401;
        }
        if (mprotect(a, size, PROT_READ | PROT_WRITE)) die("svc#44 mprotect");
        return 0;
    }
    case 45: {  // UnmapPhysicalMemory(addr, size)
        mem_init();
        uint8_t *a = (uint8_t *)(uintptr_t)x[0];
        size_t size = (size_t)x[1];
        if (a < g_alias || a + size > g_alias + ALIAS_CAP) return 0xD401;
        madvise(a, size, MADV_FREE);
        if (mprotect(a, size, PROT_NONE)) die("svc#45 mprotect");
        return 0;
    }
    case 47: x[1] = x[2] = x[3] = 0; return 0;   // GetLastThreadInfo（x1..x3 三寄存器）
    case 48: x[1] = 0x100000000ull; return 0;              // GetResourceLimitLimitValue → x1
    case 49: x[1] = image_bytes() + g_heap_cur; return 0;  // GetResourceLimitCurrentValue → x1
    case 50: return 0;   // SetThreadActivity(h, 挂起/恢复)：报成功不动作——工作线程本就睡在条件变量上
    case 51: {  // GetThreadContext3(out ThreadContext 0x328, h)：结构体写指针（包装无寄存器存回）
        memset((void *)(uintptr_t)x[0], 0, 0x328);
        return 0;
    }
    case 60: return 0;   // DumpInfo
    case 64: {  // CreateSession(→w1 服务端, →w2 客户端)
        pthread_mutex_lock(&G);
        x[1] = h_alloc(H_FAKE, NULL); x[2] = h_alloc(H_FAKE, NULL);
        pthread_mutex_unlock(&G);
        return 0;
    }
    case 69: {  // CreateEvent(→w1, →w2)：读写事件同体
        ev_t *e = calloc(1, sizeof *e);
        pthread_mutex_lock(&G);
        uint32_t h = h_alloc(H_EVENT, e);
        pthread_mutex_unlock(&G);
        x[1] = h; x[2] = h;
        return 0;
    }
    case 83: {  // CreateInterruptEvent(→w1)
        pthread_mutex_lock(&G); x[1] = h_alloc(H_FAKE, NULL); pthread_mutex_unlock(&G);
        return 0;
    }
    default:
        return 0xF001;
    }
}

int g_last_svc = -1;   // 崩溃现场用（fault.c 读取）

uint64_t gate_dispatch(uint64_t ret_addr, uint64_t *regs) {
    for (unsigned i = gate_h(ret_addr);; i = (i + 1) & ((1u << GATE_BITS) - 1)) {
        const gate_t *g = &g_gate[i];
        if (g->ret == ret_addr) {
            if (g->kind != G_SVC) {   // cntpct / cntvct：19.2 MHz，arg = 目标寄存器
                uint64_t t = now_ns() * 12 / 625;
                regs[g->arg] = t;
                return t;
            }
            g_last_svc = g->arg;
            if (g->arg >= 0 && g->arg < 256 && !g_svc_seen[g->arg]++)
                LOG("svc#%d 首次命中（x0=%#llx）", g->arg, (unsigned long long)regs[0]);
            uint64_t r = svc_impl(g->arg, regs);
            if (r == 0xF001) LOG("svc#%d 未实现 → 0xF001", g->arg);
            regs[0] = r;   // 门契约：结果写进保存区，entry.S 恢复时带回客体 x0
            return r;
        }
        if (!g->ret) die("unknown gate at %#llx", (unsigned long long)ret_addr);
    }
}

// ---------- 崩溃现场与看门狗（fault.c，独立编译单元）----------
typedef struct { char name[16]; uint8_t *base; size_t size; } mod_ref_t;
void diag_install(void);
mod_ref_t g_mod_ref[MAX_MOD];
int g_nmod_ref;

// ---------- 服务层初始化按名接管（d2r-mobile hle_sdkinit.c 配方）----------
// nninitInitializeSdkModule 调的各服务初始化在真机上连 Horizon 系统服务（IPC），
// 宿主没有服务进程：接管成空操作，服务接口用到时再逐个接管（hle_fs 等）。
// 接管函数按客体 ABI 调用（参数在 x0..），返回值 = nn::Result，必须显式回 0——
// 声明成 void 会让 w0 留下垃圾，客体 R_ABORT_UNLESS 一查非 0 就走 AbortImpl。
typedef uint32_t (*hle_fn0)(void);
static uint32_t h_noop(void) { return 0; }
static uint32_t h_excstack(uint64_t *out) {
    mem_init();
    uint8_t *es = g_stack + STACK_CAP - 0x8000;   // 栈区顶段：线程栈自底向上分配，互不冲突
    if (mprotect(es, 0x4000, PROT_READ | PROT_WRITE)) die("异常栈 mprotect");
    out[0] = (uint64_t)(es + 0x4000);   // Horizon 习惯：报向下生长的栈顶
    out[1] = 0x4000;
    LOG("init 接管：客体异常栈 ← %p+%#x", es, 0x4000);
    return 0;
}
// fs 链占位：SetAllocator 会经 IsEnabledAccessLog→GetGlobalAccessLogMode 懒连接
// fsp-srv 服务对象（svc 层空指针），按出参粒度接管；MountRom 三件套先占位走通 nnMain。
static uint32_t h_logmode(uint32_t *out) { if (out) *out = 0; return 0; }
static uint32_t h_romcache(uint64_t *out) { if (out) *out = 0x1000; return 0; }
static char g_outdir[1024];                  // 产物目录（RomFS 在 <out>/RomFS）
static void rom_mount(const char *, const char *);
static uint32_t h_mountrom(const char *name, void *buf, uint64_t sz) {
    (void)buf; (void)sz;
    const char *dir = getenv("DM_ROMFS");
    char dflt[1100];
    if (!dir) { snprintf(dflt, sizeof dflt, "%s/RomFS", g_outdir[0] ? g_outdir : "out"); dir = dflt; }
    rom_mount(name, dir);
    LOG("MountRom %s → %s（目录直读）", name, dir);
    return 0;
}
// 诊断接管：SDK 的中止/断言路径把 file/func/expr/line/Result 直接交给我们打印，
// 比只看 Break reason 高效得多（main 的内部函数无符号，栈帧标不出名）。
static uint32_t h_abortimpl(const char *file, const char *func, const char *expr, int line, const uint32_t *result, ...) {
    LOG("客体中止 AbortImpl：file=%s func=%s expr=%s line=%d Result=%#x",
        file ? file : "?", func ? func : "?", expr ? expr : "?", line, result ? *result : 0);
    void guest_backtrace(uint64_t);
    guest_backtrace((uint64_t)__builtin_frame_address(0));
    _exit(83);
}
static uint32_t h_assertfail(int type, const char *file, const char *func, const char *expr, int line) {
    LOG("客体断言 OnAssertionFailure：type=%d file=%s func=%s expr=%s line=%d", type,
        file ? file : "?", func ? func : "?", expr ? expr : "?", line);
    _exit(84);
}

// ---------- 文件系统层（d2r hle_fs.c 的目录直读方案：挂载名 → 宿主目录） ----------
// 符号面按 PQ main 的导入清单实证（14 个）：OpenFile / ReadFile×4 / GetFileSize /
// CloseFile / FlushFile / WriteFile / GetEntryType / OpenDirectory / ReadDirectory /
// CloseDirectory / Unmount。RomFS 已离线解包成目录随产物分发（out/RomFS）。
#define MAX_MNT 8
#define MAX_FH 256
#define MAX_DH 32
static struct { char name[16]; char dir[1024]; } g_mnt[MAX_MNT];
static int g_nmnt;
static int g_fh[MAX_FH];            // 宿主 fd（1 基句柄，0 = 空）
static uint64_t g_fh_pos[MAX_FH];   // 文件位置：ReadFile 传 off=-1 时从当前位置续读并推进
static struct { DIR *d; int mode; char path[1024]; } g_dh[MAX_DH];

static void rom_mount(const char *name, const char *dir) {
    if (g_nmnt >= MAX_MNT) die("挂载表满");
    strlcpy(g_mnt[g_nmnt].name, name, sizeof g_mnt[0].name);
    strlcpy(g_mnt[g_nmnt].dir, dir, sizeof g_mnt[0].dir);
    g_nmnt++;
}
// "rom:/Data/x" → 宿主路径；返回挂载下标，-1 = 无此挂载
static int host_path(const char *guest, char *out, size_t n) {
    const char *colon = strchr(guest, ':');
    if (!colon || colon[1] != '/') return -1;
    size_t mnlen = (size_t)(colon - guest);
    for (int i = 0; i < g_nmnt; i++)
        if (strlen(g_mnt[i].name) == mnlen && !strncmp(g_mnt[i].name, guest, mnlen)) {
            snprintf(out, n, "%s%s", g_mnt[i].dir, colon + 1);
            return i;
        }
    return -1;
}
#define FS_ENOENT 0x202   // nn::fs PathNotFound（模块 2）

static uint32_t h_openfile(uint64_t *out, const char *path, int mode) {
    char hp[1100];
    if (host_path(path, hp, sizeof hp) < 0) { LOG("OpenFile 未挂载：%s", path); return FS_ENOENT; }
    int hm = ((mode & 3) == 1) ? O_RDONLY : ((mode & 3) == 2) ? O_WRONLY | O_CREAT : O_RDWR | O_CREAT;
    int fd = open(hp, hm, 0644);
    if (fd < 0) { LOG("OpenFile(%s) mode=%d → errno=%d", path, mode, errno); return FS_ENOENT; }   // 只读区里缺文件按未找到回（Unity 会探测可选资源）
    int h = 1;
    while (h < MAX_FH && g_fh[h]) h++;
    if (h >= MAX_FH) { close(fd); return 0xF701; }
    g_fh[h] = fd;
    g_fh_pos[h] = 0;
    LOG("fs Open %s（mode=%d → h=%d）", path, mode, h);
    *out = (uint64_t)h;
    return 0;
}
static uint32_t h_readfile_n(uint64_t *out, uint64_t h, int64_t off, void *buf, uint64_t n) {
    if (!h || h >= MAX_FH || !g_fh[h]) return 0xF601;
    uint64_t pos;
    if (off < 0) { pos = g_fh_pos[h]; }        // -1 = 从当前位置续读（nnSdk 语义）
    else { pos = (uint64_t)off; g_fh_pos[h] = (uint64_t)off; }
    ssize_t r = pread(g_fh[h], buf, n, (off_t)pos);
    if (r < 0) { LOG("ReadFile h=%llu off=%lld n=%llu → errno=%d", (unsigned long long)h, (long long)off, (unsigned long long)n, errno); return 0xFA01; }
    g_fh_pos[h] = pos + (uint64_t)r;
    if (out) *out = (uint64_t)r;
    return 0;
}
static uint32_t h_getfilesize(int64_t *out, uint64_t h) {
    if (!h || h >= MAX_FH || !g_fh[h]) return 0xF601;
    struct stat st;
    if (fstat(g_fh[h], &st)) return 0xFA01;
    *out = st.st_size;
    return 0;
}
static uint32_t h_closefile(uint64_t h) {
    if (h && h < MAX_FH && g_fh[h]) { close(g_fh[h]); g_fh[h] = 0; }
    return 0;
}
static uint32_t h_flushfile(uint64_t h) { (void)h; return 0; }
static uint32_t h_getentrytype(int32_t *out, const char *path) {
    char hp[1100];
    if (host_path(path, hp, sizeof hp) < 0) { LOG("GetEntryType(%s) 未挂载 ← %p", path, __builtin_return_address(0)); return FS_ENOENT; }
    struct stat st;
    if (stat(hp, &st)) { LOG("GetEntryType(%s) stat 失败 errno=%d ← %p", path, errno, __builtin_return_address(0)); return FS_ENOENT; }
    *out = S_ISDIR(st.st_mode) ? 1 : 0;   // 本 SDK 的 DirectoryEntryType：1=目录 0=文件（il2cpp GetFileAttributes 映射反汇编实证；2 是非法值会触发断言）
    LOG("GetEntryType(%s) → type=%d", path, *out);
    return 0;
}
static uint32_t h_opendirectory(uint64_t *out, const char *path, int mode) {
    char hp[1100];
    if (host_path(path, hp, sizeof hp) < 0) return FS_ENOENT;
    DIR *d = opendir(hp);
    if (!d) { LOG("OpenDirectory(%s) mode=%#x → errno=%d", path, mode, errno); return FS_ENOENT; }
    int h = 1;
    while (h < MAX_DH && g_dh[h].d) h++;
    if (h >= MAX_DH) { closedir(d); return 0xF701; }
    g_dh[h] = (typeof(g_dh[0])){d, mode, {0}};
    strlcpy(g_dh[h].path, hp, sizeof g_dh[0].path);
    LOG("fs OpenDir %s（mode=%#x → h=%d）", path, mode, h);
    *out = (uint64_t)h;
    return 0;
}
// DirectoryEntry：name[0x301] type@0x304 size@0x308（步长 0x310）
static uint32_t h_readdirectory(int64_t *out, void *ents, uint64_t h, int64_t max) {
    *out = 0;
    if (!h || h >= MAX_DH || !g_dh[h].d) return 0xF601;
    int64_t cnt = 0;
    uint8_t *e = ents;
    while (cnt < max) {
        struct dirent *de = readdir(g_dh[h].d);
        if (!de) break;
        if (de->d_name[0] == '.') continue;
        int want = (de->d_type == DT_DIR) ? 1 : 0;   // 1=目录 0=文件
        if (g_dh[h].mode && !(g_dh[h].mode & want) && g_dh[h].mode != 3) continue;
        uint8_t *slot = e + (size_t)cnt * 0x310;
        memset(slot, 0, 0x310);
        strlcpy((char *)slot, de->d_name, 0x301);
        *(int32_t *)(slot + 0x304) = want;   // 1=目录 0=文件（同 GetEntryType）
        *(int64_t *)(slot + 0x308) = 0;
        struct stat st;
        if (de->d_type != DT_DIR && fstatat(dirfd(g_dh[h].d), de->d_name, &st, 0) == 0)
            *(int64_t *)(slot + 0x308) = st.st_size;
        cnt++;
    }
    *out = cnt;
    return 0;
}
static uint32_t h_closedirectory(uint64_t h) {
    if (h && h < MAX_DH && g_dh[h].d) { closedir(g_dh[h].d); g_dh[h].d = NULL; }
    return 0;
}
static uint32_t h_writefile(uint64_t h, int64_t off, const void *buf, uint64_t n, const void *opt) {
    (void)opt;
    if (!h || h >= MAX_FH || !g_fh[h]) return 0xF601;
    ssize_t r = pwrite(g_fh[h], buf, n, (off_t)off);
    return r < 0 ? 0xFA01 : 0;
}
static uint32_t h_vi_opendefault(void **out) {   // 假 Display 句柄：Unity 需要非空才能走下去
    if (out) *out = (void *)(uintptr_t)0x55490001;
    return 0;
}
static uint32_t h_vi_createlayer(void **out, void *display) {   // 假 Layer：出参必须写真值
    (void)display;
    if (out) *out = (void *)(uintptr_t)0x55490002;
    return 0;
}
static uint32_t h_vi_getnativewindow(void **out, void *layer) {   // 假 native window：给块可读的零缓冲
    (void)layer;
    static uint8_t g_fake_nw[0x1000];
    if (out) *out = g_fake_nw;
    return 0;
}
// ---------- NVN 接口层（d2r hle_nvn.c 的最小起点） ----------
// main 只导入 nvnBootstrapLoader 一个 nvn 符号——NVN 全 API 按名字经它取函数指针，
// 强制接管后 sdk 里的 NVN 驱动栈整块不执行。
// 关键语义：NVN 的 Initialize 族返回 NVNboolean（1=成功）而非 Result 0——
// 纯 0 桩会让 Unity 判定初始化失败走清理路径（对齐分配配普通 delete，真机上不执行的死代码）。
// 对象按 d2r nvn_obj.h 的最小布局就地写进游戏分配的内存（magic + 设备指针等）。
#define NVN_MAGIC(a, b, c, d) ((uint32_t)(a) | (uint32_t)(b) << 8 | (uint32_t)(c) << 16 | (uint32_t)(d) << 24)
// 调用者探针：帧链在叶子函数不可靠（x29 链与硬件 lr 曾矛盾），一律用硬件返回地址
#define NVN_CALLER __builtin_return_address(0)
static void *h_nvn_bootstrap(const char *name);
static void *h_nvn_getprocaddr(void *dev, const char *name) {
    void *fn = h_nvn_bootstrap(name);
    LOG("nvnDeviceGetProcAddress(%s) → %p", name && (uintptr_t)name > 0x10000 ? name : "?", fn);
    return fn;
}
// 设备属性表：Tegra X1 实测值（照抄 d2r，nvn_DeviceConstantsNX.h 逐项实测）
static const int g_nvn_devinfo[0x4E] = {
    [0x00] = 53, [0x01] = 311, [0x02] = 14, [0x03] = 65536, [0x04] = 256, [0x05] = 8, [0x06] = 16, [0x07] = 4, [0x08] = 16, [0x09] = 32,
    [0x0A] = 16, [0x0B] = 4, [0x0C] = 4, [0x0D] = 4, [0x0E] = 16, [0x0F] = 32, [0x10] = 32, [0x11] = 256, [0x12] = 256,
    [0x13] = 4, [0x14] = 8, [0x15] = 512, [0x16] = 256, [0x17] = 2, [0x18] = 256, [0x19] = 4096, [0x1A] = 131072,
    [0x1B] = 16, [0x1C] = 1536, [0x1D] = 1024, [0x1E] = 64, [0x1F] = 1536, [0x20] = 65535, [0x21] = 65535, [0x22] = 65535,
    [0x23] = 8, [0x24] = 1048576, [0x25] = 4096, [0x26] = 16, [0x27] = 4096, [0x28] = 1, [0x29] = 1, [0x2A] = 1,
    [0x2B] = 262144, [0x2C] = 15, [0x2D] = 2048, [0x2E] = 1, [0x2F] = 1, [0x30] = 14, [0x31] = 5, [0x32] = 1, [0x33] = 8,
    [0x34] = 8, [0x35] = 4, [0x36] = 32, [0x37] = 128, [0x38] = 32, [0x39] = 128, [0x3A] = 65536, [0x3B] = 1, [0x3C] = 4,
    [0x3D] = 16384, [0x3E] = 134217728, [0x3F] = 2048, [0x40] = 16384, [0x41] = 16384, [0x42] = 1, [0x43] = 1, [0x44] = 1,
    [0x45] = 1, [0x46] = 5, [0x47] = 1, [0x48] = 1, [0x49] = 1, [0x4A] = 1, [0x4B] = 1, [0x4C] = 1, [0x4D] = 16,
};
// —— 设备（dev_t：magic/flags @0，其余按需扩）
static uint32_t n_dev_setdefaults(void *b) { memset(b, 0, 0x20); return 0; }
static uint32_t n_dev_setflags(void *b, uint32_t f) { *(uint32_t *)b = f; return 0; }
static uint32_t n_dev_init(void *d, const void *b) {
    memset(d, 0, 0x20);
    *(uint32_t *)d = NVN_MAGIC('D', 'E', 'V', '0');
    ((uint32_t *)d)[1] = *(const uint32_t *)b;
    LOG("nvn DeviceInitialize %p flags=%#x ← %p", d, *(const uint32_t *)b, NVN_CALLER);
    return 1;   // NVNboolean：成功
}
static uint32_t n_dev_finalize(void *d) { LOG("nvn DeviceFinalize %p", d); *(uint32_t *)d = 0; return 0; }
static uint32_t n_dev_getint(const void *d, int32_t pname, int32_t *out) {
    (void)d;
    if (out) *out = (pname >= 0 && pname < (int32_t)(sizeof g_nvn_devinfo / sizeof g_nvn_devinfo[0])) ? g_nvn_devinfo[pname] : 0;
    return 0;   // void 返回
}
// —— 队列（queue_builder_t：dev@0 flags@8 cmd@16 comp@24 ctl@32 flush@40 mem@48 memsz@56）
static uint32_t n_qb_setdevice(void *b, void *d) { *(void **)b = d; return 0; }
static uint32_t n_qb_setdefaults(void *b) { memset(b, 0, 0x40); return 0; }
static uint32_t n_qb_setflags(void *b, uint32_t f) { *(uint32_t *)((uint8_t *)b + 8) = f; return 0; }
static uint32_t n_qb_setcmdsz(void *b, uint64_t n) { *(uint64_t *)((uint8_t *)b + 16) = n; return 0; }
static uint32_t n_qb_setcompsz(void *b, uint64_t n) { *(uint64_t *)((uint8_t *)b + 24) = n; return 0; }
static uint32_t n_qb_setctlsz(void *b, uint64_t n) { *(uint64_t *)((uint8_t *)b + 32) = n; return 0; }
static uint32_t n_qb_setflush(void *b, uint64_t n) { *(uint64_t *)((uint8_t *)b + 40) = n; return 0; }
static uint64_t n_qb_getmemsize(const void *b) {
    const uint8_t *p = b;
    uint64_t cmd = *(const uint64_t *)(p + 16), comp = *(const uint64_t *)(p + 24), ctl = *(const uint64_t *)(p + 32);
    return (cmd + comp + ctl + 4095) & ~(uint64_t)4095;
}
static uint32_t n_qb_setmem(void *b, void *m, uint64_t n) {
    *(void **)((uint8_t *)b + 48) = m;
    *(uint64_t *)((uint8_t *)b + 56) = n;
    return 0;
}
static uint32_t n_queue_init(void *q, const void *b) {
    memset(q, 0, 0x40);
    *(uint32_t *)q = NVN_MAGIC('Q', 'U', 'E', 'U');
    *(void **)((uint8_t *)q + 8) = *(void *const *)b;   // dev
    LOG("nvn QueueInitialize %p dev=%p ← %p", q, *(void *const *)b, NVN_CALLER);
    return 1;
}
static uint32_t n_queue_finalize(void *q) { LOG("nvn QueueFinalize %p", q); *(uint32_t *)q = 0; return 0; }
static uint32_t n_queue_geterror(void *q, void *info) { (void)q; if (info) memset(info, 0, 0x18); return 0; }
static uint32_t n_queue_flush(void *q) { (void)q; return 0; }
static uint32_t n_queue_finish(void *q) { (void)q; return 0; }
static uint32_t n_queue_totalmem(void *q) { (void)q; return 0; }   // QueueGetTotal*MemoryUsed
static uint32_t n_queue_resetcounts(void *q) { (void)q; return 0; }
// —— 内存池（builder 布局自定：dev@0 flags@8 mem@16 size@24；对象：magic@0 flags@8 mem@16 size@24）
static uint32_t n_pb_setdefaults(void *b) { memset(b, 0, 0x20); return 0; }
static uint32_t n_pb_setdevice(void *b, void *d) { *(void **)b = d; return 0; }
static uint32_t n_pb_setflags(void *b, uint32_t f) { *(uint32_t *)((uint8_t *)b + 8) = f; return 0; }
static uint32_t n_pb_setstorage(void *b, void *mem, uint64_t size) {
    *(void **)((uint8_t *)b + 16) = mem;
    *(uint64_t *)((uint8_t *)b + 24) = size;
    return 0;
}
static uint32_t n_pb_getflags(const void *b) { return *(const uint32_t *)((const uint8_t *)b + 8); }
static void *n_pb_getmemory(const void *b) { return *(void *const *)((const uint8_t *)b + 16); }
static uint64_t n_pb_getsize(const void *b) { return *(const uint64_t *)((const uint8_t *)b + 24); }
static uint32_t n_pool_init2(void *p, const void *b) {
    *(uint32_t *)p = NVN_MAGIC('P', 'O', 'O', 'L');
    *(uint32_t *)((uint8_t *)p + 8) = *(const uint32_t *)((const uint8_t *)b + 8);
    *(void **)((uint8_t *)p + 16) = *(void *const *)((const uint8_t *)b + 16);
    *(uint64_t *)((uint8_t *)p + 24) = *(const uint64_t *)((const uint8_t *)b + 24);
    LOG("nvn MemoryPoolInitialize %p mem=%p size=%#llx ← %p", p,
        *(void *const *)((const uint8_t *)b + 16), (unsigned long long)*(const uint64_t *)((const uint8_t *)b + 24), NVN_CALLER);
    return 1;
}
static uint32_t n_pool_finalize(void *p) { *(uint32_t *)p = 0; return 0; }
static void *n_pool_map(void *p) { return *(void **)((uint8_t *)p + 16); }   // GPU 地址 = CPU 地址（d2r 模型）
static uint64_t n_pool_getsize(void *p) { return *(uint64_t *)((uint8_t *)p + 24); }
static uint32_t n_pool_getflags(void *p) { return *(uint32_t *)((uint8_t *)p + 8); }
static void *n_pool_bufaddr(void *p) { return *(void **)((uint8_t *)p + 16); }
static uint32_t n_pool_nop2(void *a, uint64_t b) { (void)a; (void)b; return 0; }   // Flush/InvalidateMappedRange
static uint32_t n_pool_label(void *a, const char *s) { (void)a; (void)s; return 0; }
// —— 窗口（builder：dev@0 nw@8 interval@16 texs@24 n@32；对象：magic@0 dev@8 interval@16 nw@24）
static uint32_t n_wb_setdefaults(void *b) { memset(b, 0, 0x40); return 0; }
static uint32_t n_wb_setdevice(void *b, void *d) { *(void **)b = d; return 0; }
static uint32_t n_wb_setnw(void *b, void *nw) { *(void **)((uint8_t *)b + 8) = nw; return 0; }
static uint32_t n_wb_setinterval(void *b, uint32_t i) { *(uint32_t *)((uint8_t *)b + 16) = i; return 0; }
static uint32_t n_wb_settextures(void *b, void *const *texs, uint32_t n) {
    *(void **)((uint8_t *)b + 24) = (void *)texs;
    *(uint32_t *)((uint8_t *)b + 32) = n;
    return 0;
}
static void *n_wb_getnw(const void *b) { return *(void *const *)((const uint8_t *)b + 8); }
static uint32_t n_wb_getinterval(const void *b) { return *(const uint32_t *)((const uint8_t *)b + 16); }
static uint32_t n_win_init2(void *w, const void *b) {
    memset(w, 0, 0x40);
    *(uint32_t *)w = NVN_MAGIC('W', 'I', 'N', '0');
    *(void **)((uint8_t *)w + 8) = *(void *const *)b;
    *(uint32_t *)((uint8_t *)w + 16) = *(const uint32_t *)((const uint8_t *)b + 16);
    *(void **)((uint8_t *)w + 24) = *(void *const *)((const uint8_t *)b + 8);
    LOG("nvn WindowInitialize %p dev=%p nw=%p ← %p", w, *(void *const *)b, *(void *const *)((const uint8_t *)b + 8), NVN_CALLER);
    return 1;
}
static uint32_t n_win_finalize(void *w) { *(uint32_t *)w = 0; return 0; }
static void *n_win_getnw(void *w) { return *(void **)((uint8_t *)w + 24); }
static uint32_t n_win_interval_get(void *w) { return *(uint32_t *)((uint8_t *)w + 16); }
static uint32_t n_win_interval_set(void *w, uint32_t i) { *(uint32_t *)((uint8_t *)w + 16) = i; return 0; }
static uint32_t n_win_crop(void *w, int32_t l, int32_t t, int32_t r, int32_t b2) { (void)w; (void)l; (void)t; (void)r; (void)b2; return 0; }
static uint32_t n_win_acquire(void *w, void **tex, void *sema) { (void)w; (void)sema; if (tex) *tex = NULL; return 0; }
static uint32_t n_win_label(void *w, const char *s) { (void)w; (void)s; return 0; }
// —— 同步等待：立即可通过（引导期没有真 GPU 时序）
static uint32_t n_sync_wait(void *s, int64_t timeout) { (void)s; (void)timeout; return 1; }
static uint32_t n_sync_label(void *s, const char *n) { (void)s; (void)n; return 0; }
static uint32_t n_sync_finalize(void *s) { *(uint32_t *)s = 0; return 0; }
// —— 命令缓冲内存管理（对象：magic@0 dev@8 memcb@0x10 cbdata@0x18）
static uint32_t n_cb_setcb(void *c, void *cb) { *(void **)((uint8_t *)c + 0x10) = cb; return 0; }
static uint32_t n_cb_setcbdata(void *c, void *d) { *(void **)((uint8_t *)c + 0x18) = d; return 0; }
static void *n_cb_getcb(void *c) { return *(void **)((uint8_t *)c + 0x10); }
static void *n_cb_getcbdata(void *c) { return *(void **)((uint8_t *)c + 0x18); }
static uint64_t n_cb_memfree(void *c) { (void)c; return 0x100000; }   // Command/Control Memory Free/Size：给足
static uint64_t n_cb_memused(void *c) { (void)c; return 0; }
static uint32_t n_cb_addcmd(void *c, void *m, uint64_t n) { (void)c; (void)m; (void)n; return 0; }
static uint32_t n_cb_addctl(void *c, void *m, uint64_t n) { (void)c; (void)m; (void)n; return 0; }
static uint32_t n_cb_setpool(void *c, void *pool, int64_t off) { (void)c; (void)pool; (void)off; return 0; }   // SetTexturePool/SetSamplerPool/SetShaderScratchMemory
static uint32_t n_cb_fence(void *c, void *s, int f) { (void)c; (void)s; (void)f; return 0; }   // FenceSync/WaitSync
// —— 贴图/采样器/缓冲描述符池（对象：magic@0 pool@8 off@16 count@24）
static uint32_t n_tpool_init(void *tp, void *pool, int64_t off, int32_t count) {
    *(uint32_t *)tp = NVN_MAGIC('T', 'P', 'O', 'L');
    *(void **)((uint8_t *)tp + 8) = pool;
    *(uint64_t *)((uint8_t *)tp + 16) = (uint64_t)off;
    *(int32_t *)((uint8_t *)tp + 24) = count;
    LOG("nvn TexturePool/SamplerPoolInitialize %p pool=%p off=%#llx n=%d ← %p", tp, pool, (unsigned long long)off, count, NVN_CALLER);
    return 1;
}
static uint32_t n_tpool_fin(void *tp) { *(uint32_t *)tp = 0; return 0; }
static void *n_tpool_getpool(void *tp) { return *(void **)((uint8_t *)tp + 8); }
static uint64_t n_tpool_getoff(void *tp) { return *(uint64_t *)((uint8_t *)tp + 16); }
static uint32_t n_tpool_getsize(void *tp) { return *(int32_t *)((uint8_t *)tp + 24); }
static uint32_t n_tpool_register(void *tp, void *a, void *b) { (void)tp; (void)a; (void)b; return 0; }
static uint32_t n_tpool_label(void *tp, const char *s) { (void)tp; (void)s; return 0; }
// —— 缓冲（builder：dev@0 size@0x10 pool@0x18 off@0x20；对象：magic@0 pool@8 off@0x10 size@0x18）
// Map = 内存池的 mem + 偏移（GPU 地址 = CPU 地址模型）。对象只写字段不清块（cmdbuf 教训）
static uint32_t n_bb_setdefaults(void *b) { memset(b, 0, 0x28); return 0; }
static uint32_t n_bb_setdevice(void *b, void *d) { *(void **)b = d; return 0; }
static uint32_t n_bb_setstorage(void *b, void *pool, int64_t off, uint64_t size) {
    *(uint64_t *)((uint8_t *)b + 0x10) = size;
    *(void **)((uint8_t *)b + 0x18) = pool;
    *(uint64_t *)((uint8_t *)b + 0x20) = (uint64_t)off;
    return 0;
}
static uint64_t n_bb_getsize(const void *b) { return *(const uint64_t *)((const uint8_t *)b + 0x10); }
static void *n_bb_getpool(const void *b) { return *(void *const *)((const uint8_t *)b + 0x18); }
static uint64_t n_bb_getoff(const void *b) { return *(const uint64_t *)((const uint8_t *)b + 0x20); }
static uint32_t n_buf_init(void *buf, const void *b) {
    *(uint32_t *)buf = NVN_MAGIC('B', 'U', 'F', '0');
    *(void **)((uint8_t *)buf + 8) = n_bb_getpool(b);
    *(uint64_t *)((uint8_t *)buf + 0x10) = n_bb_getoff(b);
    *(uint64_t *)((uint8_t *)buf + 0x18) = n_bb_getsize(b);
    LOG("nvn BufferInitialize %p pool=%p off=%#llx size=%#llx ← %p", buf, n_bb_getpool(b),
        (unsigned long long)n_bb_getoff(b), (unsigned long long)n_bb_getsize(b), NVN_CALLER);
    return 1;
}
static void *n_buf_map(void *buf) {
    void *pool = *(void **)((uint8_t *)buf + 8);
    void *base = pool ? *(void **)((uint8_t *)pool + 16) : NULL;   // MemoryPool 的 mem 字段
    return base ? (uint8_t *)base + *(uint64_t *)((uint8_t *)buf + 0x10) : NULL;
}
static void *n_buf_getpool(void *buf) { return *(void **)((uint8_t *)buf + 8); }
static uint64_t n_buf_getoff(void *buf) { return *(uint64_t *)((uint8_t *)buf + 0x10); }
static uint32_t n_buf_fin(void *buf) { *(uint32_t *)buf = 0; return 0; }
static uint32_t n_buf_range3(void *a, uint64_t b, uint64_t c) { (void)a; (void)b; (void)c; return 0; }   // Flush/InvalidateMappedRange
// —— 同步 / 命令缓冲初始化（对象语义见上方注释）
static uint32_t n_sync_init(void *s, void *dev, uint32_t flags) {
    memset(s, 0, 0x20); *(uint32_t *)s = NVN_MAGIC('S', 'Y', 'N', 'C'); (void)dev; (void)flags;
    static int n_logged;
    if (n_logged++ < 3) LOG("nvn SyncInitialize %p flags=%#x ← %p（前 3 个）", s, flags, NVN_CALLER);
    return 1;
}
// 注意：不 memset 整对象——Unity 的命令缓冲对象（实证 0xe0 字节）同时携带其他字段
// （+0xb0=同步池包装、+0xc0=内存池），清 0x100 会抹掉它们并溢出堆 32 字节
static uint32_t n_cb_init(void *c, void *dev) { *(uint32_t *)c = NVN_MAGIC('C', 'M', 'D', 'B'); *(void **)((uint8_t *)c + 8) = dev; LOG("nvn CommandBufferInitialize %p dev=%p ← %p", c, dev, NVN_CALLER); return 1; }
static void *h_nvn_bootstrap(const char *name) {
    if (!name || !*name) return NULL;
    static const struct { const char *nm; void *fn; } known[] = {
        {"nvnDeviceGetProcAddress", (void *)h_nvn_getprocaddr},
        {"nvnDeviceBuilderSetDefaults", (void *)n_dev_setdefaults},
        {"nvnDeviceBuilderSetFlags", (void *)n_dev_setflags},
        {"nvnDeviceInitialize", (void *)n_dev_init},
        {"nvnDeviceFinalize", (void *)n_dev_finalize},
        {"nvnDeviceGetInteger", (void *)n_dev_getint},
        {"nvnQueueBuilderSetDevice", (void *)n_qb_setdevice},
        {"nvnQueueBuilderSetDefaults", (void *)n_qb_setdefaults},
        {"nvnQueueBuilderSetFlags", (void *)n_qb_setflags},
        {"nvnQueueBuilderSetCommandMemorySize", (void *)n_qb_setcmdsz},
        {"nvnQueueBuilderSetComputeMemorySize", (void *)n_qb_setcompsz},
        {"nvnQueueBuilderSetControlMemorySize", (void *)n_qb_setctlsz},
        {"nvnQueueBuilderSetCommandFlushThreshold", (void *)n_qb_setflush},
        {"nvnQueueBuilderGetQueueMemorySize", (void *)n_qb_getmemsize},
        {"nvnQueueBuilderSetQueueMemory", (void *)n_qb_setmem},
        {"nvnQueueInitialize", (void *)n_queue_init},
        {"nvnQueueFinalize", (void *)n_queue_finalize},
        {"nvnQueueGetError", (void *)n_queue_geterror},
        {"nvnQueueFlush", (void *)n_queue_flush},
        {"nvnQueueFinish", (void *)n_queue_finish},
        {"nvnQueueGetTotalCommandMemoryUsed", (void *)n_queue_totalmem},
        {"nvnQueueGetTotalComputeMemoryUsed", (void *)n_queue_totalmem},
        {"nvnQueueGetTotalControlMemoryUsed", (void *)n_queue_totalmem},
        {"nvnQueueResetMemoryUsageCounts", (void *)n_queue_resetcounts},
        // 内存池
        {"nvnMemoryPoolBuilderSetDefaults", (void *)n_pb_setdefaults},
        {"nvnMemoryPoolBuilderSetDevice", (void *)n_pb_setdevice},
        {"nvnMemoryPoolBuilderSetFlags", (void *)n_pb_setflags},
        {"nvnMemoryPoolBuilderSetStorage", (void *)n_pb_setstorage},
        {"nvnMemoryPoolBuilderGetFlags", (void *)n_pb_getflags},
        {"nvnMemoryPoolBuilderGetMemory", (void *)n_pb_getmemory},
        {"nvnMemoryPoolBuilderGetSize", (void *)n_pb_getsize},
        {"nvnMemoryPoolInitialize", (void *)n_pool_init2},
        {"nvnMemoryPoolFinalize", (void *)n_pool_finalize},
        {"nvnMemoryPoolMap", (void *)n_pool_map},
        {"nvnMemoryPoolGetSize", (void *)n_pool_getsize},
        {"nvnMemoryPoolGetFlags", (void *)n_pool_getflags},
        {"nvnMemoryPoolGetBufferAddress", (void *)n_pool_bufaddr},
        {"nvnMemoryPoolFlushMappedRange", (void *)n_pool_nop2},
        {"nvnMemoryPoolInvalidateMappedRange", (void *)n_pool_nop2},
        {"nvnMemoryPoolSetDebugLabel", (void *)n_pool_label},
        // 窗口
        {"nvnWindowBuilderSetDefaults", (void *)n_wb_setdefaults},
        {"nvnWindowBuilderSetDevice", (void *)n_wb_setdevice},
        {"nvnWindowBuilderSetNativeWindow", (void *)n_wb_setnw},
        {"nvnWindowBuilderSetPresentInterval", (void *)n_wb_setinterval},
        {"nvnWindowBuilderSetTextures", (void *)n_wb_settextures},
        {"nvnWindowBuilderGetNativeWindow", (void *)n_wb_getnw},
        {"nvnWindowBuilderGetPresentInterval", (void *)n_wb_getinterval},
        {"nvnWindowInitialize", (void *)n_win_init2},
        {"nvnWindowFinalize", (void *)n_win_finalize},
        {"nvnWindowGetNativeWindow", (void *)n_win_getnw},
        {"nvnWindowGetPresentInterval", (void *)n_win_interval_get},
        {"nvnWindowSetPresentInterval", (void *)n_win_interval_set},
        {"nvnWindowSetCrop", (void *)n_win_crop},
        {"nvnWindowGetCrop", (void *)n_win_crop},
        {"nvnWindowAcquireTexture", (void *)n_win_acquire},
        {"nvnWindowSetDebugLabel", (void *)n_win_label},
        // 同步
        {"nvnSyncInitialize", (void *)n_sync_init},
        {"nvnSyncFinalize", (void *)n_sync_finalize},
        {"nvnSyncWait", (void *)n_sync_wait},
        {"nvnSyncSetDebugLabel", (void *)n_sync_label},
        // 命令缓冲
        {"nvnCommandBufferInitialize", (void *)n_cb_init},
        {"nvnCommandBufferSetMemoryCallback", (void *)n_cb_setcb},
        {"nvnCommandBufferSetMemoryCallbackData", (void *)n_cb_setcbdata},
        {"nvnCommandBufferGetMemoryCallback", (void *)n_cb_getcb},
        {"nvnCommandBufferGetMemoryCallbackData", (void *)n_cb_getcbdata},
        {"nvnCommandBufferAddCommandMemory", (void *)n_cb_addcmd},
        {"nvnCommandBufferAddControlMemory", (void *)n_cb_addctl},
        {"nvnCommandBufferGetCommandMemoryFree", (void *)n_cb_memfree},
        {"nvnCommandBufferGetCommandMemorySize", (void *)n_cb_memfree},
        {"nvnCommandBufferGetCommandMemoryUsed", (void *)n_cb_memused},
        {"nvnCommandBufferGetControlMemoryFree", (void *)n_cb_memfree},
        {"nvnCommandBufferGetControlMemorySize", (void *)n_cb_memfree},
        {"nvnCommandBufferGetControlMemoryUsed", (void *)n_cb_memused},
        {"nvnCommandBufferSetTexturePool", (void *)n_cb_setpool},
        {"nvnCommandBufferSetSamplerPool", (void *)n_cb_setpool},
        {"nvnCommandBufferSetShaderScratchMemory", (void *)n_cb_setpool},
        {"nvnCommandBufferFenceSync", (void *)n_cb_fence},
        {"nvnCommandBufferWaitSync", (void *)n_cb_fence},
        // 描述符池
        {"nvnTexturePoolInitialize", (void *)n_tpool_init},
        {"nvnSamplerPoolInitialize", (void *)n_tpool_init},
        {"nvnTexturePoolFinalize", (void *)n_tpool_fin},
        {"nvnSamplerPoolFinalize", (void *)n_tpool_fin},
        {"nvnTexturePoolGetMemoryPool", (void *)n_tpool_getpool},
        {"nvnSamplerPoolGetMemoryPool", (void *)n_tpool_getpool},
        {"nvnTexturePoolGetMemoryOffset", (void *)n_tpool_getoff},
        {"nvnSamplerPoolGetMemoryOffset", (void *)n_tpool_getoff},
        {"nvnTexturePoolGetSize", (void *)n_tpool_getsize},
        {"nvnSamplerPoolGetSize", (void *)n_tpool_getsize},
        {"nvnTexturePoolRegisterTexture", (void *)n_tpool_register},
        {"nvnTexturePoolRegisterImage", (void *)n_tpool_register},
        {"nvnSamplerPoolRegisterSampler", (void *)n_tpool_register},
        {"nvnSamplerPoolRegisterSamplerBuilder", (void *)n_tpool_register},
        {"nvnTexturePoolSetDebugLabel", (void *)n_tpool_label},
        {"nvnSamplerPoolSetDebugLabel", (void *)n_tpool_label},
        // 队列-同步
        {"nvnQueueFenceSync", (void *)n_cb_fence},
        {"nvnQueueWaitSync", (void *)n_cb_fence},
        // 缓冲
        {"nvnBufferBuilderSetDefaults", (void *)n_bb_setdefaults},
        {"nvnBufferBuilderSetDevice", (void *)n_bb_setdevice},
        {"nvnBufferBuilderSetStorage", (void *)n_bb_setstorage},
        {"nvnBufferBuilderGetSize", (void *)n_bb_getsize},
        {"nvnBufferBuilderGetMemoryPool", (void *)n_bb_getpool},
        {"nvnBufferBuilderGetMemoryOffset", (void *)n_bb_getoff},
        {"nvnBufferInitialize", (void *)n_buf_init},
        {"nvnBufferFinalize", (void *)n_buf_fin},
        {"nvnBufferMap", (void *)n_buf_map},
        {"nvnBufferGetMemoryPool", (void *)n_buf_getpool},
        {"nvnBufferGetMemoryOffset", (void *)n_buf_getoff},
        {"nvnBufferFlushMappedRange", (void *)n_buf_range3},
        {"nvnBufferInvalidateMappedRange", (void *)n_buf_range3},
    };
    for (unsigned i = 0; i < sizeof known / sizeof known[0]; i++)
        if (!strcmp(known[i].nm, name)) return known[i].fn;
    for (unsigned k = 0; k < g_nstub; k++)
        if (g_stub_name[k] && !strcmp(g_stub_name[k], name)) return &unimpl_stubs[k];
    if (g_nstub >= MAX_STUB) die("nvn 桩表满");
    g_stub_name[g_nstub] = strdup(name);
    return &unimpl_stubs[g_nstub++];
}
// oe 查询（服务对象因 Initialize 接管为空，直查会空表解引用）：掌机模式 + 正常性能 + 已聚焦
static uint32_t h_oe_handheld(void) { return 1; }   // GetOperationMode：1=Handheld（触屏取向）
static uint32_t h_oe_normal(void) { return 0; }     // GetPerformanceMode：0=Normal
static uint32_t h_oe_focused(void) { return 1; }    // GetCurrentFocusState：1=InFocus
static uint32_t h_oe_lang(uint8_t *out) { if (out) *out = 1; return 0; }   // GetDesiredLanguage：1=English（语言码表后续接宿主）
static uint32_t h_oe_trypop(uint32_t *out) {
    if (out) *out = 0;   // 无消息：id=0 不命中 0x10/0x1f/0x1e 任何处理器（此前不写出参，残留栈值可能被当 ExitRequested）
    return 0;
}
static uint32_t h_guest_exit(int code) {
    LOG("客体 exit(%d) ← %p ← %p", code, NVN_CALLER, __builtin_return_address(1));
    _exit(90);
}
static uint32_t h_hid_zero8(void *state) { if (state) { *(uint64_t *)state = 0; ((uint32_t *)state)[2] = 0; } return 0; }   // 采样号/调度清零
static uint32_t h_hid_touchcount(int32_t *count, void *states, int32_t max) {
    (void)states; (void)max;
    if (count) *count = 0;   // 无触摸点
    return 0;
}
// 客体 stdio 直通宿主 stderr（d2r libc 直通表思路）——Unity 引擎日志因此现形，
// 此前 musl printf 的输出被 nn-musl 的 write 垫片静默丢弃。
static uint64_t h_g_printf(const char *fmt, ...) { va_list ap; va_start(ap, fmt); int r = vfprintf(stderr, fmt, ap); va_end(ap); return r; }
static uint64_t h_g_fprintf(void *f, const char *fmt, ...) { (void)f; va_list ap; va_start(ap, fmt); int r = vfprintf(stderr, fmt, ap); va_end(ap); return r; }
static uint64_t h_g_vfprintf(void *f, const char *fmt, va_list ap) { (void)f; return (uint64_t)vfprintf(stderr, fmt, ap); }
static uint64_t h_g_fwrite(const void *p, uint64_t sz, uint64_t n, void *f) { (void)f; return (uint64_t)fwrite(p, (size_t)sz, (size_t)n, stderr); }
static uint64_t h_g_puts(const char *s) { fputs(s ? s : "(null)", stderr); fputc('\n', stderr); return 0; }
static uint64_t h_g_fflush(void *f) { (void)f; fflush(stderr); return 0; }
// 客体 FILE 族直通宿主（带 rom:/ 路径映射）——il2cpp os 层的文件读写走客体内存
// musl 的 fopen，其底层 write/read 在宿主必然失败；全部接到宿主后 FILE* 语义自洽。
static uint64_t h_g_fopen(const char *path, const char *mode) {
    char hp[1100];
    if (path && host_path(path, hp, sizeof hp) >= 0) {
        FILE *f = fopen(hp, mode);
        LOG("fopen(%s,%s) → %p", path, mode, f);
        return (uint64_t)f;
    }
    if (path) LOG("fopen(%s) 未挂载 → NULL", path);
    return 0;
}
static uint64_t h_g_fread(void *p, uint64_t sz, uint64_t n, void *f) { return (uint64_t)fread(p, (size_t)sz, (size_t)n, (FILE *)f); }
static uint64_t h_g_fclose(void *f) { return (uint64_t)fclose((FILE *)f); }
static uint64_t h_g_fseek(void *f, int64_t off, int whence) { return (uint64_t)fseeko((FILE *)f, (off_t)off, whence); }
static uint64_t h_g_ftell(void *f) { return (uint64_t)ftello((FILE *)f); }
static uint64_t h_g_feof(void *f) { return (uint64_t)feof((FILE *)f); }
static uint64_t h_g_ferror(void *f) { return (uint64_t)ferror((FILE *)f); }
typedef struct { const char *name; hle_fn0 fn; } hle_ent;
static hle_fn0 force_lookup(const char *name) {
    // nnMain 开局序（main+0xbfdcdc 反汇编实证）：time::Initialize(+0x74) 连 sm IPC、
    // vi::Initialize(+0x108)、nv::InitializeGraphics(+0xe4, 64MB)；其余为
    // nninitInitializeSdkModule 的服务初始化（d2r hle_sdkinit.c 同款名单）。
    static const hle_ent tab[] = {
        {"nndiagStartup", h_noop},
        {"_ZN2nn2oe10InitializeEv", h_noop},
        {"_ZN2nn3aoc10InitializeEv", h_noop},
        {"_ZN2nn4pctl10InitializeEv", h_noop},
        {"_ZN2nn3err26InitializeContextWriterApiEv", h_noop},
        {"_ZN2nn2fs24InitializeForApplicationEv", h_noop},
        {"_ZN2nn4diag34InitializeApplicationAbortObserverEv", h_noop},
        {"nnosGetDefaultUserExceptionStackForApplication", (hle_fn0)h_excstack},
        {"_ZN2nn2sm10InitializeEv", h_noop},      // nnMain+0x74 起的服务链：无服务进程，接口级接管
        {"_ZN2nn4time10InitializeEv", h_noop},
        {"_ZN2nn2vi10InitializeEv", h_noop},
        {"_ZN2nv18InitializeGraphicsEPvm", h_noop},
        {"_ZN2nn4nifm10InitializeEv", h_noop},   // 网络接口服务：Unity 启动必查；连接类接口后续按需接管
        {"_ZN2nn6socket10InitializeEPvmmi", h_noop},   // BSD 套接字层（在线功能；离线跑通为要）
        {"_ZN2nn2vi18OpenDefaultDisplayEPPNS0_7DisplayE", (hle_fn0)h_vi_opendefault},   // 假 Display；vi 其余接口走命名桩
        {"_ZN2nn2vi11CreateLayerEPPNS0_5LayerEPNS0_7DisplayE", (hle_fn0)h_vi_createlayer},
        {"_ZN2nn2vi15GetNativeWindowEPPvPNS0_5LayerE", (hle_fn0)h_vi_getnativewindow},
        {"nvnBootstrapLoader", (hle_fn0)h_nvn_bootstrap},   // NVN 全接口经此按名取函数指针；记名桩收集调用面
        {"exit", (hle_fn0)h_guest_exit},          // 诊断：客体主动 exit 的调用者
        {"_exit", (hle_fn0)h_guest_exit},
        {"quick_exit", (hle_fn0)h_guest_exit},
        // 客体 stdio → 宿主 stderr（引擎日志现形）
        {"printf", (hle_fn0)h_g_printf},
        {"fprintf", (hle_fn0)h_g_fprintf},
        {"vfprintf", (hle_fn0)h_g_vfprintf},
        {"fwrite", (hle_fn0)h_g_fwrite},
        {"puts", (hle_fn0)h_g_puts},
        {"fflush", (hle_fn0)h_g_fflush},
        {"fopen", (hle_fn0)h_g_fopen},
        {"fread", (hle_fn0)h_g_fread},
        {"fclose", (hle_fn0)h_g_fclose},
        {"fseek", (hle_fn0)h_g_fseek},
        {"ftell", (hle_fn0)h_g_ftell},
        {"feof", (hle_fn0)h_g_feof},
        {"ferror", (hle_fn0)h_g_ferror},
        // hid 查询（Unity 已调用）：写出参为零态，避免读到残留栈值
        {"_ZN2nn3hid15GetNpadStyleSetERKj", h_oe_normal},                     // 无手柄样式
        {"_ZN2nn3hid16GetDebugPadStateEPNS0_13DebugPadStateE", (hle_fn0)h_hid_zero8},
        {"_ZN2nn3hid20GetTouchScreenStatesILm16EEEiPNS0_16TouchScreenStateIXT_EEEi", (hle_fn0)h_hid_touchcount},
        {"_ZN2nn2fs22GetGlobalAccessLogModeEPj", (hle_fn0)h_logmode},
        {"_ZN2nn2fs22QueryMountRomCacheSizeEPm", (hle_fn0)h_romcache},
        {"_ZN2nn2fs8MountRomEPKcPvm", (hle_fn0)h_mountrom},
        // oe 服务对象因 Initialize 接管为空，三个 notification setter 会空表解引用（sdk+0x14f064 实证）
        {"_ZN2nn2oe28SetResumeNotificationEnabledEb", h_noop},
        {"_ZN2nn2oe44SetPerformanceModeChangedNotificationEnabledEb", h_noop},
        {"_ZN2nn2oe42SetOperationModeChangedNotificationEnabledEb", h_noop},
        {"_ZN2nn2oe25TryPopNotificationMessageEPj", (hle_fn0)h_oe_trypop},   // 写 *out=0（无消息）+ 返回 0：nnMain+0x78c tbz w0,#0 → 跳过读消息
        {"_ZN2nn2oe16GetOperationModeEv", (hle_fn0)h_oe_handheld},
        {"_ZN2nn2oe18GetPerformanceModeEv", (hle_fn0)h_oe_normal},
        {"_ZN2nn2oe20GetCurrentFocusStateEv", (hle_fn0)h_oe_focused},
        {"_ZN2nn2oe18GetDesiredLanguageEv", (hle_fn0)h_oe_lang},
        {"_ZN2nn4diag6detail9AbortImplEPKcS3_S3_iPKNS_6ResultEPKNS_2os17UserExceptionInfoES3_z", (hle_fn0)h_abortimpl},
        {"_ZN2nn4diag6detail9AbortImplEPKcS3_S3_iS3_z", (hle_fn0)h_abortimpl},
        {"_ZN2nn4diag6detail18OnAssertionFailureENS0_13AssertionTypeEPKcS4_S4_i", (hle_fn0)h_assertfail},
        // fs 读面（main 导入清单实证）→ 宿主 open/pread/opendir/stat
        {"_ZN2nn2fs8OpenFileEPNS0_10FileHandleEPKci", (hle_fn0)h_openfile},
        {"_ZN2nn2fs8ReadFileEPmNS0_10FileHandleElPvm", (hle_fn0)h_readfile_n},
        {"_ZN2nn2fs8ReadFileEPmNS0_10FileHandleElPvmRKNS0_9ReadOptionE", (hle_fn0)h_readfile_n},
        {"_ZN2nn2fs8ReadFileENS0_10FileHandleElPvm", (hle_fn0)h_readfile_n},
        {"_ZN2nn2fs8ReadFileENS0_10FileHandleElPvmRKNS0_9ReadOptionE", (hle_fn0)h_readfile_n},
        {"_ZN2nn2fs11GetFileSizeEPlNS0_10FileHandleE", (hle_fn0)h_getfilesize},
        {"_ZN2nn2fs9CloseFileENS0_10FileHandleE", (hle_fn0)h_closefile},
        {"_ZN2nn2fs9FlushFileENS0_10FileHandleE", (hle_fn0)h_flushfile},
        {"_ZN2nn2fs9WriteFileENS0_10FileHandleElPKvmRKNS0_11WriteOptionE", (hle_fn0)h_writefile},
        {"_ZN2nn2fs12GetEntryTypeEPNS0_18DirectoryEntryTypeEPKc", (hle_fn0)h_getentrytype},
        {"_ZN2nn2fs13OpenDirectoryEPNS0_15DirectoryHandleEPKci", (hle_fn0)h_opendirectory},
        {"_ZN2nn2fs13ReadDirectoryEPlPNS0_14DirectoryEntryENS0_15DirectoryHandleEl", (hle_fn0)h_readdirectory},
        {"_ZN2nn2fs14CloseDirectoryENS0_15DirectoryHandleE", (hle_fn0)h_closedirectory},
        {"_ZN2nn2fs7UnmountEPKc", h_noop},
    };
    for (unsigned i = 0; i < sizeof tab / sizeof tab[0]; i++)
        if (!strcmp(tab[i].name, name)) return tab[i].fn;
    return NULL;
}

// ---------- 装载 ----------
static void read_layout(module_t *m, const char *dir) {
    char path[1024]; snprintf(path, sizeof path, "%s/%s.fixups.tsv", dir, m->name);
    FILE *f = fopen(path, "r");
    if (!f) die("open %s", path);
    static const char *kn[4] = {"K18", "KTLS", "KTLR", "KGATE"};
    char line[256], key[32]; unsigned long v;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "# %31s %lx", key, &v) != 2) continue;
        if (!strcmp(key, "PATCH_OFF")) m->patch_off = v;
        else if (!strcmp(key, "KEY_PAGE_OFF")) m->key_page_off = v;
        else if (!strcmp(key, "KEY_PAGE_SIZE")) m->key_page_size = v;
        else if (!strcmp(key, "TEXT_END")) m->text_end = v;
        else for (int k = 0; k < 4; k++) {
            char want[32]; snprintf(want, sizeof want, "KEY_%s_IDX", kn[k]);
            if (!strcmp(key, want)) { m->key_idx[k] = (unsigned)v; break; }
        }
    }
    fclose(f);
    if (!m->patch_off || m->key_page_off % PAGE || m->key_page_size != PAGE) die("%s: 产物布局不符", m->name);
}

static void create_keys(void) {
    if (pthread_key_create(&g_key18, NULL) || pthread_key_create(&g_keytls, NULL) ||
        pthread_key_create(&g_keytlr, NULL) || pthread_key_create(&g_keygate, NULL)) die("创建线程槽键失败");
    LOG("键号 K18=%lu KTLS=%lu KTLR=%lu KGATE=%lu", (unsigned long)g_key18, (unsigned long)g_keytls, (unsigned long)g_keytlr, (unsigned long)g_keygate);
}

static void install_key_page(module_t *m) {
    uint64_t *page = (uint64_t *)(m->base + m->key_page_off);
    memset(page, 0, m->key_page_size);
    const pthread_key_t kv[4] = {g_key18, g_keytls, g_keytlr, g_keygate};
    for (int k = 0; k < 4; k++) page[m->key_idx[k]] = (uint64_t)kv[k] * 8;
    if (mprotect(m->base + m->key_page_off, m->key_page_size, PROT_READ)) die("%s 键页 mprotect", m->name);
}

// TSD 布局自检：pthread 键落在 tpidrro_el0 指向的直接 TSD 区（d2r-mobile 同款机制）
static void tsd_check(void) {
    pthread_setspecific(g_key18, (void *)0x1234);
    uint64_t base; __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(base));
    uint64_t off = *(uint64_t *)(g_mod[0].base + g_mod[0].key_page_off + g_mod[0].key_idx[0] * 8);
    if (((uint64_t *)(base & ~7ull))[off / 8] != 0x1234) die("TSD 布局不符（tpidrro_el0 与 pthread 键不对齐）");
    pthread_setspecific(g_key18, 0);
}

static void parse_dynamic(module_t *m) {
    uint32_t mod0 = *(uint32_t *)(m->base + 4);
    if (memcmp(m->base + mod0, "MOD0", 4)) die("%s: no MOD0", m->name);
    m->dyn = (const Elf64_Dyn *)(m->base + mod0 + *(int32_t *)(m->base + mod0 + 4));
    for (const Elf64_Dyn *d = m->dyn; d->d_tag; d++) switch ((int)d->d_tag) {
        case DT_SYMTAB: m->symtab = (const Elf64_Sym *)(m->base + d->d_un.d_ptr); break;
        case DT_STRTAB: m->strtab = (const char *)(m->base + d->d_un.d_ptr); break;
        case DT_INIT: m->init = d->d_un.d_ptr; break;
    }
    m->nsym = (unsigned)(((const uint8_t *)m->strtab - (const uint8_t *)m->symtab) / sizeof(Elf64_Sym));
}

static void register_gates(module_t *m, const char *dir) {
    char path[1024], line[256]; snprintf(path, sizeof path, "%s/%s.gates.tsv", dir, m->name);
    FILE *f = fopen(path, "r");
    int ng = 0;
    if (f) {
        unsigned long ret; char kind[16]; int arg;
        while (fgets(line, sizeof line, f))
            if (sscanf(line, "%lx %15s %d", &ret, kind, &arg) >= 3) { gate_register((uint64_t)m->base + ret, kind, arg); ng++; }
        fclose(f);
    }
    LOG("%s: gates=%d", m->name, ng);
}

// ---------- 观测门：text 封 RX 前把指定 main 偏移的指令换成「记名跳桩」----------
// 桩 = unimpl_stubs[k]（movz x9,#k; b unimpl_entry）→ unimpl_c 打一行名字后回 0。
// 用于定位 il2cpp os::File 编排层的运行时分支边（0x4808a4/0x4808cc/0x22bd98）。
// 站点已清空（观测期结束）：门会替换原指令（bl/tbz 换成跳桩），验证修复时必须全部移除。
// 需要再观测时按需加回：{ 偏移, "OBS_/OBSD_ 名" }（OBSD_ 前缀会转储 x0 对象头 0x40 字节）。
static const struct { uint64_t off; const char *name; } g_obs_sites[] = {
    { 0xc29178, "OBSS_settings_path" },   // 0xc2914c 的设置读取调用点：x1=路径串
};
static void obs_patch(module_t *m) {
    if (strcmp(m->name, "main")) return;
    for (unsigned i = 0; i < sizeof g_obs_sites / sizeof g_obs_sites[0]; i++) {
        uint64_t off = g_obs_sites[i].off;
        if (!off || !g_obs_sites[i].name) continue;   // 空占位
        if (off >= m->text_end) die("观测门越界 %s", g_obs_sites[i].name);
        // 找/建命名桩（与导入桩同表）
        unsigned k = 0;
        while (k < g_nstub && g_stub_name[k] && strcmp(g_stub_name[k], g_obs_sites[i].name)) k++;
        if (k == g_nstub) {
            if (g_nstub >= MAX_STUB) die("桩表满");
            g_stub_name[g_nstub] = g_obs_sites[i].name;
            k = g_nstub++;
        }
        uint32_t *code = (uint32_t *)(m->base + off);
        uint32_t orig0 = code[0];
        // bl unimpl_stubs[k]（桩地址 - (base+off)）/ 4，26 位有符号
        int64_t delta = (int64_t)((uint8_t *)&unimpl_stubs[k] - (m->base + off)) / 4;
        if (delta < -(1 << 25) || delta >= (1 << 25)) die("观测门超出 bl 范围 %s", g_obs_sites[i].name);
        code[0] = 0x94000000u | (uint32_t)(delta & 0x3ffffff);
        // nop 一条垫着（桩返回后落到下一条原指令位置继续；观测是有扰的，够定位分支边）
        code[1] = 0xd503201fu;
        LOG("观测门 %s @ main+%#llx（原指令 %#x）", g_obs_sites[i].name, (unsigned long long)off, orig0);
    }
}

static void relocate(module_t *m) {
    uint64_t rela = 0, relasz = 0, jmprel = 0, pltsz = 0;
    for (const Elf64_Dyn *d = m->dyn; d->d_tag; d++) switch ((int)d->d_tag) {
        case DT_RELA: rela = d->d_un.d_ptr; break;
        case DT_RELASZ: relasz = d->d_un.d_val; break;
        case DT_JMPREL: jmprel = d->d_un.d_ptr; break;
        case DT_PLTRELSZ: pltsz = d->d_un.d_val; break;
    }
    const Elf64_Rela *tabs[2] = {(const Elf64_Rela *)(m->base + rela), (const Elf64_Rela *)(m->base + jmprel)};
    uint64_t sizes[2] = {relasz, pltsz};
    int cnt[3] = {0};
    for (int t = 0; t < 2; t++)
        for (uint64_t i = 0; i < sizes[t] / sizeof(Elf64_Rela); i++) {
            const Elf64_Rela *r = &tabs[t][i];
            uint64_t *where = (uint64_t *)(m->base + r->r_offset);
            unsigned type = ELF64_R_TYPE(r->r_info), si = ELF64_R_SYM(r->r_info);
            if (type == R_AARCH64_RELATIVE) { *where = (uint64_t)m->base + r->r_addend; cnt[0]++; continue; }
            const Elf64_Sym *s = &m->symtab[si];
            const char *nm = m->strtab + s->st_name;
            uint64_t v;
            hle_fn0 hf = force_lookup(nm);   // HLE_FORCE：接管优先于一切定义
            if (hf) v = (uint64_t)hf;
            else if (strcmp(m->name, "sdk") && (!strncmp(nm, "_ZN2nn3hid", 10) || !strncmp(nm, "_ZN2nn5audio", 12) || !strncmp(nm, "_ZN2nn2vi", 9)))
                v = resolve_import(m, nm);   // hid/audio/vi 只对 main/subsdk0 接命名桩（sdk 自身初始化要绑真实现）；首次命中记名、回 0、不写出参
            else if (s->st_shndx) v = (uint64_t)m->base + s->st_value;
            else {
                void *p = NULL;
                for (int j = 0; j < g_nmod && !p; j++) p = module_sym(&g_mod[j], nm);
                v = p ? (uint64_t)p : resolve_import(m, nm);
            }
            if (type == R_AARCH64_JUMP_SLOT) { *where = v; cnt[2]++; }
            else { *where = v + r->r_addend; cnt[1]++; }
        }
    LOG("%s: reloc rel=%d abs=%d jmp=%d", m->name, cnt[0], cnt[1], cnt[2]);
}

static void load_modules(const char *dir, const char **names, int n) {
    for (int i = 0; i < n; i++) { strlcpy(g_mod[i].name, names[i], sizeof g_mod[i].name); read_layout(&g_mod[i], dir); }
    create_keys();
    for (int i = 0; i < n; i++) {
        module_t *m = &g_mod[i];
        char path[1024]; snprintf(path, sizeof path, "%s/%s.patched.bin", dir, m->name);
        int fd = open(path, O_RDONLY);
        if (fd < 0) die("open %s", path);
        struct stat st; fstat(fd, &st);
        m->size = ((size_t)st.st_size + PAGE - 1) & ~(size_t)(PAGE - 1);
        m->base = mmap(NULL, m->size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (m->base == MAP_FAILED) die("%s mmap", m->name);
        if (read(fd, m->base, st.st_size) != st.st_size) die("read %s", path);
        close(fd);
        install_key_page(m);
        obs_patch(m);   // text 封 RX 前打观测门（main 的 il2cpp os::File 分支边）
        uint64_t rx = (m->text_end + PAGE - 1) & ~(uint64_t)(PAGE - 1);
        if (mprotect(m->base, rx, PROT_READ | PROT_EXEC)) die("%s mprotect text", m->name);
        if (mprotect(m->base + (m->patch_off & ~(uint64_t)(PAGE - 1)), m->size - (m->patch_off & ~(uint64_t)(PAGE - 1)), PROT_READ | PROT_EXEC)) die("%s mprotect patch", m->name);
        if (!i) tsd_check();
        parse_dynamic(m);
        register_gates(m, dir);
        LOG("%s: base=%p size=%#zx", m->name, m->base, m->size);
        strlcpy(g_mod_ref[g_nmod_ref].name, m->name, sizeof g_mod_ref[0].name);
        g_mod_ref[g_nmod_ref].base = m->base;
        g_mod_ref[g_nmod_ref].size = m->size;
        g_nmod_ref++;
        g_nmod++;
    }
    for (int i = 0; i < g_nmod; i++) relocate(&g_mod[i]);
}

// ---------- 客体线程环境（thread.c 同款，参数位省略）----------
void guest_thread_init(void) {
    pthread_setspecific(g_keygate, (void *)dm_gate);
    pthread_setspecific(g_key18, 0);
    void *tls = calloc(1, 8192), *tlr = calloc(1, 0x200 + 0x400);
    *(void **)((uint8_t *)tlr + 0x1f8) = (uint8_t *)tlr + 0x200;   // TLR[0x1f8] = 当前线程对象
    pthread_setspecific(g_keytls, tls);
    pthread_setspecific(g_keytlr, tlr);
}

typedef void (*fn0)(void);
typedef void (*fn2)(uint64_t, uint64_t);

static void guest_main(void) {
    guest_thread_init();
    ((fn0)req("_init_libc0"))();
    LOG(">>> nnosInitialize");
    ((fn2)req("nnosInitialize"))(main_thread_register(), 0);
    // d2r main.c 同款：Unity 从 argv[0] 推导设置/数据路径——缺了它设置路径为空串，
    // PlayerInitEngine 的回退文件读取全部「未挂载」失败 → fail_player（实证）。
    {
        static char arg0[] = "D2R";
        static char *argv0[2] = { arg0, NULL };
        ((void (*)(void *))req("_ZN2nn2os11SetHostArgcEi"))((void *)(uintptr_t)1);
        ((void (*)(void *))req("_ZN2nn2os11SetHostArgvEPPc"))(argv0);
        LOG("argv[0]=%s 已设置", arg0);
    }
    ((fn0)req("_init_libc1"))();
    LOG(">>> nninitInitializeSdkModule"); ((fn0)req("nninitInitializeSdkModule"))();
    LOG(">>> nninitStartup"); ((fn0)req("nninitStartup"))();
    ((fn0)req("_init_libc2"))();
    for (int i = 0; i < g_nmod; i++) {   // rtld 回调 B：各模块 DT_INIT（全局构造）
        module_t *m = &g_mod[i];
        if (m->init) { LOG("%s: DT_INIT +%#llx", m->name, (unsigned long long)m->init); ((fn0)(m->base + m->init))(); }
    }
    LOG(">>> nnMain");
    ((fn0)req("nnMain"))();
    LOG("nnMain returned");
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: dmhost <产物目录> [模块…]\n"); return 2; }
    strlcpy(g_outdir, argv[1], sizeof g_outdir);
    diag_install();
    alarm(600);   // CI 看门狗：资产装载阶段耗时（192MB 池 + Unity 资源解析），10 分钟；workflow 上限 15 分钟
    const char *names[MAX_MOD]; int n = 0;
    for (int i = 2; i < argc && n < MAX_MOD; i++) names[n++] = argv[i];
    if (!n) { names[n++] = "main"; names[n++] = "sdk"; names[n++] = "subsdk0"; }
    load_modules(argv[1], names, n);
    guest_main();
    return 0;
}
