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
    if (!g_stub_seen[idx]++)
        LOG("UNIMPL %s (x0=%#llx x1=%#llx)", g_stub_name[idx], (unsigned long long)regs[0], (unsigned long long)regs[1]);
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
static void mem_init(void) {
    if (g_as) return;
    g_as = mmap(NULL, RESERVE, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (g_as == MAP_FAILED) die("预留客体地址空间失败");
    g_alias = g_as + 0x10000000;
    g_stack = g_as + 0x50000000;
    g_heap  = g_as + 0x60000000;
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
    if (!t) _exit(0);   // 主线程 ExitThread ≈ 进程退出
    pthread_mutex_lock(&G);
    t->exited = 1;
    pthread_cond_broadcast(&GV);
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
    if (fd < 0) return FS_ENOENT;   // 只读区里缺文件按未找到回（Unity 会探测可选资源）
    int h = 1;
    while (h < MAX_FH && g_fh[h]) h++;
    if (h >= MAX_FH) { close(fd); return 0xF701; }
    g_fh[h] = fd;
    *out = (uint64_t)h;
    return 0;
}
static uint32_t h_readfile_n(uint64_t *out, uint64_t h, int64_t off, void *buf, uint64_t n) {
    if (!h || h >= MAX_FH || !g_fh[h]) return 0xF601;
    ssize_t r = pread(g_fh[h], buf, n, (off_t)off);
    if (r < 0) return 0xFA01;
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
    if (host_path(path, hp, sizeof hp) < 0) return FS_ENOENT;
    struct stat st;
    if (stat(hp, &st)) return FS_ENOENT;
    *out = S_ISDIR(st.st_mode) ? 1 : 2;   // DirectoryEntryType: 1=目录 2=文件
    return 0;
}
static uint32_t h_opendirectory(uint64_t *out, const char *path, int mode) {
    char hp[1100];
    if (host_path(path, hp, sizeof hp) < 0) return FS_ENOENT;
    DIR *d = opendir(hp);
    if (!d) return FS_ENOENT;
    int h = 1;
    while (h < MAX_DH && g_dh[h].d) h++;
    if (h >= MAX_DH) { closedir(d); return 0xF701; }
    g_dh[h] = (typeof(g_dh[0])){d, mode, {0}};
    strlcpy(g_dh[h].path, hp, sizeof g_dh[0].path);
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
        int want = (de->d_type == DT_DIR) ? 1 : 2;
        if (g_dh[h].mode && !(g_dh[h].mode & want) && g_dh[h].mode != 3) continue;
        uint8_t *slot = e + (size_t)cnt * 0x310;
        memset(slot, 0, 0x310);
        strlcpy((char *)slot, de->d_name, 0x301);
        *(int32_t *)(slot + 0x304) = want;
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
// ---------- NVN 接口层（d2r hle_nvn.c 的最小起点） ----------
// main 只导入 nvnBootstrapLoader 一个 nvn 符号——NVN 全 API 按名字经它取函数指针，
// 强制接管后 sdk 里的 NVN 驱动栈整块不执行。第一步每个名字发「记名桩」：
// 回 0 恰是 NVN_SUCCESS（设备/队列/窗口初始化族天然通过），首次调用记名——
// 在 runner 上收集 Unity 实际调用的 NVN 面，再按 d2r 的语义分层逐个实装。
static void *h_nvn_bootstrap(const char *name);
static void *h_nvn_getprocaddr(void *dev, const char *name) {
    void *fn = h_nvn_bootstrap(name);
    LOG("nvnDeviceGetProcAddress(%s) → %p", name && (uintptr_t)name > 0x10000 ? name : "?", fn);
    return fn;
}
static void *h_nvn_bootstrap(const char *name) {
    if (!name || !*name) return NULL;
    static const struct { const char *nm; void *fn; } known[] = {
        {"nvnDeviceGetProcAddress", (void *)h_nvn_getprocaddr},
    };
    for (unsigned i = 0; i < sizeof known / sizeof known[0]; i++)
        if (!strcmp(known[i].nm, name)) return known[i].fn;
    for (unsigned k = 0; k < g_nstub; k++)
        if (g_stub_name[k] && !strcmp(g_stub_name[k], name)) return &unimpl_stubs[k];
    if (g_nstub >= MAX_STUB) die("nvn 桩表满");
    g_stub_name[g_nstub] = strdup(name);
    return &unimpl_stubs[g_nstub++];
}
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
        {"nvnBootstrapLoader", (hle_fn0)h_nvn_bootstrap},   // NVN 全接口经此按名取函数指针；记名桩收集调用面
        {"_ZN2nn2fs22GetGlobalAccessLogModeEPj", (hle_fn0)h_logmode},
        {"_ZN2nn2fs22QueryMountRomCacheSizeEPm", (hle_fn0)h_romcache},
        {"_ZN2nn2fs8MountRomEPKcPvm", (hle_fn0)h_mountrom},
        // oe 服务对象因 Initialize 接管为空，三个 notification setter 会空表解引用（sdk+0x14f064 实证）
        {"_ZN2nn2oe28SetResumeNotificationEnabledEb", h_noop},
        {"_ZN2nn2oe44SetPerformanceModeChangedNotificationEnabledEb", h_noop},
        {"_ZN2nn2oe42SetOperationModeChangedNotificationEnabledEb", h_noop},
        {"_ZN2nn2oe25TryPopNotificationMessageEPj", h_noop},   // 返回 0：nnMain+0x78c tbz w0,#0 → 跳过读消息
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
    alarm(120);   // CI 看门狗：两分钟内没走完启动序就由 watchdog 记录后终止
    const char *names[MAX_MOD]; int n = 0;
    for (int i = 2; i < argc && n < MAX_MOD; i++) names[n++] = argv[i];
    if (!n) { names[n++] = "main"; names[n++] = "sdk"; names[n++] = "subsdk0"; }
    load_modules(argv[1], names, n);
    guest_main();
    return 0;
}
