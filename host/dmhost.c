// pq-port 宿主（Apple silicon / arm64）：装载改写后的三模块，按 d2r-mobile 宿主的启动序引导。
// 架构照抄 d2r-mobile dm/host（MIT）：
//   装载（loader.c 的多模块 + 键页 + 门登记 + 跨模块重定位）· 门 ABI（entry.S dm_gate）
//   · 线程槽（pthread_setspecific × tpidrro_el0 直接 TSD）· 启动序（main.c guest_main）
// 本文件是 Apple silicon 上跑通「SDK 初始化 → nnMain」的最小骨架；svc 处理器按
// bootsim 的实证清单逐个补齐（hle_svc_dispatch 里未实现的记名返回错误码）。
// 构建：make -C host （clang -arch arm64；本仓库的 Intel Mac 只做交叉编译验证）
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
#define MAX_STUB 1024
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
#define RESERVE (5ull << 30)          // 5 GB：alias/stack + 4 GB 堆区，只占地址不占内存
static uint8_t *g_as;                 // 客体地址空间基址
static uint8_t *g_alias, *g_stack, *g_heap;
static void mem_init(void) {
    if (g_as) return;
    g_as = mmap(NULL, RESERVE, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (g_as == MAP_FAILED) die("预留客体地址空间失败");
    g_alias = g_as + 0x10000000;      // alias 512 MB
    g_stack = g_as + 0x30000000;      // 栈区 256 MB
    g_heap  = g_as + 0x40000000;      // 堆区（到块尾 ≈ 4 GB）
    LOG("客体地址空间 %p +%#llx（alias %p / stack %p / heap %p）", g_as, (unsigned long long)RESERVE, g_alias, g_stack, g_heap);
}

// 客体堆（SetHeapSize / QueryMemory 共用）
static void *guest_heap(void) {
    mem_init();
    return g_heap;
}

// svc 处理器：号码表按本 SDK 二进制符号名实证（build/svc_map.txt，老固件世代编号，
// 与现代 Horizon 表不同——svc#41=GetInfo、svc#29=SignalProcessWideKey、svc#38=Break）。
// 返回值 = Result（0 成功）；未实现的返回 0xF001 并记名一次。
static uint32_t g_handle_next = 0x10;   // 假句柄分配（线程/事件）

static uint64_t svc_impl(int num, uint64_t *x) {
    switch (num) {
    case 1: {  // SetHeapSize(size) → x1 = 堆地址（在预留块堆区内提交 RW）
        mem_init();
        uint64_t size = x[1];
        if (size > RESERVE - 0x40000000) return 0xCE011;   // 超出堆区：让 SDK 按原版步进减 2 MB 重试
        if (mprotect(g_heap, (size_t)size, PROT_READ | PROT_WRITE)) die("SetHeapSize mprotect");
        x[1] = (uint64_t)g_heap;
        return 0;
    }
    case 6: {  // QueryMemory(out MemoryInfo 0x28, out PageInfo, addr)：按客体地址空间分区回报
        mem_init();
        uint64_t addr = x[2], base = 0, esz = 0;
        uint32_t state = 0, perm = 0;
        if ((uint64_t)g_as <= addr && addr < (uint64_t)g_as + RESERVE) {
            if (addr < (uint64_t)g_alias) { base = (uint64_t)g_as; esz = 0x10000000; }
            else if (addr < (uint64_t)g_alias + 0x20000000) { base = (uint64_t)g_alias; esz = 0x20000000; state = 0x3; perm = 3; }
            else if (addr < (uint64_t)g_stack) { base = (uint64_t)g_alias + 0x20000000; esz = 0x10000000; }
            else if (addr < (uint64_t)g_heap) { base = (uint64_t)g_stack; esz = 0x10000000; state = 0xB; perm = 3; }
            else { base = (uint64_t)g_heap; esz = RESERVE - 0x40000000; state = 0x3; perm = 3; }
        } else {
            for (int i = 0; i < g_nmod; i++) {   // 模块映像 = 代码区
                uint64_t b = (uint64_t)g_mod[i].base;
                if (addr >= b && addr < b + g_mod[i].size) { base = b; esz = g_mod[i].size; state = 3; perm = 5; break; }
            }
            if (!esz) {   // 宿主当前线程栈 → 状态 0xB（SDK 主线程记录用，见 d2r 注释）
                uint64_t top = (uint64_t)pthread_get_stackaddr_np(pthread_self());
                uint64_t ssz = pthread_get_stacksize_np(pthread_self());
                if (addr < top && addr >= top - ssz) { base = top - ssz; esz = ssz; state = 0xB; perm = 3; }
                else { base = addr & ~0x3FFFull; esz = 0x4000; }
            }
        }
        struct { uint64_t base, size; uint32_t state, attr, ipc, perm, pad; } mi = {base, esz, state, 0, 0, perm, 0};
        memcpy((void *)(uintptr_t)x[0], &mi, sizeof mi);
        if (x[1]) *(uint32_t *)(uintptr_t)x[1] = 0;
        return 0;
    }
    case 7:  // ExitProcess
        LOG("svc#7 ExitProcess");
        _exit(0);
    case 8:  // CreateThread(out h, entry, arg, sp, prio, core)：单线程模拟，发假句柄不真跑
        *(uint32_t *)(uintptr_t)x[0] = g_handle_next++;
        return 0;
    case 9:  // StartThread(h)
        return 0;
    case 10: // ExitThread
        LOG("svc#10 ExitThread on main?");
        return 0;
    case 11: // SleepThread(ns)
        return 0;
    case 12: {  // GetThreadPriority(out i32, h) ← 44
        *(int32_t *)(uintptr_t)x[0] = 44;
        return 0;
    }
    case 13: // SetThreadPriority(h, prio)
        return 0;
    case 14: {  // GetThreadCoreMask(out i32, out u64 mask, h)
        *(int32_t *)(uintptr_t)x[0] = 0;
        *(uint64_t *)(uintptr_t)x[1] = 1;
        return 0;
    }
    case 15: // SetThreadCoreMask
        return 0;
    case 16: // GetCurrentProcessorNumber
        return 0;
    case 22: // CloseHandle
        return 0;
    case 24: {  // WaitSynchronization(out idx, handles, n, timeout)：恒满足
        if (x[0]) *(int32_t *)(uintptr_t)x[0] = 0;
        return 0;
    }
    case 25: // CancelSynchronization
        return 0;
    case 26: // ArbitrateLock
    case 27: // ArbitrateUnlock
    case 28: // WaitProcessWideKeyAtomic
    case 29: // SignalProcessWideKey
        return 0;
    case 30: // GetSystemTick（19.2 MHz）
        return now_ns() * 12 / 625;
    case 31: {  // ConnectToNamedPort(out h, name)
        char nm[64] = {0};
        for (int i = 0; i < 63; i++) {
            uint8_t c = *(const uint8_t *)(uintptr_t)(x[1] + i);
            if (!c) break;
            nm[i] = (char)c;
        }
        LOG("svc#31 ConnectToNamedPort → %s", nm);
        *(uint32_t *)(uintptr_t)x[0] = g_handle_next++;
        return 0;
    }
    case 38: {  // Break(reason, addr, size)：Debug 断点继续，致命断点退出
        uint64_t reason = x[0];
        LOG("svc#38 Break reason=%#llx addr=%#llx size=%#llx", (unsigned long long)reason,
            (unsigned long long)x[1], (unsigned long long)x[2]);
        if (reason & 1) return 0;   // BreakReason_Debug：仅停一下，继续
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
    case 36: {  // GetProcessId(out u64, h)
        *(uint64_t *)(uintptr_t)x[0] = 0x50;
        return 0;
    }
    case 37: {  // GetThreadId(out u64, h)
        *(uint64_t *)(uintptr_t)x[0] = 0x60 + g_handle_next;
        return 0;
    }
    case 41: {  // GetInfo(out u64, InfoType, handle, key)：老固件编号，语义按调用方符号实证
        mem_init();
        uint64_t t = x[1], key = x[3], v = 0;
        switch (t) {
        case 12: v = (uint64_t)g_as; break;                    // 地址空间起点（Aslr/OsResourceManager）
        case 13: v = (uint64_t)g_as + RESERVE; break;          // 地址空间终点
        case 14: v = 0; break;                                  // 栈守卫起点
        case 15: v = 0x8000000ull; break;                       // 栈守卫终点
        case 2:                                                 // VAMM 保留区起点（AddressRegionManager 启动问法）
        case 11:                                                // VAMM 保留区（GetReservedRegionImpl，key 2/3）
            v = (uint64_t)g_alias; break;
        case 3:
            v = (uint64_t)g_alias + 0x20000000; break;          // 保留区终点
        case 16: v = 1; break;                                  // 虚拟地址内存启用（MapPhysicalMemory 走 alias 区）
        case 17: v = 0; break;                                  // VAMM 资源用量
        case 8:  v = 0; break;                                  // 无调试器
        case 10: v = 0; break;                                  // 空闲拍数
        case 7:  v = 0xE0000000ull; break;                      // 总内存（QueryMemoryInfo 总量格）
        case 6:  v = 0x1000000ull; break;                       // 已用内存
        default: LOG("svc#41 GetInfo type=%llu key=%#llx → 0", (unsigned long long)t, (unsigned long long)key); v = 0; break;
        }
        (void)key;
        *(uint64_t *)(uintptr_t)x[0] = v;
        return 0;
    }
    case 44: {  // MapPhysicalMemory(addr, size)：只许在 alias 区内（d2r 配方：mprotect 提交）
        mem_init();
        uint8_t *a = (uint8_t *)(uintptr_t)x[0];
        size_t size = (size_t)x[1];
        if (a < g_alias || a + size > g_alias + 0x20000000) {
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
        if (a < g_alias || a + size > g_alias + 0x20000000) return 0xD401;
        madvise(a, size, MADV_FREE);
        if (mprotect(a, size, PROT_NONE)) die("svc#45 mprotect");
        return 0;
    }
    case 48: {  // GetResourceLimitLimitValue(out i64, h, resource)
        *(int64_t *)(uintptr_t)x[0] = 0x100000000ll;
        return 0;
    }
    case 49: {  // GetResourceLimitCurrentValue(out i64, h, resource)
        *(int64_t *)(uintptr_t)x[0] = 0x8000000ll;
        return 0;
    }
    case 51: {  // GetThreadContext3(out ThreadContext 0x328, h)
        memset((void *)(uintptr_t)x[0], 0, 0x328);
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
            static uint8_t hit[256];
            if (g->arg < 256 && !hit[g->arg]++) LOG("svc#%d 首次命中（x0=%#llx）", g->arg, (unsigned long long)regs[0]);
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
// 接管函数按客体 ABI 调用（参数在 x0..），与宿主 C ABI 一致。
typedef void (*hle_fn0)(void);
static void h_noop(void) {}
static void h_excstack(uint64_t *out) {
    mem_init();
    uint8_t *es = g_stack + 0x80000;
    if (mprotect(es, 0x4000, PROT_READ | PROT_WRITE)) die("异常栈 mprotect");
    out[0] = (uint64_t)(es + 0x4000);   // Horizon 习惯：报向下生长的栈顶
    out[1] = 0x4000;
    LOG("init 接管：客体异常栈 ← %p+%#x", es, 0x4000);
}
typedef struct { const char *name; hle_fn0 fn; } hle_ent;
static hle_fn0 force_lookup(const char *name) {
    static const hle_ent tab[] = {
        {"nndiagStartup", h_noop},
        {"_ZN2nn2oe10InitializeEv", h_noop},
        {"_ZN2nn3aoc10InitializeEv", h_noop},
        {"_ZN2nn4pctl10InitializeEv", h_noop},
        {"_ZN2nn4diag34InitializeApplicationAbortObserverEv", h_noop},
        {"nnosGetDefaultUserExceptionStackForApplication", (hle_fn0)h_excstack},
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
    ((fn2)req("nnosInitialize"))(1, 0);
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
    diag_install();
    alarm(120);   // CI 看门狗：两分钟内没走完启动序就由 watchdog 记录后终止
    const char *names[MAX_MOD]; int n = 0;
    for (int i = 2; i < argc && n < MAX_MOD; i++) names[n++] = argv[i];
    if (!n) { names[n++] = "main"; names[n++] = "sdk"; names[n++] = "subsdk0"; }
    load_modules(argv[1], names, n);
    guest_main();
    return 0;
}
