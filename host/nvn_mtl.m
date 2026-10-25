// NVN → Metal 回放层（d2r-mobile nvn_mtl.m 方法论移植）
// 有 GPU（mode 1）：提交走真 MTLCommandBuffer，完成回调（addCompletedHandler）回流真完成事件。
// 无 GPU（mode 2，如 GitHub Actions runner）：软件完成模拟——提交后经真实延迟（dispatch_after）
// 在独立队列上触发完成，QueueFinish 真等待、sync 真信号化。关键性质是「异步 + 跨线程 + 有延迟」，
// 不是即时返回——此前 CI 实证即时信号化会回归。
// 回放编码（B2T 纹理上传 / 清屏 / 绘制）按里程碑逐阶段长入；着色器微码→MSL 在后续步骤。
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>

static id<MTLDevice> g_mdev;
static id<MTLCommandQueue> g_mq;
static dispatch_queue_t g_simq;   // 软件完成模拟队列（mode 2）
static pthread_mutex_t g_mtl_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_mtl_inflight;        // 已提交、完成未到的提交数
static uint64_t g_mtl_done;       // 完成总数
static atomic_int g_mtl_mode;     // 0=未初始化 1=真 Metal 2=软件完成模拟

// dmhost.c 提供：sync 对象置已信号（完成回调线程调用）
extern void nvn_sync_mark_signaled(void *sync);

int mtl_init(void) {
    int m = atomic_load(&g_mtl_mode);
    if (m) return m;
    @autoreleasepool {
        g_mdev = MTLCreateSystemDefaultDevice();
        if (g_mdev) g_mq = [g_mdev newCommandQueue];
        atomic_store(&g_mtl_mode, (g_mdev && g_mq) ? 1 : 2);
        g_simq = dispatch_queue_create("dm.mtl.sim", DISPATCH_QUEUE_SERIAL);
    }
    fprintf(stderr, "[dm] mtl_init: mode=%d dev=%p（1=真 Metal，2=软件完成模拟——无 GPU 环境）\n",
            atomic_load(&g_mtl_mode), (__bridge void *)g_mdev);
    return atomic_load(&g_mtl_mode);
}

static void sim_signal(void **syncs, int nsync) {   // 在模拟完成线程上信号化
    extern void nvn_sync_mark_signaled(void *sync);
    extern void host_wake_pool_waits(void);
    for (int i = 0; i < nsync; i++)
        if (syncs[i]) nvn_sync_mark_signaled(syncs[i]);
    free(syncs);
    host_wake_pool_waits();   // 驱动侧完成：唤醒池区条件键等待者（NVN 队列完成协议）
}

// 提交一批记录链（句柄 = BEGIN 记录地址）+ 本批 FenceSync 的 sync 对象。
// 完成时机：mode 1 = GPU 完成回调；mode 2 = 2ms 模拟延迟。syncs 数组被本函数接管（完成后释放）。
void mtl_submit_chains(void *const *handles, int n, void **syncs, int nsync) {
    (void)handles; (void)n;
    int mode = mtl_init();
    pthread_mutex_lock(&g_mtl_mu);
    g_mtl_inflight++;
    pthread_mutex_unlock(&g_mtl_mu);
    if (mode != 1) {   // 软件完成模拟：真异步节拍
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_MSEC), g_simq, ^{
            sim_signal(syncs, nsync);
            pthread_mutex_lock(&g_mtl_mu);
            g_mtl_inflight--; g_mtl_done++;
            pthread_mutex_unlock(&g_mtl_mu);
        });
        return;
    }
    id<MTLCommandBuffer> cb;
    @autoreleasepool {
        cb = [g_mq commandBuffer];
    }
    if (!cb) {   // 极端：有设备却拿不到缓冲——按完成处理
        sim_signal(syncs, nsync);
        pthread_mutex_lock(&g_mtl_mu);
        g_mtl_inflight--; g_mtl_done++;
        pthread_mutex_unlock(&g_mtl_mu);
        return;
    }
    @autoreleasepool {
        id<MTLBlitCommandEncoder> bl = [cb blitCommandEncoder];
        [bl endEncoding];
    }
    [cb addCompletedHandler:^(__attribute__((unused)) id<MTLCommandBuffer> b) {
        sim_signal(syncs, nsync);
        pthread_mutex_lock(&g_mtl_mu);
        g_mtl_inflight--; g_mtl_done++;
        pthread_mutex_unlock(&g_mtl_mu);
    }];
    [cb commit];
}

// 呈现完成的 sync：真实语义 = 上屏纹理退役后才信号（约一帧后）。即时信号化已实证回归，
// 故走同一模拟节拍（16ms）。
void mtl_defer_signal(void *sync, uint64_t delay_ms) {
    if (!sync) return;
    mtl_init();
    void **one = malloc(sizeof(void *));
    if (!one) return;
    one[0] = sync;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)delay_ms * NSEC_PER_MSEC), g_simq, ^{
        sim_signal(one, 1);
    });
}

// QueueFinish 语义：等在途提交全部完成（真队列等待；mode 2 = 等模拟延迟走完）
void mtl_finish(void) {
    mtl_init();
    for (;;) {
        pthread_mutex_lock(&g_mtl_mu);
        int inf = g_mtl_inflight;
        pthread_mutex_unlock(&g_mtl_mu);
        if (!inf) return;
        struct timespec ts = {0, 2000000};
        nanosleep(&ts, NULL);
    }
}

uint64_t mtl_done_count(void) { return g_mtl_done; }
