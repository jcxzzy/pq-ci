// NVN → Metal 回放层（d2r-mobile nvn_mtl.m 方法论移植）
// 第一阶段骨架：把游戏提交的记录链变成真 MTLCommandBuffer 提交——GPU 时间线首次存在，
// 完成回调（addCompletedHandler）是真完成事件的回流通道；QueueFinish 获得真等待语义。
// 回放编码（B2T 纹理上传 / 清屏 / 绘制）按里程碑逐阶段长入；着色器微码→MSL 在后续步骤。
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>

static id<MTLDevice> g_mdev;
static id<MTLCommandQueue> g_mq;
static pthread_mutex_t g_mtl_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_mtl_inflight;      // 已 commit、完成回调未到的提交数
static uint64_t g_mtl_done;     // 完成总数
static atomic_int g_mtl_mode;   // 0=未初始化 1=真 Metal 2=无 GPU 降级

int mtl_init(void) {
    int m = atomic_load(&g_mtl_mode);
    if (m) return m;
    @autoreleasepool {
        g_mdev = MTLCreateSystemDefaultDevice();
        if (g_mdev) g_mq = [g_mdev newCommandQueue];
        atomic_store(&g_mtl_mode, (g_mdev && g_mq) ? 1 : 2);
    }
    fprintf(stderr, "[dm] mtl_init: mode=%d dev=%p（1=真 Metal，2=无 GPU 降级）\n",
            atomic_load(&g_mtl_mode), (__bridge void *)g_mdev);
    return atomic_load(&g_mtl_mode);
}

// 提交一批记录链（句柄 = BEGIN 记录地址）。骨架阶段：空命令缓冲（含一个合法 blit 编码器）
// 提交——完成通道先行；记录链回放编码在后续里程碑接入此处。
void mtl_submit_chains(void *const *handles, int n) {
    int mode = mtl_init();
    if (mode != 1) { g_mtl_done++; return; }   // 降级：立即视为完成
    (void)handles; (void)n;
    id<MTLCommandBuffer> cb;
    @autoreleasepool {
        cb = [g_mq commandBuffer];
    }
    if (!cb) { g_mtl_done++; return; }
    pthread_mutex_lock(&g_mtl_mu);
    g_mtl_inflight++;
    pthread_mutex_unlock(&g_mtl_mu);
    @autoreleasepool {
        id<MTLBlitCommandEncoder> bl = [cb blitCommandEncoder];
        [bl endEncoding];
    }
    [cb addCompletedHandler:^(__attribute__((unused)) id<MTLCommandBuffer> b) {
        pthread_mutex_lock(&g_mtl_mu);
        g_mtl_inflight--;
        g_mtl_done++;
        pthread_mutex_unlock(&g_mtl_mu);
    }];
    [cb commit];
}

// QueueFinish 语义：等在途提交全部完成（真队列等待）
void mtl_finish(void) {
    if (mtl_init() != 1) return;
    for (;;) {
        pthread_mutex_lock(&g_mtl_mu);
        int inf = g_mtl_inflight;
        pthread_mutex_unlock(&g_mtl_mu);
        if (!inf) return;
        struct timespec ts = {0, 2000000};   // 2ms 轮询（完成回调在 Metal 内部队列上跑）
        nanosleep(&ts, NULL);
    }
}

uint64_t mtl_done_count(void) { return g_mtl_done; }
