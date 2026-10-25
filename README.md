# pq-ci — 宝可梦寻宝探险 Switch→Apple 兼容层（宿主实现）

以 [d2r-mobile](https://github.com/jhaizhou-ops/d2r-mobile) 方法论构建的 Nintendo Switch
→ iOS/macOS 兼容层宿主。本仓库只包含**兼容层代码**——不含任何游戏资源或解密程序；
运行需自备游戏文件（bring your own files）。

## 布局
- `host/dmhost.c` — 宿主：HLE svc（同步原语/线程/内存/时间）、fs、NVN 接管层
  （纹理/程序/命令录制/Metal 回放接入）、诊断（线程转储/SIGUSR1 采样/看门狗）
- `host/nvn_mtl.m` — NVN→Metal 回放层：真 MTLCommandBuffer 提交 + 完成回调回流；
  无 GPU 环境软件完成模拟（2ms 异步节拍）+ 50ms 驱动心跳
- `host/fault.c` — 崩溃符号化、看门狗、心跳打断点取证
- `host/entry.S` — 桩跳板/观测门
- `.github/workflows/arm64.yml` — arm64 构建运行（macos-14）

## 九步进度
| 步 | 状态 | 说明 |
|---|---|---|
| 1 可行性合规 | ✅ | aarch64 同构、NVN、BYO-files 合规边界 |
| 2 解包 | ✅ | NSO/RomFS（自备密钥，不入库） |
| 3 静态分析 | ✅ | 手术清单/调用点测绘/TSV 产物 |
| 4 二进制重写器 | ✅ | patch_nso + 重定位 + 观测门 |
| 5 宿主层 | ✅ | svc/fs/线程/同步/网络快速失败 |
| 6 图形层 | 🔶 45% | 命令录制层完整（每帧真命令流 CI 实证）；Metal 回放骨架+完成通道；着色器翻译待做 |
| 7 音频输入 | ⬜ | hid/vi UNIMPL 面 <10 项 |
| 8 iOS 外壳 | ⬜ | |
| 9 验证回归 | ⬜ | |

## 当前焦点（详见 pq-port/build/STATE.md）
装载期死锁闭环已完全测绘：订阅风暴→注册表膨胀→走查永不收尾→完成表不初始化→
装载事件不发布。解楔补丁（扫描环 NOP）已就位；下一步=符号化 il2cpp 订阅函数
（global-metadata.dat）并装载期桩化生产者。

## 构建
```
make -C host        # arm64 交叉（Intel Mac 验证）
./host/dmhost out/  # arm64 机上运行（out/ 含自备之 patched.bin + RomFS）
```
