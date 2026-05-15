# 多模输入组件指引

## 项目定位

本仓库对应 OpenHarmony `foundation/multimodalinput/input`。优先按这些目录定位问题：

- `service/`：服务端输入处理、分发、窗口管理、设备管理和指针绘制。
- `frameworks/`、`interfaces/`：Native、NAPI、ETS 和 C API。
- `common/`、`util/`：共享工具和基础结构。
- `etc/`、`sa_profile/`、`multimodalinput.cfg`、`mmi_uinput.rc`：运行配置。
- `test/`、`test/fuzztest/`：单元测试和 fuzz 目标。

## 构建和验证

构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。

```sh
./build.sh --product-name rk3568 --build-target input --ccache
prebuilts/build-tools/linux-x86/bin/ninja -C out/rk3568 InputWindowsManagerTest
```

涉及真实窗口、显示、设备、图形或服务集成的行为，需要补充板侧证据。提交使用 `git commit -s`，并保留 `Co-Authored-By: Agent`。

## 知识索引

稳定背景知识放在 `docs/knowledge/`。改动前按场景读取对应文件：

| 场景 | 先读 |
| --- | --- |
| 事件归一化、目标选择、命中测试、坐标转换、分发、合成事件、高频移动/绘制路径 | `docs/knowledge/input-event-pipeline.md` |
| 显示组、焦点隔离、捕获、取消、axis-end、重分发、默认组回退 | `docs/knowledge/display-group-model.md` |
| 设备/显示绑定、热插拔、虚拟/远端设备、摇杆、手写板、手写笔、触控板、生命周期清理 | `docs/knowledge/input-device-scope.md` |
| 鼠标/光标缓存、捕获状态、指针序列、键盘焦点重发、UDS 分发状态、懒分配 | `docs/knowledge/input-context-state.md` |
| 构建、板侧测试、PR 证据、重构建共享库、公开 API 或配置行为验证 | `docs/knowledge/board-verification.md` |

## 项目约束

- 事件分发和光标绘制是高频路径，不要在每次移动或绘制中增加全量扫描、字符串格式化或 INFO 日志。
- 设备分类的归属规则要保持显式，不要把手写板、手写笔、触控板、远端或虚拟输入规则折叠进通用鼠标/键盘路径。
- 默认组状态只适合默认初始化和明确的遗留 helper。非默认事件链应继续使用已解析上下文或序列快照。
- 可选上下文状态保持懒分配，不要为了普通默认路径预先分配分发或渲染上下文。
- C++ 改动优先复用附近的 `CHKPV`、`CHKPR`、`MMI_HILOG*`、`RET_OK`、`RET_ERR` 等项目宏和返回约定。
