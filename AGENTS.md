# 多模输入组件指引

## 项目定位

本仓库对应 OpenHarmony `foundation/multimodalinput/input`。优先按这些目录定位问题：

- `service/`：服务端输入处理、分发、窗口管理、设备管理和指针绘制。
- `frameworks/`、`interfaces/`：Native、NAPI、ETS 和 C API。
- `common/`、`util/`：共享工具和基础结构。
- `etc/`、`sa_profile/`、`multimodalinput.cfg`、`mmi_uinput.rc`：运行配置。
- `test/`、`test/fuzztest/`：单元测试和 fuzz 目标。

### 按任务类型定位代码

| 任务类型 | 首选目录 | 关键文件 |
| --- | --- | --- |
| 新增输入设备类型 | `service/device_manager/` | `input_device_manager.h/cpp`, `pointer_device_manager.h/cpp` |
| 修改设备状态管理 | `service/device_state_manager/` | `device_state_manager.h/cpp` |
| 修改事件分发逻辑 | `service/event_dispatch/` | `event_dispatch_handler.h/cpp` |
| 修改窗口/显示绑定 | `service/window_manager/` | `input_windows_manager.h`, `input_display_bind_helper.h` |
| 修改指针绘制 | `service/window_manager/` | `pointer_drawing_manager.h`, `pointer_renderer.h` |
| 修改硬件光标 | `service/hardware_cursor_pointer_manager/` | `hardware_cursor_pointer_manager.h/cpp` |
| 修改显示状态 | `service/display_state_manager/` | `display_event_monitor.h/cpp` |
| 触摸/鼠标/键盘事件归一化 | `service/*_event_normalize/` | 对应归一化处理器 |
| 修改 Native API | `interfaces/native/innerkits/` | 对应模块的 `.h` 头文件 |
| 修改 NAPI 绑定 | `frameworks/napi/` | 各事件类型目录下的绑定文件 |
| 修改 ETS 接口 | `frameworks/ets/` | 对应模块的 `.taihe` IDL 文件 |
| 修改 NDK 接口 | `interfaces/kits/c/input` | 对应接口的  `.h` 头文件 |
| 修改权限处理 | `service/permission_helper/` | `permission_helper.h/cpp` |

### 嵌套指引

本仓库无目录级别的嵌套指引。所有任务级指导均通过 `docs/knowledge/` 中的场景文档提供。

## 构建和验证

构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。

```sh
./build.sh --product-name rk3568 --build-target input --ccache
prebuilts/build-tools/linux-x86/bin/ninja -C out/rk3568 InputWindowsManagerTest
```

### 完成标准

任务被认为完成，当且仅当：

1. **代码改动已提交** - 使用 `git commit -s`，多代理协作时添加 `Co-Authored-By: Agent`
2. **本地构建通过** - 执行上述构建命令
3. **相关测试通过** - 对应单元测试通过
4. **板侧验证（如适用）** - 涉及窗口/显示/设备/图形的改动需提供验证证据
5. **文档更新（如适用）** - 公共 API 修改需更新注释和文档

### 如果无法运行验证

明确说明无法运行的原因，列出推荐的验证步骤供人工执行，标记需要人工验证的部分。

### 完成报告格式

报告应包含：改动摘要（文件列表、改动点）、验证结果（构建/测试输出）、风险评估（API 兼容性、性能风险）、未完成事项。

## 知识索引

稳定背景知识放在 `docs/knowledge/`。改动前按场景读取对应文件：

### 场景与路径路由

| 场景 | 修改目录 | 先读文档 |
| --- | --- | --- |
| 事件归一化、目标选择、命中测试、坐标转换、分发、合成事件、高频移动/绘制路径 | `service/event_dispatch/`, `service/window_manager/` | `docs/knowledge/input-event-pipeline.md` |
| 显示组、焦点隔离、捕获、axis-end、重分发、默认组回退 | `service/window_manager/`, `service/display_state_manager/` | `docs/knowledge/display-group-model.md` |
| 设备/显示绑定、热插拔、虚拟/远端设备、摇杆、手写板、手写笔、触控板、生命周期清理 | `service/device_manager/`, `service/device_state_manager/` | `docs/knowledge/input-device-scope.md` |
| 鼠标/光标缓存、捕获状态、指针序列、键盘焦点重发、UDS 分发状态、懒分配 | `service/window_manager/` | `docs/knowledge/input-context-state.md` |
| 构建、板侧测试、PR 证据、重构建共享库、公开 API 或配置行为验证 | 任何构建/测试相关改动 | `docs/knowledge/board-verification.md` |

### 开始编辑前

在修改代码前，按以下顺序确认：
1. 确认任务类别
2. 根据上表确定需要阅读的文档
3. 根据"项目约束"确认不违反任何约束
4. 声明："我将修改 X，已阅读 Y 文档，遵循 Z 约束"

## 项目约束

### 性能约束

- 事件分发和光标绘制是高频路径，不要在每次移动或绘制中增加全量扫描、字符串格式化或 INFO 日志。

### 架构约束

- 设备分类的归属规则要保持显式，不要把手写板、手写笔、触控板、远端或虚拟输入规则折叠进通用鼠标/键盘路径。
- 默认组状态只适合默认初始化和明确的遗留 helper。非默认事件链应继续使用已解析上下文或序列快照。
- 可选上下文状态保持懒分配，不要为了普通默认路径预先分配分发或渲染上下文。

### 编码约定

- C++ 改动优先复用附近的 `MMI_HILOG*`、`RET_OK`、`RET_ERR` 等项目宏和返回约定。
- C++ 新增改动进行指针判空时，不要使用`CHKPV*`、`CHKPR*`、`CHKPC*`等改变代码逻辑的宏。

### 公共 API 约束

**Do not（禁止）：**
- 修改已发布的 Native、NAPI、ETS、C API 的签名、参数类型、返回值类型
- 修改已有 API 的错误码，除非明确标注为废弃
- 删除或重命名已有公共 API
- 修改已有 API 的行为语义（如异步变同步、阻塞变非阻塞）

**Ask before（修改前必须确认）：**
- 新增公共 API：确认是否需要 DFX 日志、事件追踪、权限检查
- 修改内部接口：评估是否影响跨模块兼容性
- 修改错误处理逻辑：确认是否影响应用层的错误码兼容性

### 安全与权限边界

**Do not（禁止）：**
- 绕过已有的权限检查逻辑（如 `AccessTokenID` 验证）
- 在未验证的情况下直接使用跨进程传递的文件描述符、共享内存
- 将敏感输入信息（如密码输入）写入非安全的日志
- 修改涉及多用户/多账户访问控制的逻辑，除非经过安全评审

**Ask before（修改前必须确认）：**
- 涉及 `Security::AccessToken` 相关代码的改动
- 涉及跨设备数据传输的改动
- 涉及输入事件重定向到其他应用/用户的改动
- 涉及隐私数据（如指纹、用户名、设备SN等）的处理

### 协议与数据格式兼容性

**Do not（禁止）：**
- 修改 IDL 定义的 IPC 接口签名、Parcel 序列化顺序
- 修改跨进程传递的数据结构布局（如 `struct` 的字段顺序）
- 修改已有事件的类型码、事件数据格式

**Ask before（修改前必须确认）：**
- 新增 IPC 接口：确认是否需要跨版本兼容性处理
- 修改事件类型：确认是否影响事件接收方的兼容性

### 生成代码边界

**Do not（禁止）：**
- 直接修改 IDL 编译器生成的 C++ 代码文件
- 手动编辑生成的 IPC Proxy/Stub 代码

**正确做法：**
- 修改 IDL 定义文件（`*.idl` 或 `*.taihe`）
- 重新运行 IDL 编译器生成代码
- 如果生成代码不满足需求，考虑调整 IDL 定义或使用回调机制

### 设备操作约束

**涉及真实设备时的注意事项：**
- 不执行可能影响设备正常运行的破坏性操作（如强制关闭输入设备）
- 需要在真实设备上验证的改动，必须提供板侧证据（日志、截图、hdc 输出）
- 设备节点的打开/关闭操作需要权限检查
