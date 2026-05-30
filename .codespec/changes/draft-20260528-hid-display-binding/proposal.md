---
target_release: OpenHarmony-master
issue: ""
author: ""
date: "2026-05-28"
status: Draft
---

# Proposal

## 背景与问题

OpenHarmony 多模输入当前已有显示组、窗口组和部分设备/显示绑定能力，但全局非触控输入设备状态仍存在默认组假设。蓝牙/USB HID 标准外设接入多屏场景后，系统服务需要能够把指定设备绑定到指定屏幕所属的 display group，使该设备后续产生的所有事件只在该屏幕组内命中、分发和渲染。

本需求同时触及高频事件分发、光标绘制、设备/显示生命周期和 Inner API 权限。尤其光标存在软光标 RS 链路和硬光标 CPU/HWC buffer + RS buffer 链路，绑定后的 group 上下文必须贯穿事件路由与渲染链路，否则会出现事件分发到目标屏幕但光标仍显示在默认屏幕的问题。

## 初始分级判断

| 判断项 | 结果 | 依据 |
|--------|------|------|
| 复杂度 | 复杂 | 涉及 Inner API、SA IPC、设备/显示生命周期、窗口命中、分发缓存、软/硬光标渲染两条路径 |
| 涉及仓数量 | 1 | 本次限定 `foundation/multimodalinput/input` |
| 是否涉及 Public/System API | 是 | 新增 Inner API，使用系统 API 权限管控；不新增 Public API |
| 是否涉及安全/性能关键路径 | 是 | 权限校验、防止普通应用绑定输入路由；事件分发和光标绘制是高频路径 |
| 是否跨 SIG | 待确认 | 主要在多模输入仓，板侧验证涉及显示/图形栈行为证据 |

## 目标

- 提供 Inner API `BindDeviceToDisplayGroupByDisplay(deviceId, displayId)`，供其他系统服务设置蓝牙/USB HID 标准设备与 `displayId` 所属 display group 的运行时绑定关系。
- 提供 Inner API `UnbindDeviceFromDisplayGroup(deviceId)`，供系统服务主动解除指定设备的运行时绑定关系；生命周期自动清理不能替代显式解绑能力。
- 绑定成功后，该设备产生的按键、鼠标/指针、轴、触控板等非触控 HID 事件只在绑定 display group 内选择焦点、窗口目标、捕获状态和分发目标。
- 设备下线、显示下线、显示组拓扑移除、多模服务 SA 重启时自动解除绑定关系。
- 接口必须使用系统 API 管控，非系统应用或无授权调用返回权限错误，不改变绑定状态。
- 未绑定场景保持现有默认行为，避免为普通路径预分配额外 group 状态或渲染状态。
- 逐点盘点现有 `MAIN_GROUPID`、`DEFAULT_GROUP_ID`、`GetDefaultDisplayGroupInfo`、`GetConstMainDisplayGroupInfo`、`GetDisplayInfoVector()`、`GetWindowInfoVector()`、`GetFocusWindowId()` 等默认组使用点；每个使用点必须明确“保持默认组语义”或“改为绑定事件 resolved group”。
- 验证绑定临界区：未绑定的同类设备继续共享现有默认状态；绑定后按设备所属 group 拆分位置、焦点、按下态、修饰键、光标样式和渲染节点等目标敏感状态。
- 保证事件序列闭环：若绑定前已经向默认组发送开始事件，绑定后的结束事件必须回到原始目标组/窗口，不能把同一未闭环序列拆到两个 display group。
- 窗口级 API 继续按窗口所属 group 天然隔离；全局设置 API 继续仅作用默认屏幕组。
- 软光标和硬光标两条渲染路径均使用绑定后的 group/display 上下文。
- 使用真实 `mmi_service` 完成端到端验证：通过 `/dev/uinput` 构造内核虚拟鼠标/键盘设备，通过监听器获取分发输出，并通过 `hidumper` 输出绑定、状态、RS 与 HWC 参数证据。

## 非目标

- 不新增三方 Public API、NAPI 或 C API。
- 不把触摸屏原生触控事件改为绑定路由；触控屏仍按触摸设备现有显示映射处理。
- 不持久化本次运行时绑定关系到配置文件；SA 重启后绑定关系必须清空。
- 不改变窗口管理传入的 display group 模型，不在输入侧重新定义 display group。
- 不重构全部历史全局 API；仅梳理与本需求相关的事件状态、缓存状态和光标状态。

## 成功标准

| 标准 | 可观察指标 | 验证方式 |
|------|-----------|---------|
| 绑定接口可控 | 系统服务调用蓝牙/USB HID 设备绑定返回 `RET_OK`；非系统应用或无权限调用返回 `ERROR_NO_PERMISSION` | `MMIService`/connect manager 单元测试，权限 mock 覆盖成功和失败分支 |
| 解绑接口可控 | 系统服务调用 `UnbindDeviceFromDisplayGroup(deviceId)` 返回 `RET_OK` 并清理绑定；无权限调用返回 `ERROR_NO_PERMISSION` 且绑定表不变 | `MMIService`/connect manager/window manager 单元测试 |
| 事件仅在绑定组分发 | 绑定设备事件命中绑定 group 的焦点窗口；默认 group 订阅窗口不收到该设备普通分发事件 | `InputWindowsManager` 多 group 单元测试；板侧双屏 HID 验证 |
| 默认组使用点已盘点 | `input_windows_manager.*` 中默认组 helper、`MAIN_GROUPID`、`DEFAULT_GROUP_ID` 使用点有分类结论和测试覆盖 | 代码审查清单；`InputWindowsManagerTest` 多 group 回归 |
| 多设备状态隔离 | 未绑定 A/B 鼠标共享当前位置、颜色、大小、样式、surface node 等现有状态；绑定后 A/B 分别使用各自 group 状态 | 双鼠标双显示组单元测试；软/硬光标测试 |
| 临界区事件闭环 | 键盘/鼠标在绑定前发出 down/start，绑定后 up/end 仍发回原目标；新序列才进入绑定 group | pointer/key sequence snapshot 测试 |
| 生命周期自动解除 | 设备移除、显示移除、SA 重启后查询不到运行时绑定；后续事件回到默认解析路径或返回无绑定 | helper/manager 单元测试；connect manager 不重放该运行时绑定 |
| 未绑定路径零额外常驻状态 | 服务启动和未绑定事件不创建非默认 group 的绑定上下文、光标上下文或分发缓存 | 单元测试检查 lazy map；代码审查确认无构造期预分配 |
| 软/硬光标一致 | 绑定鼠标移动时 RS 软光标、HWC 硬光标 buffer 和 RS buffer 均更新绑定 display | `PointerDrawingManager`/`CursorDrawingComponent` 测试；板侧软/硬光标各一组证据 |
| 兼容性保持 | 窗口级 API 行为不变；全局设置 API 只影响默认 group | 回归现有 `InputWindowsManagerTest`、pointer style/capture 相关测试 |
| 真实服务验证完整 | 真实 `mmi_service` 中虚拟 A/B 鼠标、A/B 键盘和通过 `InputManager::UpdateDisplayInfo` 构造的两个 display group 的 listener 输出与 `hidumper` 状态一致 | `/dev/uinput` 注入、mmi listener 分发记录、`hidumper -s 3101` 多组绑定/状态/RS/HWC 参数输出 |

## 影响范围

| 子系统 | 仓库 | 模块/路径 | 影响类型 |
|--------|------|-----------|---------|
| 多模输入接口 | foundation/multimodalinput/input | `interfaces/native/innerkits/proxy/`, `frameworks/proxy/` | 新增 Inner API 声明和代理调用 |
| 多模输入 SA IPC | foundation/multimodalinput/input | `service/connect_manager/`, `service/module_loader/` | 新增 IPC 方法、权限校验、服务端转发 |
| 窗口/分发管理 | foundation/multimodalinput/input | `service/window_manager/` | 设备到 display group 运行时绑定、目标选择和状态隔离 |
| 设备生命周期 | foundation/multimodalinput/input | `service/window_manager/src/input_windows_manager.cpp`, `InputDisplayBindHelper` | 设备/显示下线清理 |
| 光标渲染 | foundation/multimodalinput/input | `PointerDrawingManager`, `CursorDrawingComponent`, `ScreenPointer` | 软/硬光标按 group/display 更新 |
| Dump/诊断 | foundation/multimodalinput/input | `service/event_dump/`, `InputWindowsManager::Dump`, `InputDeviceManager::Dump`, `PointerDrawingManager::Dump` | 补齐多 display group 下绑定、事件状态、RS/HWC 参数输出 |
| 测试 | foundation/multimodalinput/input | `service/*/test`, `frameworks/proxy/events/test` | 新增权限、绑定、分发、光标、生命周期测试 |

## 假设与开放问题

### 假设
- `displayId` 由调用方传入物理显示 id，输入侧通过现有 `DisplayGroupInfo.displaysInfo` 解析其 display group。
- “HID 标准设备”本次限定连接类型为 USB 或 BLUETOOTH 的非触控外设；设备能力仍通过 `InputDeviceManager` 判定，不把手写板、手写笔、触控板折叠到普通鼠标路径。
- 运行时绑定不写入 `input_device_name.cfg` 或现有持久绑定文件。
- `BindDeviceToDisplayGroupByDisplay` 返回 `RET_OK` 表示绑定关系已生效；同设备重复绑定到新 display 时覆盖旧绑定。

### 开放问题
- 目标权限名沿用现有 `CheckInputDeviceCfg()` 还是新增专用权限，需要接口评审确认。本设计按“系统 API + 现有 INPUT_DEVICE_CONFIGURATOR 权限能力”规划。
- 返回错误码是否需要对“设备不存在/显示不存在/非 USB 或蓝牙 HID”区分精确 ErrCode，当前按 `RET_ERR` + `msg` 兼容现有接口风格规划。

## 不涉及项确认

| 维度 | 是否涉及 | 依据 |
|------|---------|------|
| 性能 | 是 | 高频事件分发和光标绘制必须保持 O(1)/局部查询，不能每次移动全量扫描 |
| 安全/权限 | 是 | 绑定输入路由会影响其他屏幕输入归属，必须系统 API 管控 |
| 兼容性 | 是 | 未绑定路径、窗口级 API、全局 API 默认组行为必须保持 |
| API/SDK | 是 | 新增 Inner API，不新增 Public API |
| IPC/跨进程 | 是 | 通过 `IMultimodalInputConnect` 调用 SA |
| 构建/组件 | 视情况 | 可能涉及 IDL 生成和测试目标更新 |
| 国际化/无障碍 | 否 | 不新增可见 UI 文案 |
| 数据迁移 | 否 | 运行时绑定不持久化 |
