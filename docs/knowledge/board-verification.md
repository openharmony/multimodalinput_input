# 板侧验证知识

本文记录多模输入变更需要板侧证据时的稳定做法。

## 构建位置

OpenHarmony 构建命令从源码根目录执行：

```sh
cd <openharmony-source-root>
prebuilts/build-tools/linux-x86/bin/ninja -C out/rk3568 InputWindowsManagerTest
```

涉及分发、窗口管理、指针绘制、设备绑定或公开行为时，构建服务或相关测试目标。

## 何时需要板侧证据

| 变更类型 | 最低证据 |
| --- | --- |
| 分发、焦点、目标、捕获、重分发 | 构建并运行最近的窗口/分发目标；涉及 UDS 或真实窗口时增加板侧运行。 |
| 指针绘制或光标渲染 | 构建绘制目标；涉及 surface、RS、硬光标或屏幕状态时在板侧运行。 |
| 设备绑定或热插拔 | 构建设备/绑定目标；需要物理设备或显示拓扑时在板侧运行。 |
| 公开 API 兼容性 | 构建并运行 API 测试；API 触达服务状态时增加板侧证据。 |
| 仅配置解析 | 除非运行时行为变化，否则运行解析器或最近单元测试即可。 |

## 板侧运行方式

把测试二进制和本地重构建共享库推到同一临时目录，并让该目录排在 `LD_LIBRARY_PATH` 最前：

```sh
hdc file send out/rk3568/tests/unittest/input/input/InputWindowsManagerTest <device-temp-dir>/
hdc shell "cd <device-temp-dir> && LD_LIBRARY_PATH=<device-temp-dir>:/system/lib:/vendor/lib ./InputWindowsManagerTest"
```

记录板侧镜像、产品、测试命令、gtest filter、通过/失败数量和已知环境问题。不要把 `hdc`、权限、surface、窗口创建或服务启动失败报成行为通过。

## 场景化验证

单元测试无法覆盖设备注入、显示拓扑、窗口层级或已渲染光标状态时，使用服务集成场景：

- 输入设备场景通过 `/dev/uinput` 创建虚拟设备，并通过该设备写入事件。
- 多屏或多显示组窗口层级通过 `InputManager::UpdateDisplayInfo` 构造。
- 输出事件通过向 `mmi_service` 注册监听器检查。
- 光标输出先用 `hidumper` 检查绘制参数；参数正确后，可用截图辅助确认样式、大小和颜色。

## API 行为陷阱

板侧验证中易踩的非显然行为，按子系统分类：

### 显示组与窗口

- `UpdateDisplayInfo` 成功时返回 `-201`，不是 `0`。不要将非零返回值当作失败。
- `GetDeviceIds` / `GetDevice` 是**异步回调** API，不能直接取返回值。必须传 `std::function` 回调并用 `condition_variable` 等待结果。

### 鼠标与光标

- 光标钳制范围是 `[0, dimension]` **含端点**（如 720×1280 屏幕，Y 最大值为 1280 而非 1279）。`cursorPos` 和 `mouseLocation` 可能差 1（cursorPos 含端点，mouseLocation 不含）。
- 滚轮事件产生 `POINTER_ACTION_AXIS_BEGIN`(5) + `POINTER_ACTION_AXIS_END`(7)，**没有** `POINTER_ACTION_AXIS_UPDATE`(6)。

### 触控板

- `TouchpadTransformProcessor` 将触控板手势转换为 `SOURCE_TYPE_MOUSE`(1)，**不是** `SOURCE_TYPE_TOUCHPAD`(3)。验证触控板路由时需接受两种 sourceType。
- 创建 uinput 触控板必须用 `UI_ABS_SETUP` + `UI_DEV_SETUP`（ioctl 方式），不能用 legacy `uinput_user_dev` 结构体。需要设置 `INPUT_PROP_POINTER` + `INPUT_PROP_BUTTONPAD`。
- libinput 触控板手势识别需要多帧连续手指运动（单帧触摸不产生指针移动事件）。

### 键盘

- 键盘 repeat 由服务端 `KeyAutoRepeat` 定时器驱动（默认 delay=500ms, rate=50ms），不是内核 `EV_REP`。Repeat 事件以 `KEY_ACTION_DOWN` + `IsRepeat()=true` 形式投递。API 层没有 `KEY_ACTION_REPEAT` 常量。
- 长按测试需持续 ≥1500ms 才能稳定触发 repeat（500ms delay + 调度延迟）。

### 设备状态

- 测试运行后 `MouseDownState` 条目会残留。**两次运行之间必须重启设备**（`hdc shell reboot`），否则绑定操作返回 `-1`。
- 设备热拔（关闭 uinput fd）后，服务自动清理对应绑定条目，约需 1-2 秒生效。

## PR 证据模板

```text
构建：
- 产品：rk3568
- 目标：<目标名称>
- 结果：<通过/失败，已检查命令输出>

板侧：
- 设备/镜像：<相关时填写标识>
- 推送文件：<测试二进制和重构建库>
- 命令：<精确的 hdc shell 命令或 gtest 过滤器>
- 结果：<通过/失败数量>
- 环境说明：<无，或已知设置/环境问题>
```
