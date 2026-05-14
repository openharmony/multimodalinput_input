# 板侧验证知识

本文记录多模输入变更中稳定的板侧验证实践。

## 构建位置

OpenHarmony 构建命令需要在 OpenHarmony 源码根目录执行：

```sh
cd <openharmony-source-root>
```

常用增量构建命令：

```sh
prebuilts/build-tools/linux-x86/bin/ninja -C out/rk3568 InputWindowsManagerTest
```

当变更涉及分发、窗口管理、指针绘制、设备绑定或公开行为时，需要构建服务或相关测试目标。

## 目标选择

优先选择能覆盖变更行为的最小目标集合；当行为依赖真实窗口、显示、设备、图形或服务集成时，再补充板侧运行。

- 事件分发或事件处理：`EventDispatchTest`、`EventHandlerTest`、`InputEventHandlerTest`，以及相关 subscriber/interceptor/monitor 目标。
- 窗口命中、焦点、捕获、重分发、取消或 axis-end：`InputWindowsManagerTest`、`InputWindowsManagerEXTest`、`InputWindowsManagerCoverageTest` 或 `InputWindowsManagerOneTest`。
- 显示/设备绑定：`InputDisplayBindHelperTest`、`InputDisplayBindHelperBranchStandaloneTest`、`DeviceManagerTest`、`DeviceManagerExTest`、`InputDeviceManagerTestWithMock` 或 `DeviceStateManagerTest`。
- 指针绘制、光标渲染和序列缓存：`PointerDrawingManagerTest`、`PointerDrawingManagerExTest`、`PointerDrawingManagerSupTest`、`PointerDrawingManagerHardCursorTest`、`CursorDrawingComponentTest`、`CursorDrawingComponentCoverageTest` 或 `PointerDispatchEventCacheStandaloneTest`。
- 鼠标、触摸、触控板、手写板和遥控转换：就近选择 `MouseEventNormalize*`、`TouchEventNormalize*`、`Touchpad*`、`TabletToolTransformTest` 或 `RemoteControlTransformProcessorTestWithMock` 目标。
- Native API 兼容性：`InputNativeTest` 或 `InputNativeHotkeyTest`。

## 何时需要板侧证据

当变更影响依赖真实服务、显示服务、输入设备栈、图形表面或 UDS 投递路径的行为时，应提供板侧证据。纯解析器、helper 或 API 参数校验变更若不跨越这些边界，通常单元测试证据即可。

| 变更类型 | 最低证据 |
| --- | --- |
| 分发、焦点、目标、捕获、重分发 | 构建并运行最接近的窗口/分发目标；涉及 UDS 或真实窗口时增加板侧运行。 |
| 指针绘制或光标渲染 | 构建绘制目标；涉及 surface、RS、硬光标或屏幕状态时在板侧运行。 |
| 设备绑定或热插拔 | 构建设备/绑定目标；需要物理设备或显示拓扑时在板侧运行。 |
| 公开 API 兼容性 | 构建并运行 API 测试；API 触达服务状态时增加板侧证据。 |
| 仅配置解析 | 除非运行时行为变化，否则构建并运行解析器或最接近的单元目标。 |

## 板侧测试流程

使用 `hdc` 推送目标测试二进制，以及它依赖的本地重构建共享库。在板侧临时目录运行测试，并让 `LD_LIBRARY_PATH` 先指向该临时目录，再指向系统和 vendor 库路径。

示例形态：

```sh
hdc file send out/rk3568/tests/unittest/input/input/InputWindowsManagerTest <device-temp-dir>/
hdc shell "cd <device-temp-dir> && LD_LIBRARY_PATH=<device-temp-dir>:/system/lib:/vendor/lib ./InputWindowsManagerTest"
```

如果单元测试链接了本地重构建的服务库，需要把这些库和测试二进制放在同一目录，并把该临时目录放在 `LD_LIBRARY_PATH` 最前面。若测试依赖系统图形、窗口管理器或输入服务状态，需要记录板侧镜像、产品和复现运行所需的设置命令。

## 场景化验证

当单元测试无法覆盖设备注入、显示拓扑、窗口层级或已渲染光标状态时，使用服务集成场景验证。

- 输入设备场景应通过 `/dev/uinput` 创建虚拟设备，再通过该虚拟设备写入事件，不要直接调用更底层的 handler。
- 多屏或多显示组窗口层级场景应通过 `InputManager::UpdateDisplayInfo` 构造拓扑，使焦点、分组和显示路由走服务路径。
- 输出事件检查应向 `mmi_service` 注册监听器，并断言该监听器观察到的事件流。
- 光标输出检查应优先使用 `hidumper` 检查绘制参数。当 `hidumper` 输出正确后，可以把截图作为光标样式、大小和颜色的辅助证据。

## 常见环境失败

不要把环境失败包装成测试通过。若环境失败与被评审行为无关，需要单独说明：

- `hdc` 连接或设备授权失败。
- 板上缺少测试二进制或共享库。
- `LD_LIBRARY_PATH` 中系统库排在重构建库之前。
- 指针绘制测试中的图形、surface 或窗口创建失败。
- 被测代码运行前发生权限、SELinux 或服务启动失败。
- GTest 过滤器没有匹配任何测试。

## 需要记录的证据

对于影响输入分发、设备绑定、窗口管理器或指针绘制的 PR，需要记录：

- 构建目标名称和结果。
- 相关时记录板侧设备标识。
- 精确的测试二进制和 gtest 过滤器。
- 通过和失败的测试数量。
- 已知环境失败，尤其是指针绘制测试中的图形或 surface 失败。

除非命令已经完成且相关输出已检查，否则不要报告测试通过。

## 证据反模式

- 只因二进制启动了，就报告测试通过，但没有检查 gtest 汇总。
- 只运行了测试子集，却省略 gtest 过滤器。
- 代码或重构建库变更后复用旧的板侧结果。
- 忘记为链接服务的单元测试推送重构建共享库。
- 把图形、surface、权限或 `hdc` 失败当作行为成功。
- 只写“built input”，但实际变更对应的单元目标没有构建。

## PR 证据模板

需要板侧验证时，PR 说明可使用以下形态：

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
