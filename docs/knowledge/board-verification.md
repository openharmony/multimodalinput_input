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
