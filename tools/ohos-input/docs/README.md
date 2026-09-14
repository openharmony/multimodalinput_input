# ohos-input

## 概述

面向 AI Agent 应用的键鼠输入模拟工具。基于 multimodalinput 部件内建 Controller 接口（MouseController / KeyboardController）模拟鼠标点击、双击、滚动、移动、拖动与键盘按键等输入操作，输出统一 JSON 结果，供自动化框架解析。仅支持 PC（2in1）设备形态部署。

## 功能列表

- **模拟鼠标单击**：在指定坐标模拟一次鼠标点击，支持按键选择与修饰键组合
- **模拟鼠标双击**：两次完整点击，按下间隔可配置
- **模拟鼠标滚轮垂直滚动**：按齿数滚动，1 齿 = 15 度，正数向上、负数向下
- **移动鼠标光标**：将光标移动到指定显示器的指定位置
- **模拟鼠标拖动**：按住按键从起点拖至终点，支持跨显示器与按时长插值步进
- **模拟键盘按键**：按 OHOS 键码注入按键，支持 ctrl/alt/shift/meta 修饰键组合

## 依赖

### 系统能力

- `InputManager` - Controller 创建入口（libmmi-client 内建接口）
- `MouseController` - 鼠标事件注入（移动、按键、滚轮轴会话）
- `KeyboardController` - 键盘事件注入（按键按下与抬起）

### 权限

| 权限 | 命令 | 说明 |
|-----------|----------|-------------|
| `ohos.permission.CONTROL_DEVICE` | 全部命令 | Controller 创建与逐事件注入的权限校验 |

权限校验在 Controller 创建时由输入服务完成，之后对每个注入的 Controller 事件再次校验；权限不足时命令以退出码 3 失败。

## 基本用法

```bash
ohos-input <subcommand> [options]
ohos-input --help
ohos-input --version
ohos-input <subcommand> --help
```

## 命令列表

| 命令 | 说明 | 参数 | 权限 | 前置依赖 |
|---------|-------------|------------|-------------|--------------|
| mouse-click | 模拟鼠标单击 | `--x --y`（必填）；`--displayId --button --holdDuration --modifier`（可选） | `ohos.permission.CONTROL_DEVICE` | 无 |
| mouse-double-click | 模拟鼠标双击 | 同 mouse-click，另加 `--clickInterval`（可选） | `ohos.permission.CONTROL_DEVICE` | 无 |
| mouse-scroll | 模拟鼠标滚轮垂直滚动 | `--clicks`（必填）；`--modifier`（可选） | `ohos.permission.CONTROL_DEVICE` | 无 |
| mouse-move | 移动鼠标光标到指定位置 | `--x --y`（必填）；`--displayId --modifier`（可选） | `ohos.permission.CONTROL_DEVICE` | 无 |
| mouse-drag | 模拟鼠标拖动（支持跨显示器） | `--srcX --srcY --dstX --dstY`（必填）；`--srcDisplayId --dstDisplayId --button --duration --modifier`（可选） | `ohos.permission.CONTROL_DEVICE` | 无 |
| key-press | 模拟键盘按键 | `--key`（必填）；`--holdDuration --modifier`（可选） | `ohos.permission.CONTROL_DEVICE` | 无 |

**前置依赖说明**：
- **无**：命令可直接执行，无需前置条件；执行时由 CLI 自动创建所需 Controller（提供 `--modifier` 时额外创建键盘 Controller）

## 参数说明

### mouse-click

```
ohos-input mouse-click [options]
  --displayId <number>    显示器 ID（可选，>=0，默认 0）
  --x <integer>           目标 X 坐标（必填整数，>=0）
  --y <integer>           目标 Y 坐标（必填整数，>=0）
  --button <key>          鼠标按键（可选，left/right/middle，默认 left）
  --holdDuration <number> 按下持续时间 ms（可选，[50,200]，默认 100）
  --modifier <keys>       修饰键（可选，ctrl/alt/shift/meta，多个用 | 分隔，不可重复）
```

### mouse-double-click

同 mouse-click，另增加：

```
  --clickInterval <number> 第一次按下到第二次按下的间隔 ms（可选，[100,400]，须大于 holdDuration，默认 250）
```

### mouse-scroll

```
ohos-input mouse-scroll [options]
  --clicks <number>       滚动齿数（必填，[-100,-1] 或 [1,100]，正数向上、负数向下，1 齿 = 15 度）
  --modifier <keys>       修饰键（可选）
```

### mouse-move

```
ohos-input mouse-move [options]
  --displayId <number>    显示器 ID（可选，>=0，默认 0）
  --x <integer>           目标 X 坐标（必填整数，>=0）
  --y <integer>           目标 Y 坐标（必填整数，>=0）
  --modifier <keys>       修饰键（可选）
```

### mouse-drag

```
ohos-input mouse-drag [options]
  --srcDisplayId <number> 源显示器 ID（可选，>=0，默认 0）
  --srcX/--srcY <integer> 起点 X/Y 坐标（必填整数，>=0）
  --dstDisplayId <number> 目标显示器 ID（可选，>=0，默认 0）
  --dstX/--dstY <integer> 终点 X/Y 坐标（必填整数，>=0）
  --button <key>          拖动按住的按键（可选，默认 left）
  --duration <number>     总时长 ms（可选，[0,10000]，0 表示瞬间完成，默认 0；>0 时按 16ms 步进插值）
  --modifier <keys>       修饰键（可选）
```

源显示器与目标显示器不同时，两端点换算为全局坐标后插值注入，由输入服务选择实际显示器；同显示器拖动走显示器坐标路径。

### key-press

```
ohos-input key-press [options]
  --key <number>          OHOS 键码（必填，>=1，如 2049=A、2054=回车）
  --holdDuration <number> 按下持续时间 ms（可选，[0,10000]，0 表示瞬间抬起，默认 100）
  --modifier <keys>       修饰键（可选；修饰键+目标键总数不超过 5）
```

修饰键仅支持 `ctrl` / `alt` / `shift` / `meta`（映射 LEFT 变体键码 2072/2045/2047/2076），按下顺序为书写顺序，抬起顺序为逆序；`--key` 键码不得与已选修饰键键码重复。

## 输出格式

所有命令将 JSON 输出到 stdout，结构如下：

### 成功响应

```json
{
  "type": "result",
  "status": "success",
  "data": {
    // 命令特定数据（action 及对应坐标/键码等）
  }
}
```

### 失败响应

```json
{
  "type": "result",
  "status": "failed",
  "errCode": "ERR_XXX",
  "errMsg": "错误描述",
  "suggestion": "建议的下一步操作"
}
```

### 错误码

| 错误码 | 退出码 | 说明 |
|------------|---------|-------------|
| `ERR_INPUT_SERVICE_EXCEPTION` (3800001) | 1 | 输入服务异常（服务未运行、注入失败、运行期状态错误） |
| `ERR_PARAMETER_ERROR` (401) | 2 | 参数校验失败（前置拦截，不发起 IPC） |
| `ERR_PERMISSION_DENIED` (201) | 3 | 权限不足（未持有 ohos.permission.CONTROL_DEVICE） |

## 示例

### mouse-click

```bash
# 单击 (100, 200)
ohos-input mouse-click --x 100 --y 200

# Ctrl+单击 (300, 400)，按住 100ms
ohos-input mouse-click --x 300 --y 400 --holdDuration 100 --modifier ctrl

# 输出示例：
{"type":"result","status":"success","data":{"action":"mouse-click","displayId":0,"x":100,"y":200}}
```

### mouse-double-click

```bash
# 右键双击，自定义间隔
ohos-input mouse-double-click --x 100 --y 200 --button right --holdDuration 100 --clickInterval 200

# 输出示例：
{"type":"result","status":"success","data":{"action":"mouse-double-click","displayId":0,"x":100,"y":200}}
```

### mouse-scroll

```bash
# 向下滚动 3 齿（1 齿 = 15 度）
ohos-input mouse-scroll --clicks -3

# Ctrl+向上滚动 5 齿
ohos-input mouse-scroll --clicks 5 --modifier ctrl

# 输出示例：
{"type":"result","status":"success","data":{"action":"mouse-scroll","clicks":-3}}
```

### mouse-move

```bash
# 移动光标到 (100, 200)
ohos-input mouse-move --x 100 --y 200

# 移动光标到 1 号显示器 (100, 200)
ohos-input mouse-move --displayId 1 --x 100 --y 200

# 输出示例：
{"type":"result","status":"success","data":{"action":"mouse-move","displayId":1,"x":100,"y":200}}
```

### mouse-drag

```bash
# 左键从 (100,100) 拖动到 (300,300)，历时 500ms
ohos-input mouse-drag --srcX 100 --srcY 100 --dstX 300 --dstY 300 --duration 500

# 跨显示器拖动
ohos-input mouse-drag --srcDisplayId 0 --srcX 100 --srcY 100 --dstDisplayId 1 --dstX 200 --dstY 200 --duration 500

# 输出示例：
{"type":"result","status":"success","data":{"action":"mouse-drag","srcDisplayId":0,"srcX":100,"srcY":100,"dstDisplayId":0,"dstX":300,"dstY":300}}
```

### key-press

```bash
# 按下回车键（默认按住 100ms）
ohos-input key-press --key 2054

# Ctrl+A（全选）
ohos-input key-press --key 2049 --modifier ctrl

# Ctrl+Shift+S（按下顺序 ctrl、shift；抬起顺序 shift、ctrl）
ohos-input key-press --key 2066 --modifier ctrl|shift

# 输出示例：
{"type":"result","status":"success","data":{"action":"key-press","key":2049}}
```

## 典型工作流

```bash
# 1. 移动光标到目标位置
ohos-input mouse-move --x 100 --y 200

# 2. 单击选中对象
ohos-input mouse-click --x 100 --y 200

# 3. 双击打开
ohos-input mouse-double-click --x 100 --y 200

# 4. Ctrl+A 全选
ohos-input key-press --key 2049 --modifier ctrl

# 5. 滚动浏览内容
ohos-input mouse-scroll --clicks -3

# 6. 拖动对象到新位置
ohos-input mouse-drag --srcX 100 --srcY 100 --dstX 300 --dstY 300 --duration 500
```

## 安装

- 可执行文件：`/system/bin/cli_tool/executable/ohos-input`
- 描述文件：`/system/bin/cli_tool/configs/ohos-input.json`（由构建系统从本仓 ohos-input.json 自动部署）

## 构建配置

- **构建目标**：`ohos-input`
- **子系统**：`multimodalinput`
- **部件**：`input`
- **门控开关**：gn 变量 `input_controller_inject_enable`（默认 false），PC 产品配置中开启后编译
