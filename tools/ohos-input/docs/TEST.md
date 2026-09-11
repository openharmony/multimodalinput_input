# ohos-input 测试用例

## 测试覆盖概览

| 分类 | 测试数量 | 覆盖命令 |
|----------|------------|------------------|
| 修饰键测试 | 4 | 所有（修饰键解析，前置拦截） |
| 选项解析测试 | 10 | 所有（选项白名单与数值规则） |
| 注册表测试 | 3 | 所有（命令注册与查找） |
| 输出打印测试 | 5 | 所有（JSON 输出格式验证） |
| 错误处理测试 | 2 | 所有（错误码验证） |
| 执行器测试 | 15 | 所有（命令注册、帮助路由、版本） |
| 鼠标支持测试 | 5 | mouse click / scroll（齿数与按键名验证） |
| 拖拽命令测试 | 5 | mouse drag（插值步进验证） |
| 集成测试 | 13 | 所有 6 个命令（mock Controller 工作流验证） |
| 控制器工厂测试 | 6 | 所有（Controller 创建契约） |
| **总计** | **68** | **所有 6 个命令** |

## 命令测试矩阵

### mouse click

| 测试用例 | 命令示例 | 说明 | 权限 | 前置依赖 | 预期结果 |
|-----------|-----------------|-------------|------------|------------|-----------------|
| 默认单击 | `ohos-input mouse click --x 100 --y 200` | 在 (100,200) 模拟左键单击 | `ohos.permission.CONTROL_DEVICE` | 无 | 成功：`{type:"result",status:"success",data:{action:"mouse click",displayId:0,x:100,y:200}}` |
| 全参数单击 | `ohos-input mouse click --x 300 --y 400 --displayId 1 --button right --holdDuration 100 --modifier ctrl` | 显示器/按键/时长/修饰键组合 | `ohos.permission.CONTROL_DEVICE` | 无 | 成功：data 含 `displayId:1` 与坐标 |
| 多修饰键 | `ohos-input mouse click --x 100 --y 200 --modifier ctrl\|shift` | 两个修饰键组合，按下为书写顺序、抬起为逆序 | `ohos.permission.CONTROL_DEVICE` | 无 | 成功 |
| 缺少必填参数 | `ohos-input mouse click --x 100` | 缺少 `--y` | 无 | 无 | 失败：`ERR_PARAMETER_ERROR` (401)，退出码 2 |
| 无效按键 | `ohos-input mouse click --x 100 --y 200 --button side` | 按键不在 left/right/middle 之内 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2 |
| 时长越界 | `ohos-input mouse click --x 100 --y 200 --holdDuration 300` | 超出 [50,200] 上界 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2 |
| 未知选项 | `ohos-input mouse click --x 1 --y 2 --unknown 3` | 选项不在白名单 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2 |
| 修饰键重复 | `ohos-input mouse click --x 1 --y 2 --modifier ctrl\|ctrl` | 修饰键不可重复 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2 |

### mouse double-click

| 测试用例 | 命令示例 | 说明 | 权限 | 前置依赖 | 预期结果 |
|-----------|-----------------|-------------|------------|------------|-----------------|
| 全参数双击 | `ohos-input mouse double-click --x 100 --y 200 --button right --holdDuration 100 --clickInterval 200` | 自定义间隔的右键双击 | `ohos.permission.CONTROL_DEVICE` | 无 | 成功：`data:{action:"mouse double-click",displayId:0,x:100,y:200}` |
| 间隔约束 | `ohos-input mouse double-click --x 1 --y 1 --holdDuration 250 --clickInterval 200` | clickInterval 必须大于 holdDuration | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2 |
| 间隔越界 | `ohos-input mouse double-click --x 1 --y 1 --clickInterval 500` | 超出 [100,400] 上界 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2 |
| 缺少坐标 | `ohos-input mouse double-click` | 必填 `--x --y` 缺失 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2 |

### mouse scroll

| 测试用例 | 命令示例 | 说明 | 权限 | 前置依赖 | 预期结果 |
|-----------|-----------------|-------------|------------|------------|-----------------|
| 向下滚动 | `ohos-input mouse scroll --clicks -3` | 向下 3 齿（1 齿 = 15 度） | `ohos.permission.CONTROL_DEVICE` | 无 | 成功：`data:{action:"mouse scroll",clicks:-3}` |
| 向上滚动加修饰键 | `ohos-input mouse scroll --clicks 5 --modifier ctrl` | Ctrl+向上 5 齿 | `ohos.permission.CONTROL_DEVICE` | 无 | 成功 |
| 零齿数 | `ohos-input mouse scroll --clicks 0` | 非零校验 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2 |
| 齿数越界 | `ohos-input mouse scroll --clicks 101` | 超出 [-100,100] 取值上界 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2 |

### mouse move-to

| 测试用例 | 命令示例 | 说明 | 权限 | 前置依赖 | 预期结果 |
|-----------|-----------------|-------------|------------|------------|-----------------|
| 移动光标 | `ohos-input mouse move-to --x 100 --y 200` | 移动到 0 号显示器 (100,200) | `ohos.permission.CONTROL_DEVICE` | 无 | 成功：`data:{action:"mouse move-to",displayId:0,x:100,y:200}` |
| 指定显示器 | `ohos-input mouse move-to --displayId 1 --x 100 --y 200` | 移动到 1 号显示器 | `ohos.permission.CONTROL_DEVICE` | 无 | 成功：data 含 `displayId:1` |
| 缺少参数 | `ohos-input mouse move-to --x 100` | 缺少 `--y` | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2 |

### mouse drag

| 测试用例 | 命令示例 | 说明 | 权限 | 前置依赖 | 预期结果 |
|-----------|-----------------|-------------|------------|------------|-----------------|
| 同屏按时长拖拽 | `ohos-input mouse drag --srcX 100 --srcY 100 --dstX 300 --dstY 300 --duration 500` | 左键 500ms 插值拖拽（16ms 步进） | `ohos.permission.CONTROL_DEVICE` | 无 | 成功：data 含 src/dst 全部坐标 |
| 跨显示器拖拽 | `ohos-input mouse drag --srcDisplayId 0 --srcX 100 --srcY 100 --dstDisplayId 1 --dstX 200 --dstY 200 --duration 500` | 两端点换算全局坐标后插值注入 | `ohos.permission.CONTROL_DEVICE` | 多显示器环境 | 成功 |
| 瞬间拖拽 | `ohos-input mouse drag --srcX 1 --srcY 1 --dstX 2 --dstY 2` | 默认 duration 0，瞬间完成 | `ohos.permission.CONTROL_DEVICE` | 无 | 成功 |
| 时长越界 | `ohos-input mouse drag --srcX 1 --srcY 1 --dstX 2 --dstY 2 --duration 10001` | 超出 [0,10000] 上界 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2 |
| 缺少终点坐标 | `ohos-input mouse drag --srcX 1 --srcY 1` | 必填 `--dstX --dstY` 缺失 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2 |

### key press

| 测试用例 | 命令示例 | 说明 | 权限 | 前置依赖 | 预期结果 |
|-----------|-----------------|-------------|------------|------------|-----------------|
| 回车键 | `ohos-input key press --key 2054` | 按下回车，默认按住 100ms | `ohos.permission.CONTROL_DEVICE` | 无 | 成功：`data:{action:"key press",key:2054}` |
| Ctrl+A 组合 | `ohos-input key press --key 2049 --modifier ctrl` | 全选 | `ohos.permission.CONTROL_DEVICE` | 无 | 成功：data 含 `key:2049` |
| 三键组合 | `ohos-input key press --key 2066 --modifier ctrl\|shift` | 按下为书写顺序，抬起为逆序 | `ohos.permission.CONTROL_DEVICE` | 无 | 成功 |
| 键码重复 | `ohos-input key press --key 2072 --modifier ctrl` | 2072 为 ctrl 修饰键码，不得重复 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2 |
| 键码越界 | `ohos-input key press --key 0` | 键码须 ≥1 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2 |
| 时长越界 | `ohos-input key press --key 2049 --holdDuration 10001` | 超出 [0,10000] 上界 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2 |

### 帮助命令

| 测试用例 | 命令示例 | 说明 | 权限 | 前置依赖 | 预期结果 |
|-----------|-----------------|-------------|------------|------------|-----------------|
| 全局帮助 | `ohos-input --help` | 显示顶层帮助 | 无 | 无 | 帮助文本输出到 stdout（非 JSON 格式） |
| 空参数 | `ohos-input` | 无参数调用 | 无 | 无 | 帮助文本输出到 stdout（非 JSON 格式） |
| 版本号 | `ohos-input --version` | 输出版本字符串 | 无 | 无 | 版本号输出到 stdout（非 JSON 格式） |
| 设备帮助 | `ohos-input mouse --help` | 显示 mouse 子命令帮助 | 无 | 无 | 帮助文本输出到 stdout（非 JSON 格式） |
| 仅设备名 | `ohos-input mouse` | 缺少动作子命令 | 无 | 无 | 设备帮助输出到 stdout（非 JSON 格式） |
| 动作帮助 | `ohos-input mouse click --help` | 显示 click 选项帮助 | 无 | 无 | 帮助文本输出到 stdout（非 JSON 格式） |
| 选项中帮助 | `ohos-input mouse click --x 1 --help` | `--help` 可出现在选项任意位置 | 无 | 无 | 帮助文本输出到 stdout（非 JSON 格式），不创建 Controller |

### 错误场景

| 测试用例 | 命令示例 | 说明 | 权限 | 前置依赖 | 预期结果 |
|-----------|-----------------|-------------|------------|------------|-----------------|
| 未知设备 | `ohos-input touchscreen click --x 1 --y 1` | 设备名无效 | 无 | 无 | 失败：`{type:"result",status:"failed",errCode:"ERR_PARAMETER_ERROR",errMsg:"Unknown command: touchscreen",suggestion:"..."}` |
| 未知动作 | `ohos-input mouse hover` | 动作名无效 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`（"Unknown command: hover"），退出码 2 |
| 权限拒绝 | Controller 创建返回 -201 | 未持有 CONTROL_DEVICE | `ohos.permission.CONTROL_DEVICE` | 无 | 失败：`ERR_PERMISSION_DENIED`，退出码 3 |
| 服务异常 | 注入调用返回非 0 | 输入服务运行期失败 | `ohos.permission.CONTROL_DEVICE` | 服务运行 | 失败：`ERR_INPUT_SERVICE_EXCEPTION`，退出码 1 |

## 集成测试工作流

### 工作流 1：基础操作序列

```bash
# 1. 移动光标到目标位置
ohos-input mouse move-to --x 100 --y 200

# 2. 单击选中对象
ohos-input mouse click --x 100 --y 200

# 3. 双击打开
ohos-input mouse double-click --x 100 --y 200

# 4. Ctrl+A 全选
ohos-input key press --key 2049 --modifier ctrl

# 5. 滚动浏览内容
ohos-input mouse scroll --clicks -3

# 6. 拖拽对象到新位置
ohos-input mouse drag --srcX 100 --srcY 100 --dstX 300 --dstY 300 --duration 500
```

### 工作流 2：跨显示器拖拽

```bash
# 1. 移动光标到 0 号显示器起点
ohos-input mouse move-to --displayId 0 --x 100 --y 100

# 2. 跨显示器拖拽到 1 号显示器
ohos-input mouse drag --srcDisplayId 0 --srcX 100 --srcY 100 --dstDisplayId 1 --dstX 200 --dstY 200 --duration 500

# 3. 在目标显示器双击确认
ohos-input mouse double-click --displayId 1 --x 200 --y 200
```

### 工作流 3：键盘输入场景

```bash
# 1. 单击定位输入框
ohos-input mouse click --x 100 --y 200

# 2. Ctrl+A 全选已有内容
ohos-input key press --key 2049 --modifier ctrl

# 3. 输入字母 A（覆盖）
ohos-input key press --key 2049

# 4. 回车提交
ohos-input key press --key 2054
```

## 参数验证测试

### 数值参数值域

| 参数 | 适用命令 | 合法范围 | 默认值 | 非法示例 |
|-----------|-----------------|-------------|-------|-------------|
| `--x` / `--y` | click、double-click、move-to | 整数，[0, INT32_MAX] | 必填 | `-1`、非数字、缺失 |
| `--srcX` / `--srcY` / `--dstX` / `--dstY` | drag | 整数，[0, INT32_MAX] | 必填 | `-1`、缺失 |
| `--displayId` / `--srcDisplayId` / `--dstDisplayId` | click、move-to、drag | 整数，≥0 | 0 | `-1` |
| `--button` | click、double-click、drag | left / right / middle | left | `side` |
| `--holdDuration`（鼠标） | click、double-click | [50, 200] ms | 100 | `49`、`201`、`300` |
| `--holdDuration`（键盘） | key press | [0, 10000] ms | 100 | `10001` |
| `--clickInterval` | double-click | [100, 400] ms 且 > holdDuration | 250 | `99`、`401`、`200`（当 holdDuration=250） |
| `--clicks` | scroll | [-100,-1] ∪ [1,100] 齿 | 必填 | `0`、`101`、`-101` |
| `--duration` | drag | [0, 10000] ms（0 表示瞬间完成） | 0 | `10001`、`-1` |
| `--key` | key press | 整数 ≥1（如 2049=A、2054=回车） | 必填 | `0`、与修饰键键码重复 |

### 修饰键取值

| 修饰键 | 映射键码（LEFT 变体） | 说明 |
|-----------|--------------------------|-------------|
| ctrl | 2072 | 多个修饰键用 `\|` 分隔，不可重复；仅支持 ctrl/alt/shift/meta |
| alt | 2045 | key press 中修饰键+目标键总数不超过 5 |
| shift | 2047 | 按下顺序为书写顺序，抬起为逆序 |
| meta | 2076 | `--key` 键码不得与已选修饰键键码重复 |

## JSON 输出验证

命令执行结果输出 JSON 结构：

```json
// 成功格式
{
  "type": "result",
  "status": "success",
  "data": { ... }
}

// 失败格式
{
  "type": "result",
  "status": "failed",
  "data": "",
  "errCode": "ERR_XXX",
  "errMsg": "...",
  "suggestion": "..."
}
```

**验证检查项**：
- `type` 字段始终等于 `"result"`
- `status` 为 `"success"` 或 `"failed"`（不是 `"error"`）
- 失败响应的 `data` 字段为空字符串 `""`
- 失败响应必须包含 `errCode`、`errMsg`、`suggestion`
- 所有 JSON 输出不使用缩进（紧凑格式）
- 帮助/版本输出为纯文本格式，非 JSON 结构

### 错误码与退出码映射

| 错误码 | 数值码 | 退出码 | 触发场景 |
|------------|---------|---------|-------------|
| `ERR_INPUT_SERVICE_EXCEPTION` | 3800001 | 1 | 输入服务异常（服务未运行、注入失败、运行期状态错误） |
| `ERR_PARAMETER_ERROR` | 401 | 2 | 参数校验失败（前置拦截，不发起 IPC）、未知命令 |
| `ERR_PERMISSION_DENIED` | 201 | 3 | 未持有 ohos.permission.CONTROL_DEVICE |

## 测试执行

```bash
# 构建测试
cd /home/hyh/workspace/cli_creator
hb build input -t --gn-args input_controller_inject_enable=true

# 推送到设备
hdc file send out/standard/test/tests/unittest/input/input/OhosInputCommandTest /data/local/tmp/ohos_input_test/
hdc file send out/standard/test/tests/unittest/input/input/ControllerFactoryTest /data/local/tmp/ohos_input_test/

# 运行测试
hdc shell "cd /data/local/tmp/ohos_input_test && ./OhosInputCommandTest && ./ControllerFactoryTest"

# 预期输出
[==========] 62 tests from 9 test suites ran.
[  PASSED  ] 62 tests.
[==========] 6 tests from 1 test suite ran.
[  PASSED  ] 6 tests.

# host 冒烟验证（无 gtest/SDK 环境的最小替身方案）见 tests/TEST.md
```

## 测试套件分解

| 测试套件 | 测试数量 | 覆盖范围 |
|------------|------------|----------|
| ModifierTest | 4 | 修饰键解析顺序、单键映射、非法与重复输入 |
| OptionParserTest | 10 | 选项对白名单/重复/缺值、数值规则默认值/越界/报错文案 |
| CommandRegistryTest | 3 | 按 (device, action) 查找、按设备分组保序、注册幂等 |
| PrinterTest | 5 | 成功/失败 JSON 形态、帮助输出、参数与未知命令错误 |
| ErrorHandlerTest | 2 | 控制器错误码到权限/服务异常 JSON 与退出码映射 |
| ExecutorTest | 15 | 三级帮助路由、任意位置 --help、--version、未知命令 JSON、注册完备性 |
| MouseSupportTest | 5 | 滚动齿数边界、按键名映射与默认值 |
| MouseDragCommandTest | 5 | 拖拽步进切分、静止/跨屏路径、极值不溢出 |
| IntegrationTest | 13 | 6 命令端到端（mock Controller 调用顺序）、创建前校验拦截、失败路径与销毁顺序 |
| ControllerFactoryTest | 6 | 创建失败清理输出、空实现拒绝 |
