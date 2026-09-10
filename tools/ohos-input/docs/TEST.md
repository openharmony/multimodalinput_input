# ohos-input 测试用例

## 测试覆盖概览

| 分类 | 测试数量 | 覆盖命令 |
|----------|------------|------------------|
| 修饰键测试 | 4 | 所有（修饰键解析，前置拦截） |
| 选项解析测试 | 10 | 所有（选项白名单与数值规则） |
| 注册表测试 | 4 | 所有（命令注册与查找） |
| 输出打印测试 | 5 | 所有（JSON 输出格式验证） |
| 错误处理测试 | 2 | 所有（错误码验证） |
| 执行器测试 | 11 | 已交付命令（命令注册、帮助路由、版本） |
| 集成测试 | 7 | key press（mock Controller 工作流验证） |
| **总计** | **43** | **本笔交付：框架 + key press** |

## 命令测试矩阵

### key press

| 测试用例 | 命令示例 | 说明 | 权限 | 前置依赖 | 预期结果 |
|-----------|-----------------|-------------|------------|------------|-----------------|
| 回车键 | `ohos-input key press --key 2054` | 按下回车，默认按住 100ms | `ohos.permission.CONTROL_DEVICE` | 无 | 成功：`data:{action:"key press",key:2054}` |
| Ctrl+A 组合 | `ohos-input key press --key 2049 --modifier ctrl` | 全选 | `ohos.permission.CONTROL_DEVICE` | 无 | 成功：data 含 `key:2049` |
| 三键组合 | `ohos-input key press --key 2066 --modifier ctrl\|shift` | 按下为书写顺序，抬起为逆序 | `ohos.permission.CONTROL_DEVICE` | 无 | 成功 |
| 键码重复 | `ohos-input key press --key 2072 --modifier ctrl` | 2072 为 ctrl 修饰键码，不得重复 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2 |
| 非法修饰键 | `ohos-input key press --key 2049 --modifier "ctrl\|"` | 修饰键不可为空段 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2，不创建 Controller |
| 未知选项 | `ohos-input key press --key 1 --unknown x` | 选项不在白名单 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2，不创建 Controller |
| 键码越界 | `ohos-input key press --key 0` | 键码须 ≥1 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2 |
| 时长越界 | `ohos-input key press --key 2049 --holdDuration 10001` | 超出 [0,10000] 上界 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`，退出码 2 |

### 帮助命令

| 测试用例 | 命令示例 | 说明 | 权限 | 前置依赖 | 预期结果 |
|-----------|-----------------|-------------|------------|------------|-----------------|
| 全局帮助 | `ohos-input --help` | 显示顶层帮助 | 无 | 无 | 帮助文本输出到 stdout（非 JSON 格式），SubCommands 仅列出已交付设备 |
| 空参数 | `ohos-input` | 无参数调用 | 无 | 无 | 帮助文本输出到 stdout（非 JSON 格式） |
| 版本号 | `ohos-input --version` | 输出版本字符串 | 无 | 无 | 版本号输出到 stdout（非 JSON 格式） |
| 设备帮助 | `ohos-input key --help` | 显示 key 子命令帮助 | 无 | 无 | 帮助文本输出到 stdout（非 JSON 格式） |
| 仅设备名 | `ohos-input key` | 缺少动作子命令 | 无 | 无 | 设备帮助输出到 stdout（非 JSON 格式） |
| 动作帮助 | `ohos-input key press --help` | 显示 press 选项帮助 | 无 | 无 | 帮助文本输出到 stdout（非 JSON 格式） |
| 选项中帮助 | `ohos-input key press --key 1 --help` | `--help` 可出现在选项任意位置 | 无 | 无 | 帮助文本输出到 stdout（非 JSON 格式），不创建 Controller |

### 错误场景

| 测试用例 | 命令示例 | 说明 | 权限 | 前置依赖 | 预期结果 |
|-----------|-----------------|-------------|------------|------------|-----------------|
| 未知设备 | `ohos-input touchscreen press --key 1` | 设备名无效 | 无 | 无 | 失败：`{type:"result",status:"failed",errCode:"ERR_PARAMETER_ERROR",errMsg:"Unknown command: touchscreen",suggestion:"..."}` |
| 未知动作 | `ohos-input key hover` | 动作名无效 | 无 | 无 | 失败：`ERR_PARAMETER_ERROR`（"Unknown command: hover"），退出码 2 |
| 权限拒绝 | Controller 创建返回 -201 | 未持有 CONTROL_DEVICE | `ohos.permission.CONTROL_DEVICE` | 无 | 失败：`ERR_PERMISSION_DENIED`，退出码 3 |
| 服务异常 | 注入调用返回非 0 | 输入服务运行期失败 | `ohos.permission.CONTROL_DEVICE` | 服务运行 | 失败：`ERR_INPUT_SERVICE_EXCEPTION`，退出码 1 |

## 集成测试工作流

### 键盘输入场景

```bash
# 1. Ctrl+A 全选已有内容
ohos-input key press --key 2049 --modifier ctrl

# 2. 输入字母 A（覆盖）
ohos-input key press --key 2049

# 3. 回车提交
ohos-input key press --key 2054
```

## 参数验证测试

### 数值参数值域

| 参数 | 适用命令 | 合法范围 | 默认值 | 非法示例 |
|-----------|-----------------|-------------|-------|-------------|
| `--holdDuration` | key press | [0, 10000] ms | 100 | `10001`、`-1` |
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
hb build input -t --gn-args input_controller_inject_enable=true

# 推送到设备
hdc file send out/standard/test/tests/unittest/input/input/OhosInputCommandTest /data/local/tmp/ohos_input_test/

# 运行测试
hdc shell "cd /data/local/tmp/ohos_input_test && ./OhosInputCommandTest"

# 预期输出
[==========] 43 tests from 6 test suites ran.
[  PASSED  ] 43 tests.
```

## 测试套件分解

| 测试套件 | 测试数量 | 覆盖范围 |
|------------|------------|----------|
| ModifierTest | 4 | 修饰键解析顺序、单键映射、非法与重复输入 |
| OptionParserTest | 10 | 选项对白名单/重复/缺值、数值规则默认值/越界/报错文案 |
| CommandTableTest | 4 | 按 (device, action) 查找、未交付命令返回空、按设备分组保序、注册幂等 |
| PrinterTest | 5 | 成功/失败 JSON 形态、帮助输出、参数与未知命令错误 |
| ErrorHandlerTest | 2 | 控制器错误码到权限/服务异常 JSON 与退出码映射 |
| ExecutorTest | 11 | 三级帮助路由、任意位置 --help、--version、未知命令 JSON、注册完备性 |
| IntegrationTest | 7 | key press 端到端（mock Controller 调用顺序）、创建前校验拦截、失败路径与销毁顺序 |
