# 鼠标事件注入能力设计文档 V2

## 文档版本
- 版本：V2.0
- 日期：2026-04-02
- 基于新的设计约束重新设计

## 1. 需求分析

### 1.1 需求背景
**需求价值**：满足生态应用使用 TS 接口模拟用户操作的诉求

**需求场景**：
- 自动化工具录制用户输入操作回放功能
- 远程控制（类似 TeamViewer）

**核心诉求**：通过 TS 接口将用户的操作回放出来操作设备

### 1.2 输入输出定义

**输入**：
- 鼠标及解释为鼠标事件的触控板手势（按钮/滚轮/移动）
- 触控板双指轴事件

**处理**：
- a) 正常场景（有权限）：鼠标输入事件按照用户正式操作规则分发到各业务方，并记录权限使用
- b) 异常场景1（事件序列不合法）：如无按下直接注入抬起，向业务方反馈失败
- c) 异常场景2（无权限）：向业务方反馈错误

**输出**：按键输入事件被分发到业务方

### 1.3 验收标准

1. 通过接口注入按钮按下&抬起事件，与用户操作物理鼠标效果相同
2. 通过接口注入移动事件，与用户操作物理鼠标移动光标效果相同
3. 通过接口注入滚动事件，与用户操作物理鼠标滚轮效果相同
4. 通过接口注入双指捏合/滑动事件，与用户操作物理触控板效果相同（不包含旋转）

**产品形态限制**：
- PC：接口可用
- 其他产品形态：调用接口必然失败，失败原因是无权限

## 2. 设计约束（关键）

基于最新需求，本设计必须遵循以下约束：

### 约束 1：客户端状态管理
> **MouseController 应该维护在客户端**

这意味着：
- 按键状态、轴事件状态、光标位置等状态由客户端维护
- 每个进程可以有自己独立的 MouseController 实例
- 状态验证在客户端完成

### 约束 2：无实例数量限制
> **MouseController 的数量不做限制**

这意味着：
- 同一个进程可以创建多个 MouseController 实例
- 每个实例独立维护状态
- 不需要单例模式

### 约束 3：简化 IPC 通信
> **不必要为每个 TS 接口都实现一个从 Proxy->IPC->Stub->Service 的全流程实现**

这意味着：
- 在客户端将每个接口的语义转换为对应的 PointerEvent 事件
- 直接向服务端注入这个 PointerEvent 事件
- 复用现有的 `SimulateInputEvent(PointerEvent)` 接口

### 约束 4：服务端透明
> **服务端不感知 MouseController 的概念**

这意味着：
- 服务端只接收 PointerEvent，不知道来自 MouseController
- 不需要在服务端添加新的消息类型
- 不需要在服务端添加状态管理逻辑


## 3. 架构设计

### 3.1 整体架构

```
┌─────────────────────────────────────────────────────────┐
│                   ArkTS/NAPI Layer                       │
│  (frameworks/ets/ & frameworks/napi/)                    │
│                                                          │
│  ┌────────────────────────────────────────────┐         │
│  │  MouseController (客户端状态管理)          │         │
│  │  - buttonStates_: Map<Button, bool>        │         │
│  │  - axisState_: {inProgress, type, value}   │         │
│  │  - cursorPos_: {displayId, x, y}           │         │
│  │                                             │         │
│  │  方法：                                     │         │
│  │  - moveTo() → 构造 PointerEvent(MOVE)      │         │
│  │  - pressButton() → PointerEvent(BUTTON_DOWN)│        │
│  │  - releaseButton() → PointerEvent(BUTTON_UP)│        │
│  │  - beginAxis() → PointerEvent(AXIS_BEGIN)  │         │
│  │  - updateAxis() → PointerEvent(AXIS_UPDATE)│         │
│  │  - endAxis() → PointerEvent(AXIS_END)      │         │
│  └────────────────────────────────────────────┘         │
│                      ↓                                   │
│              转换为 PointerEvent                         │
└─────────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────────┐
│                   Proxy Layer                            │
│  (frameworks/proxy/)                                     │
│                                                          │
│  InputManagerImpl::SimulateInputEvent(pointerEvent)     │
│  - 复用现有的事件注入接口                                │
│  - 不需要新增接口                                        │
└─────────────────────────────────────────────────────────┘
                      ↓ IPC
┌─────────────────────────────────────────────────────────┐
│                   Service Layer                          │
│  (service/)                                              │
│                                                          │
│  - 接收 PointerEvent                                     │
│  - 不感知 MouseController                                │
│  - 按照正常鼠标事件处理                                  │
└─────────────────────────────────────────────────────────┘
```

### 3.2 与旧设计的对比

| 维度 | 旧设计（V1） | 新设计（V2 - 基于约束） |
|------|-------------|------------------------|
| **状态位置** | 服务端 | **客户端** |
| **IPC 消息** | 6个新消息类型 | **复用现有 SimulateInputEvent** |
| **服务端改动** | 新增 MouseInjectionManager | **无需改动** |
| **实例管理** | 服务端单例 | **客户端多实例** |
| **状态一致性** | 全局一致 | **进程内一致** |

### 3.3 核心组件

#### 3.3.1 MouseController（NAPI 层实现）

**位置**：`frameworks/napi/input_inject/js_mouse_controller.cpp`

**职责**：
- 维护客户端状态（按键、轴事件、光标位置）
- 验证操作序列合法性
- 将操作转换为 PointerEvent
- 调用 InputManager::SimulateInputEvent()

**类定义**：
```cpp
class JsMouseController {
public:
    // 构造函数
    JsMouseController();
    ~JsMouseController();

    // NAPI 方法
    static napi_value MoveTo(napi_env env, napi_callback_info info);
    static napi_value PressButton(napi_env env, napi_callback_info info);
    static napi_value ReleaseButton(napi_env env, napi_callback_info info);
    static napi_value BeginAxis(napi_env env, napi_callback_info info);
    static napi_value UpdateAxis(napi_env env, napi_callback_info info);
    static napi_value EndAxis(napi_env env, napi_callback_info info);

private:
    // 状态管理
    std::map<int32_t, bool> buttonStates_;  // 按键状态
    struct {
        bool inProgress = false;
        int32_t axisType = -1;
        int32_t lastValue = 0;
    } axisState_;  // 轴事件状态
    
    struct {
        int32_t displayId = 0;
        int32_t x = 0;
        int32_t y = 0;
    } cursorPos_;  // 光标位置

    // 辅助方法
    std::shared_ptr<PointerEvent> CreatePointerEvent(int32_t action);
    int32_t InjectPointerEvent(std::shared_ptr<PointerEvent> event);
};
```


## 4. 详细设计

### 4.1 接口语义到 PointerEvent 的映射

#### 4.1.1 moveTo() → POINTER_ACTION_MOVE

```cpp
int32_t JsMouseController::MoveTo(int32_t displayId, int32_t x, int32_t y) {
    // 1. 更新内部光标位置
    cursorPos_.displayId = displayId;
    cursorPos_.x = x;
    cursorPos_.y = y;

    // 2. 构造 PointerEvent
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    
    // 3. 设置坐标
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(x);
    item.SetDisplayY(y);
    item.SetDisplayId(displayId);
    pointerEvent->AddPointerItem(item);
    
    // 4. 设置已按下的按键状态
    for (auto& [button, pressed] : buttonStates_) {
        if (pressed) {
            pointerEvent->SetButtonPressed(button);
        }
    }

    // 5. 注入事件
    return InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
}
```

#### 4.1.2 pressButton() → POINTER_ACTION_BUTTON_DOWN

```cpp
int32_t JsMouseController::PressButton(int32_t button) {
    // 1. 状态验证
    if (buttonStates_[button]) {
        return ERROR_CODE_BUTTON_PRESSED;  // 4300001
    }

    // 2. 更新状态
    buttonStates_[button] = true;

    // 3. 构造 PointerEvent
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetButtonId(button);
    pointerEvent->SetPointerId(0);
    
    // 4. 设置当前光标位置
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(cursorPos_.x);
    item.SetDisplayY(cursorPos_.y);
    item.SetDisplayId(cursorPos_.displayId);
    pointerEvent->AddPointerItem(item);
    
    // 5. 设置按键状态
    pointerEvent->SetButtonPressed(button);

    // 6. 注入事件
    return InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
}
```

#### 4.1.3 releaseButton() → POINTER_ACTION_BUTTON_UP

```cpp
int32_t JsMouseController::ReleaseButton(int32_t button) {
    // 1. 状态验证
    if (!buttonStates_[button]) {
        return ERROR_CODE_BUTTON_NOT_PRESSED;  // 4300001
    }

    // 2. 构造 PointerEvent（先注入再更新状态）
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetButtonId(button);
    pointerEvent->SetPointerId(0);
    
    // 3. 设置当前光标位置
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(cursorPos_.x);
    item.SetDisplayY(cursorPos_.y);
    item.SetDisplayId(cursorPos_.displayId);
    pointerEvent->AddPointerItem(item);

    // 4. 注入事件
    int32_t ret = InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    
    // 5. 更新状态（注入成功后）
    if (ret == RET_OK) {
        buttonStates_[button] = false;
    }
    
    return ret;
}
```

#### 4.1.4 beginAxis() → POINTER_ACTION_AXIS_BEGIN

```cpp
int32_t JsMouseController::BeginAxis(int32_t axis, int32_t value) {
    // 1. 状态验证
    if (axisState_.inProgress) {
        return ERROR_CODE_AXIS_IN_PROGRESS;  // 4300001
    }

    // 2. 更新状态
    axisState_.inProgress = true;
    axisState_.axisType = axis;
    axisState_.lastValue = value;

    // 3. 构造 PointerEvent
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    
    // 4. 设置轴值
    pointerEvent->SetAxisValue(axis, value);
    
    // 5. 设置当前光标位置
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(cursorPos_.x);
    item.SetDisplayY(cursorPos_.y);
    item.SetDisplayId(cursorPos_.displayId);
    pointerEvent->AddPointerItem(item);

    // 6. 注入事件
    return InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
}
```

#### 4.1.5 updateAxis() → POINTER_ACTION_AXIS_UPDATE

```cpp
int32_t JsMouseController::UpdateAxis(int32_t axis, int32_t value) {
    // 1. 状态验证
    if (!axisState_.inProgress) {
        return ERROR_CODE_AXIS_NOT_STARTED;  // 4300001
    }
    if (axisState_.axisType != axis) {
        return ERROR_CODE_AXIS_TYPE_MISMATCH;  // 4300001
    }

    // 2. 更新状态
    axisState_.lastValue = value;

    // 3. 构造 PointerEvent
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    
    // 4. 设置轴值
    pointerEvent->SetAxisValue(axis, value);
    
    // 5. 设置当前光标位置
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(cursorPos_.x);
    item.SetDisplayY(cursorPos_.y);
    item.SetDisplayId(cursorPos_.displayId);
    pointerEvent->AddPointerItem(item);

    // 6. 注入事件
    return InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
}
```

#### 4.1.6 endAxis() → POINTER_ACTION_AXIS_END

```cpp
int32_t JsMouseController::EndAxis(int32_t axis) {
    // 1. 状态验证
    if (!axisState_.inProgress) {
        return ERROR_CODE_AXIS_NOT_STARTED;  // 4300001
    }
    if (axisState_.axisType != axis) {
        return ERROR_CODE_AXIS_TYPE_MISMATCH;  // 4300001
    }

    // 2. 构造 PointerEvent
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    
    // 3. 设置轴值（使用最后的值）
    pointerEvent->SetAxisValue(axis, axisState_.lastValue);
    
    // 4. 设置当前光标位置
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(cursorPos_.x);
    item.SetDisplayY(cursorPos_.y);
    item.SetDisplayId(cursorPos_.displayId);
    pointerEvent->AddPointerItem(item);

    // 5. 注入事件
    int32_t ret = InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    
    // 6. 清除状态（注入成功后）
    if (ret == RET_OK) {
        axisState_.inProgress = false;
        axisState_.axisType = -1;
        axisState_.lastValue = 0;
    }
    
    return ret;
}
```

### 4.2 NAPI 绑定实现

#### 4.2.1 createMouseController() 实现

```cpp
napi_value CreateMouseController(napi_env env, napi_callback_info info) {
    // 1. 权限检查
    if (!CheckPermission(env, "ohos.permission.CONTROL_DEVICE")) {
        ThrowBusinessError(env, 201, "Permission verification failed");
        return nullptr;
    }

    // 2. 能力检查（仅 PC 支持）
    if (!IsPC()) {
        ThrowBusinessError(env, 801, "Capability not supported");
        return nullptr;
    }

    // 3. 创建 MouseController 对象
    napi_value mouseController;
    napi_create_object(env, &mouseController);

    // 4. 创建 C++ 实例并关联
    auto* controller = new JsMouseController();
    napi_wrap(env, mouseController, controller,
        [](napi_env env, void* data, void* hint) {
            delete static_cast<JsMouseController*>(data);
        }, nullptr, nullptr);

    // 5. 绑定方法
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_FUNCTION("moveTo", JsMouseController::MoveTo),
        DECLARE_NAPI_FUNCTION("pressButton", JsMouseController::PressButton),
        DECLARE_NAPI_FUNCTION("releaseButton", JsMouseController::ReleaseButton),
        DECLARE_NAPI_FUNCTION("beginAxis", JsMouseController::BeginAxis),
        DECLARE_NAPI_FUNCTION("updateAxis", JsMouseController::UpdateAxis),
        DECLARE_NAPI_FUNCTION("endAxis", JsMouseController::EndAxis),
    };
    napi_define_properties(env, mouseController, 
        sizeof(descriptors) / sizeof(descriptors[0]), descriptors);

    // 6. 返回 Promise
    napi_deferred deferred;
    napi_value promise;
    napi_create_promise(env, &deferred, &promise);
    napi_resolve_deferred(env, deferred, mouseController);
    
    return promise;
}
```


#### 4.2.2 NAPI 方法包装示例

```cpp
napi_value JsMouseController::MoveTo(napi_env env, napi_callback_info info) {
    // 1. 获取参数
    size_t argc = 3;
    napi_value argv[3];
    napi_value thisVar;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);

    // 2. 参数验证
    if (argc != 3) {
        ThrowBusinessError(env, 401, "Parameter error");
        return nullptr;
    }

    // 3. 提取参数
    int32_t displayId, x, y;
    napi_get_value_int32(env, argv[0], &displayId);
    napi_get_value_int32(env, argv[1], &x);
    napi_get_value_int32(env, argv[2], &y);

    // 4. 获取 C++ 实例
    JsMouseController* controller = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controller));
    if (controller == nullptr) {
        ThrowBusinessError(env, 3800001, "Input service exception");
        return nullptr;
    }

    // 5. 创建 Promise
    napi_deferred deferred;
    napi_value promise;
    napi_create_promise(env, &deferred, &promise);

    // 6. 异步执行
    auto asyncWork = [controller, displayId, x, y, deferred, env]() {
        int32_t ret = controller->MoveTo(displayId, x, y);
        if (ret == RET_OK) {
            napi_resolve_deferred(env, deferred, nullptr);
        } else {
            napi_value error = CreateBusinessError(env, ret);
            napi_reject_deferred(env, deferred, error);
        }
    };

    // 7. 使用线程池执行
    std::thread(asyncWork).detach();
    
    return promise;
}
```

### 4.3 状态机设计

#### 4.3.1 按键状态机（客户端维护）

```
每个 MouseController 实例独立维护：

         pressButton()
  [未按下] ──────────→ [已按下]
     ↑                    │
     │                    │
     └────────────────────┘
        releaseButton()

状态存储：buttonStates_[button] = true/false
```

#### 4.3.2 轴事件状态机（客户端维护）

```
每个 MouseController 实例独立维护：

         beginAxis()
  [空闲] ──────────→ [进行中]
     ↑                 │  ↑
     │                 │  │
     │                 │  │ updateAxis()
     │                 ↓  │
     └────────────────────┘
          endAxis()

状态存储：axisState_ = {inProgress, axisType, lastValue}
```

### 4.4 错误处理

#### 4.4.1 错误码映射

| 错误码 | 说明 | 触发场景 | 处理位置 |
|--------|------|----------|---------|
| 201 | 权限验证失败 | 缺少 CONTROL_DEVICE 权限 | NAPI 层 |
| 401 | 参数错误 | 参数类型或数量错误 | NAPI 层 |
| 801 | 能力不支持 | 非 PC 设备 | NAPI 层 |
| 3800001 | 输入服务异常 | 服务未启动或内部错误 | Proxy 层 |
| 4300001 | 状态错误 | 按键重复按下、轴事件状态不匹配 | 客户端 |
| 4300002 | 显示器不存在 | displayId 无效 | 服务端 |

#### 4.4.2 错误处理流程

```
客户端（NAPI）                    服务端
    │                               │
    ├─ 权限检查 ──✗──→ 返回 201     │
    │                               │
    ├─ 参数验证 ──✗──→ 返回 401     │
    │                               │
    ├─ 状态验证 ──✗──→ 返回 4300001 │
    │                               │
    ├─ 构造 PointerEvent            │
    │                               │
    ├─ SimulateInputEvent() ────────→ 接收事件
    │                               │
    │                               ├─ 验证 displayId ──✗──→ 返回 4300002
    │                               │
    │                               ├─ 处理事件
    │                               │
    │                               └─ 返回结果
    │                               │
    ←─────────────────────────────────┘
```

## 5. 实现要点

### 5.1 客户端状态管理

**关键点**：
1. 每个 MouseController 实例独立维护状态
2. 状态存储在 NAPI 对象的 native 数据中
3. 使用 napi_wrap 关联 C++ 实例和 JS 对象
4. 对象销毁时自动清理状态

**示例**：
```cpp
// 创建时
auto* controller = new JsMouseController();
napi_wrap(env, jsObject, controller,
    [](napi_env env, void* data, void* hint) {
        delete static_cast<JsMouseController*>(data);  // 自动清理
    }, nullptr, nullptr);

// 使用时
JsMouseController* controller = nullptr;
napi_unwrap(env, jsObject, reinterpret_cast<void**>(&controller));
```

### 5.2 PointerEvent 构造规范

**必须设置的字段**：
1. `SetPointerAction()` - 动作类型
2. `SetSourceType(SOURCE_TYPE_MOUSE)` - 源类型
3. `SetPointerId(0)` - 指针 ID
4. `AddPointerItem()` - 至少一个指针项
5. `SetDisplayX/Y()` - 坐标（在 PointerItem 中）
6. `SetDisplayId()` - 显示器 ID（在 PointerItem 中）

**按键事件额外字段**：
- `SetButtonId()` - 按键 ID
- `SetButtonPressed()` - 按键状态

**轴事件额外字段**：
- `SetAxisValue()` - 轴值

### 5.3 复用现有接口

**关键接口**：
```cpp
// frameworks/proxy/event_handler/include/input_manager_impl.h
int32_t SimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent, 
                          bool isNativeInject = false,
                          int32_t useCoordinate = PointerEvent::DISPLAY_COORDINATE);
```

**调用方式**：
```cpp
InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
```

**优势**：
- 无需新增 IPC 消息
- 无需修改服务端
- 复用现有的权限检查、事件处理逻辑

### 5.4 多实例支持

**设计要点**：
1. 不使用单例模式
2. 每次调用 `createMouseController()` 创建新实例
3. 实例之间状态完全独立
4. 由 JS GC 管理生命周期

**使用场景**：
```typescript
// 场景1：单个控制器
const controller = await inputMonitor.createMouseController();
await controller.moveTo(0, 100, 100);

// 场景2：多个控制器（独立状态）
const controller1 = await inputMonitor.createMouseController();
const controller2 = await inputMonitor.createMouseController();

await controller1.pressButton(Button.LEFT);   // controller1 状态：LEFT=pressed
await controller2.pressButton(Button.RIGHT);  // controller2 状态：RIGHT=pressed
// 两个控制器状态互不影响
```


## 6. 目录结构

```
multimodalinput_input/
├── frameworks/
│   └── napi/
│       └── input_inject/
│           ├── include/
│           │   └── js_mouse_controller.h          # MouseController NAPI 实现
│           ├── src/
│           │   ├── js_mouse_controller.cpp        # 核心实现
│           │   └── mouse_controller_module.cpp    # 模块导出
│           ├── test/
│           │   └── mouse_controller_test.ets      # 集成测试
│           └── BUILD.gn
└── interfaces/
    └── kits/
        └── napi/
            └── @ohos.multimodalInput.inputMonitor.d.ts  # TS 类型定义
```

## 7. 实现计划

### 7.1 第一阶段：核心功能（3天）

**任务**：
1. 实现 `JsMouseController` C++ 类
   - 状态管理（buttonStates_, axisState_, cursorPos_）
   - 6个操作方法的实现
   - PointerEvent 构造逻辑

2. 实现 NAPI 绑定
   - `createMouseController()` 函数
   - 6个方法的 NAPI 包装
   - 错误处理和 Promise 封装

3. 实现 TS 类型定义
   - MouseController 接口
   - Button/Axis 枚举
   - 错误码定义

**验收标准**：
- 编译通过
- 可以从 TS 调用接口
- 基本功能可用

### 7.2 第二阶段：测试和优化（2天）

**任务**：
1. 编写单元测试
   - 状态机测试
   - 错误处理测试
   - 边界条件测试

2. 编写集成测试
   - 完整操作序列测试
   - 多实例测试
   - 权限测试

3. 性能优化
   - 减少内存分配
   - 优化 PointerEvent 构造

**验收标准**：
- 测试覆盖率 > 80%
- 所有测试用例通过
- 性能满足要求

### 7.3 第三阶段：文档和发布（1天）

**任务**：
1. 完善 API 文档
2. 编写使用示例
3. 代码审查和修复

**验收标准**：
- 文档完整
- 代码符合规范
- 通过代码审查

## 8. 测试策略

### 8.1 单元测试

**测试文件**：`frameworks/napi/input_inject/test/mouse_controller_unittest.cpp`

**测试用例**：
```cpp
// 状态管理测试
TEST_F(MouseControllerTest, PressButton_Success)
TEST_F(MouseControllerTest, PressButton_AlreadyPressed)
TEST_F(MouseControllerTest, ReleaseButton_NotPressed)
TEST_F(MouseControllerTest, BeginAxis_Success)
TEST_F(MouseControllerTest, BeginAxis_AlreadyInProgress)
TEST_F(MouseControllerTest, UpdateAxis_NotStarted)
TEST_F(MouseControllerTest, EndAxis_Success)

// PointerEvent 构造测试
TEST_F(MouseControllerTest, CreateMoveEvent)
TEST_F(MouseControllerTest, CreateButtonEvent)
TEST_F(MouseControllerTest, CreateAxisEvent)

// 多实例测试
TEST_F(MouseControllerTest, MultipleInstances_IndependentState)
```

### 8.2 集成测试

**测试文件**：`frameworks/napi/input_inject/test/mouse_controller_test.ets`

**测试场景**：
```typescript
// 完整操作序列
describe('MouseController', () => {
  it('should complete full mouse operation sequence', async () => {
    const controller = await inputMonitor.createMouseController();
    
    // 移动光标
    await controller.moveTo(0, 100, 100);
    
    // 按下左键
    await controller.pressButton(inputMonitor.Button.LEFT);
    
    // 拖动
    await controller.moveTo(0, 200, 200);
    
    // 释放左键
    await controller.releaseButton(inputMonitor.Button.LEFT);
  });

  it('should handle scroll wheel', async () => {
    const controller = await inputMonitor.createMouseController();
    
    await controller.beginAxis(inputMonitor.Axis.SCROLL_VERTICAL, 10);
    await controller.updateAxis(inputMonitor.Axis.SCROLL_VERTICAL, 20);
    await controller.updateAxis(inputMonitor.Axis.SCROLL_VERTICAL, 30);
    await controller.endAxis(inputMonitor.Axis.SCROLL_VERTICAL);
  });

  it('should reject invalid button sequence', async () => {
    const controller = await inputMonitor.createMouseController();
    
    await controller.pressButton(inputMonitor.Button.LEFT);
    
    // 应该抛出 4300001 错误
    await expect(
      controller.pressButton(inputMonitor.Button.LEFT)
    ).rejects.toThrow('4300001');
  });

  it('should support multiple independent controllers', async () => {
    const controller1 = await inputMonitor.createMouseController();
    const controller2 = await inputMonitor.createMouseController();
    
    // 两个控制器独立操作
    await controller1.pressButton(inputMonitor.Button.LEFT);
    await controller2.pressButton(inputMonitor.Button.RIGHT);
    
    // 状态互不影响
    await controller1.releaseButton(inputMonitor.Button.LEFT);
    await controller2.releaseButton(inputMonitor.Button.RIGHT);
  });
});
```

### 8.3 权限测试

```typescript
describe('MouseController Permissions', () => {
  it('should reject without permission', async () => {
    // 模拟无权限场景
    await expect(
      inputMonitor.createMouseController()
    ).rejects.toThrow('201');
  });

  it('should reject on non-PC devices', async () => {
    // 模拟非 PC 设备
    await expect(
      inputMonitor.createMouseController()
    ).rejects.toThrow('801');
  });
});
```

## 9. 关键代码示例

### 9.1 完整的 JsMouseController 类

```cpp
// js_mouse_controller.h
#ifndef JS_MOUSE_CONTROLLER_H
#define JS_MOUSE_CONTROLLER_H

#include <map>
#include <memory>
#include "napi/native_api.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {

class JsMouseController {
public:
    JsMouseController();
    ~JsMouseController() = default;

    // NAPI 方法
    static napi_value MoveTo(napi_env env, napi_callback_info info);
    static napi_value PressButton(napi_env env, napi_callback_info info);
    static napi_value ReleaseButton(napi_env env, napi_callback_info info);
    static napi_value BeginAxis(napi_env env, napi_callback_info info);
    static napi_value UpdateAxis(napi_env env, napi_callback_info info);
    static napi_value EndAxis(napi_env env, napi_callback_info info);

    // 实际操作方法
    int32_t MoveTo(int32_t displayId, int32_t x, int32_t y);
    int32_t PressButton(int32_t button);
    int32_t ReleaseButton(int32_t button);
    int32_t BeginAxis(int32_t axis, int32_t value);
    int32_t UpdateAxis(int32_t axis, int32_t value);
    int32_t EndAxis(int32_t axis);

private:
    std::shared_ptr<PointerEvent> CreatePointerEvent(int32_t action);
    int32_t InjectPointerEvent(std::shared_ptr<PointerEvent> event);

    // 状态
    std::map<int32_t, bool> buttonStates_;
    struct {
        bool inProgress = false;
        int32_t axisType = -1;
        int32_t lastValue = 0;
    } axisState_;
    struct {
        int32_t displayId = 0;
        int32_t x = 0;
        int32_t y = 0;
    } cursorPos_;
};

} // namespace MMI
} // namespace OHOS

#endif // JS_MOUSE_CONTROLLER_H
```

### 9.2 模块导出

```cpp
// mouse_controller_module.cpp
#include "napi/native_api.h"
#include "js_mouse_controller.h"

namespace OHOS {
namespace MMI {

static napi_value CreateMouseController(napi_env env, napi_callback_info info) {
    // 实现见前文 4.2.1 节
}

static napi_value Init(napi_env env, napi_value exports) {
    // 导出 createMouseController 函数
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createMouseController", CreateMouseController),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    
    return exports;
}

static napi_module mouseControllerModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "multimodalInput.inputMonitor",
    .nm_priv = nullptr,
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterModule() {
    napi_module_register(&mouseControllerModule);
}

} // namespace MMI
} // namespace OHOS
```


## 10. 优势分析

### 10.1 相比 V1 设计的优势

| 维度 | V1 设计（服务端状态） | V2 设计（客户端状态） |
|------|---------------------|---------------------|
| **实现复杂度** | 高（需要新增服务端组件） | 低（仅客户端实现） |
| **IPC 开销** | 高（6个新消息类型） | 低（复用现有接口） |
| **服务端改动** | 大（新增 MouseInjectionManager） | 无 |
| **多实例支持** | 复杂（需要会话管理） | 简单（天然支持） |
| **状态一致性** | 全局一致 | 进程内一致 |
| **开发周期** | 长（约2周） | 短（约1周） |
| **维护成本** | 高 | 低 |

### 10.2 设计优势

1. **简化架构**
   - 无需修改服务端
   - 复用现有的 SimulateInputEvent 接口
   - 减少 IPC 通信开销

2. **灵活性**
   - 支持多实例
   - 每个实例独立状态
   - 适合多种使用场景

3. **易于维护**
   - 代码集中在客户端
   - 逻辑清晰简单
   - 测试容易

4. **性能优化**
   - 减少 IPC 往返次数
   - 客户端状态验证更快
   - 无服务端锁竞争

## 11. 风险和限制

### 11.1 状态一致性

**风险**：多个进程同时操作时，状态可能不一致

**示例**：
```
进程A: pressButton(LEFT) → 客户端A记录：LEFT=pressed
进程B: pressButton(LEFT) → 客户端B记录：LEFT=pressed
实际系统：LEFT只被按下一次
```

**缓解措施**：
- 文档明确说明：MouseController 状态仅在进程内有效
- 建议：同一时刻只有一个进程使用 MouseController
- 适用场景：单一控制源（如远程控制、自动化测试）

### 11.2 与真实鼠标的交互

**风险**：用户操作真实鼠标时，MouseController 状态不会更新

**示例**：
```
1. controller.pressButton(LEFT)  → 客户端状态：LEFT=pressed
2. 用户按下物理鼠标左键         → 系统状态：LEFT=pressed
3. 用户释放物理鼠标左键         → 系统状态：LEFT=released
4. controller.releaseButton(LEFT) → 客户端状态：LEFT=released
   但实际系统已经是 released 状态
```

**缓解措施**：
- 文档说明：MouseController 适用于完全控制场景
- 建议：使用期间禁用真实鼠标输入
- 或者：提供 reset() 方法清除状态

### 11.3 服务端验证缺失

**风险**：服务端不验证事件序列合法性

**影响**：
- 客户端可以绕过状态检查直接构造 PointerEvent
- 恶意应用可能注入非法事件序列

**缓解措施**：
- 依赖权限控制（CONTROL_DEVICE）
- 服务端已有的事件验证逻辑
- 文档说明正确使用方式

## 12. 未来扩展

### 12.1 状态同步（可选）

如果需要全局状态一致性，可以考虑：

```typescript
interface MouseController {
  // 新增：同步状态到服务端
  syncState(): Promise<void>;
  
  // 新增：从服务端获取状态
  getState(): Promise<MouseState>;
}
```

### 12.2 状态重置（推荐）

```typescript
interface MouseController {
  // 新增：重置所有状态
  reset(): Promise<void>;
}
```

实现：
```cpp
int32_t JsMouseController::Reset() {
    buttonStates_.clear();
    axisState_.inProgress = false;
    axisState_.axisType = -1;
    axisState_.lastValue = 0;
    return RET_OK;
}
```

### 12.3 状态查询（可选）

```typescript
interface MouseController {
  // 新增：查询按键状态
  isButtonPressed(button: Button): boolean;
  
  // 新增：查询轴事件状态
  isAxisInProgress(): boolean;
}
```

## 13. 总结

### 13.1 核心设计决策

本设计基于以下核心决策：

1. ✅ **客户端状态管理**：状态维护在 NAPI 层，每个实例独立
2. ✅ **复用现有接口**：通过 SimulateInputEvent 注入 PointerEvent
3. ✅ **服务端透明**：服务端无需感知 MouseController
4. ✅ **多实例支持**：无数量限制，状态完全独立

### 13.2 实现要点

1. **状态管理**：使用 napi_wrap 关联 C++ 实例和 JS 对象
2. **事件转换**：每个操作方法构造对应的 PointerEvent
3. **错误处理**：客户端验证 + 服务端验证双重保障
4. **生命周期**：由 JS GC 自动管理

### 13.3 适用场景

本设计特别适合：
- ✅ 远程控制（单一控制源）
- ✅ 自动化测试（录制回放）
- ✅ 辅助功能（单一辅助工具）
- ✅ 演示和教学（操作录制）

不适合：
- ❌ 多进程协同控制
- ❌ 需要全局状态一致性的场景
- ❌ 与真实鼠标混合使用

### 13.4 开发周期

- **第一阶段**（3天）：核心功能实现
- **第二阶段**（2天）：测试和优化
- **第三阶段**（1天）：文档和发布
- **总计**：约 6 个工作日

### 13.5 关键优势

1. **实现简单**：无需修改服务端，开发周期短
2. **性能优秀**：减少 IPC 开销，客户端验证快
3. **易于维护**：代码集中，逻辑清晰
4. **灵活扩展**：支持多实例，适应多种场景

---

**文档版本**：V2.0  
**最后更新**：2026-04-02  
**状态**：待评审


## 14. 待明确问题和决策点

本节列出设计中需要进一步明确的关键问题，这些问题的答案将影响最终实现。

### 14.1 高优先级问题（必须明确）

#### 14.1.1 Button 枚举定义

**问题**：接口中使用了 `Button` 类型，需要明确具体的枚举值定义。

**需要确认**：
```typescript
enum Button {
  LEFT = ?      // 对应 PointerEvent 的哪个常量？
  RIGHT = ?     // PointerEvent::MOUSE_BUTTON_RIGHT?
  MIDDLE = ?    // PointerEvent::MOUSE_BUTTON_MIDDLE?
  SIDE = ?      // 侧键
  EXTRA = ?     // 额外按键
  FORWARD = ?   // 前进键
  BACK = ?      // 后退键
}
```

**影响**：
- NAPI 层的枚举定义
- `SetButtonId()` 的参数值
- TypeScript 类型定义

**行动**：查看 `pointer_event.h` 中的按键常量定义

---

#### 14.1.2 Axis 枚举定义

**问题**：接口中使用了 `Axis` 类型，特别是触控板双指手势的支持需要明确。

**需要确认**：
```typescript
enum Axis {
  SCROLL_VERTICAL = ?      // 垂直滚轮
  SCROLL_HORIZONTAL = ?    // 水平滚轮
  
  // 触控板双指手势（需求中提到）
  PINCH = ?               // 双指捏合
  SWIPE_HORIZONTAL = ?    // 双指水平滑动
  SWIPE_VERTICAL = ?      // 双指垂直滑动
}
```

**关键问题**：
1. 双指捏合/滑动是通过 `beginAxis/updateAxis/endAxis` 实现吗？
2. 还是需要单独的接口？
3. PointerEvent 对应的 action 是什么？
   - `POINTER_ACTION_SWIPE_BEGIN/UPDATE/END`？
   - 还是 `POINTER_ACTION_AXIS_*` + 特定轴类型？

**影响**：
- 轴事件的实现逻辑
- PointerEvent 的 action 选择
- 可能需要额外的手势支持

**行动**：
1. 查看 `pointer_event.h` 中的轴类型和 SWIPE action 定义
2. 确认触控板手势的实现方式

---

#### 14.1.3 PointerEvent 必须设置的字段

**问题**：构造 PointerEvent 时，哪些字段是必须的？

**已知必须设置**：
```cpp
pointerEvent->SetPointerAction(action);           // ✅
pointerEvent->SetSourceType(SOURCE_TYPE_MOUSE);   // ✅
pointerEvent->SetPointerId(0);                    // ✅
pointerEvent->AddPointerItem(item);               // ✅
```

**需要明确**：
```cpp
pointerEvent->SetDeviceId(?);           // ❓ 需要吗？设置什么值？
pointerEvent->SetActionTime(?);         // ❓ 使用当前时间？
pointerEvent->SetActionStartTime(?);    // ❓ 需要吗？
pointerEvent->SetTargetDisplayId(?);    // ❓ 与 displayId 的关系？
pointerEvent->SetTargetWindowId(?);     // ❓ -1 表示不指定？
```

**影响**：
- PointerEvent 构造的完整性
- 事件能否被服务端正确处理

**行动**：参考现有 `SimulateInputEvent` 的实现

---

### 14.2 中优先级问题（建议明确）

#### 14.2.1 对象销毁时的清理策略

**问题**：当 MouseController 对象被 GC 回收时，如果还有按键处于按下状态，应该如何处理？

**场景**：
```typescript
async function test() {
  const controller = await createMouseController();
  await controller.pressButton(Button.LEFT);
  // controller 离开作用域，被 GC 回收
  // 但 LEFT 按键状态是 pressed
}
```

**可选方案**：

**方案 A：自动清理（推荐）**
```cpp
JsMouseController::~JsMouseController() {
  // 释放所有按下的按键
  for (auto& [button, pressed] : buttonStates_) {
    if (pressed) {
      ReleaseButton(button);
    }
  }
  
  // 结束进行中的轴事件
  if (axisState_.inProgress) {
    EndAxis(axisState_.axisType);
  }
}
```

**方案 B：不清理**
- 由应用层保证正确清理
- 文档中明确说明

**方案 C：警告但不清理**
```cpp
JsMouseController::~JsMouseController() {
  if (!buttonStates_.empty() || axisState_.inProgress) {
    MMI_HILOGW("MouseController destroyed with active state");
  }
}
```

**建议**：方案 A（自动清理），避免状态泄漏

---

#### 14.2.2 displayId 的验证策略

**问题**：`moveTo(displayId, x, y)` 中的 displayId 应该在哪里验证？

**方案 A：服务端验证（当前设计）**
```cpp
// 客户端不验证，直接构造 PointerEvent
// 如果 displayId 无效，服务端返回 4300002
```

**方案 B：客户端预验证**
```cpp
// 先查询显示器列表，验证 displayId
// 问题：需要额外的 IPC 调用，且可能有时序问题（热插拔）
```

**建议**：方案 A（服务端验证），简单高效

---

#### 14.2.3 坐标范围验证

**问题**：坐标是否需要验证？

**需要明确**：
1. **负数坐标**：是否允许？
   - 建议：允许，某些多显示器场景需要负数坐标

2. **超出屏幕范围**：如何处理？
   - 建议：不在客户端验证，由服务端裁剪到屏幕边界

3. **坐标类型**：`int` 是否足够？
   - 建议：足够，不需要小数坐标

**建议**：不在客户端验证坐标范围

---

#### 14.2.4 权限检查的时机

**问题**：权限应该在什么时候检查？

**方案 A：仅在 createMouseController 时检查（当前设计）**
```typescript
const controller = await createMouseController();  // ✅ 检查权限
await controller.moveTo(0, 100, 100);          // ❌ 不检查
```
- 优点：性能好
- 缺点：如果权限在运行时被撤销，无法及时发现

**方案 B：每次操作都检查**
- 优点：安全性高
- 缺点：性能开销大

**建议**：方案 A，假设权限在 controller 生命周期内不会改变

---

### 14.3 低优先级问题（可选明确）

#### 14.3.1 错误码 4300001 的细分

**问题**：当前 4300001 用于多种状态错误，是否需要细分？

**当前使用场景**：
- 按键已被按下
- 按键未被按下
- 轴事件正在进行中
- 轴事件未开始
- 轴事件类型不匹配

**建议**：统一使用 4300001，通过错误消息区分。如需细分，可在后续版本扩展。

---

#### 14.3.2 模块导出位置

**问题**：`createMouseController()` 应该导出到哪个模块？

**可选方案**：
- 方案 A：`@ohos.multimodalInput.inputMonitor`
- 方案 B：`@ohos.multimodalInput.inputSimulator`（新建）

**建议**：根据现有模块结构决定

---

#### 14.3.3 事件来源标记

**问题**：通过 MouseController 注入的事件，是否需要标记来源？

**方案 A：完全透明（当前设计）**
- 服务端无法区分事件来源
- 注入事件与真实事件完全相同

**方案 B：标记事件来源**
```cpp
pointerEvent->SetEventSource(EVENT_SOURCE_SIMULATED);
```

**建议**：方案 A（完全透明），如需区分可使用现有的 `isNativeInject` 参数

---

### 14.4 问题优先级汇总

| 编号 | 问题 | 优先级 | 建议方案 |
|------|------|--------|---------|
| 1 | Button 枚举定义 | 🔴 高 | 查看 PointerEvent.h |
| 2 | Axis 枚举定义 | 🔴 高 | 查看 PointerEvent.h |
| 3 | PointerEvent 必须字段 | 🔴 高 | 参考现有实现 |
| 4 | 对象销毁清理策略 | 🟡 中 | 自动清理 |
| 5 | displayId 验证策略 | 🟡 中 | 服务端验证 |
| 6 | 坐标范围验证 | 🟡 中 | 不验证 |
| 7 | 权限检查时机 | 🟡 中 | 仅初始检查 |
| 8 | 错误码细分 | 🟢 低 | 统一 4300001 |
| 9 | 模块导出位置 | 🟢 低 | 根据现有结构 |
| 10 | 事件来源标记 | 🟢 低 | 完全透明 |

---

### 14.5 下一步行动

**立即需要做的**：
1. ✅ 查看 `pointer_event.h`，确认 Button 和 Axis 的枚举定义
2. ✅ 查看现有 `SimulateInputEvent` 实现，确认 PointerEvent 必须字段
3. ✅ 确认触控板双指手势的实现方式

**可以稍后决定的**：
4. 对象销毁清理策略（建议自动清理）
5. displayId 和坐标验证策略（建议服务端验证）
6. 权限检查时机（建议仅初始检查）

**可选的**：
7. 错误码是否细分（建议不细分）
8. 模块导出位置（根据现有结构）
9. 事件来源标记（建议透明）

---

**注**：以上问题明确后，将更新到相应章节的详细设计中。

