# MouseController/KeyboardController 实现下沉方案（第1部分）

## 一、背景和目标

### 1.1 当前问题

当前 MouseController 和 KeyboardController 的完整实现都在 NAPI 层（`frameworks/napi/input_event_client/`），导致：

- **代码重复**：未来 ANI 层、NDK 层需要重复实现相同逻辑
- **维护困难**：修复 bug 需要在多处修改
- **不一致风险**：不同 API 层可能出现行为差异

### 1.2 目标

将核心实现下沉到 `input_manager_impl.cpp`，使得：

- ✅ NAPI、ANI、NDK 共享同一套核心实现
- ✅ 修复 bug 只需改一处
- ✅ 所有 API 层行为完全一致
- ✅ 可以直接测试 Impl 层，不依赖 NAPI

---

## 二、架构设计

### 2.1 当前架构（问题）

```
┌─────────────────────────────────────────┐
│  NAPI 层 (js_mouse_controller.cpp)      │
│  ├─ 状态管理 (buttonStates_, cursorPos_)│
│  ├─ 事件构造 (CreatePointerEvent)       │
│  ├─ 事件注入 (InputManager::Simulate)   │
│  └─ NAPI 包装 (参数转换、Promise)       │
└─────────────────────────────────────────┘
                    ❌ 重复实现
┌─────────────────────────────────────────┐
│  ANI 层 (未来)                           │
│  └─ 需要重复实现相同逻辑                 │
└─────────────────────────────────────────┘
                    ❌ 重复实现
┌─────────────────────────────────────────┐
│  NDK 层 (未来)                           │
│  └─ 需要重复实现相同逻辑                 │
└─────────────────────────────────────────┘
```

### 2.2 目标架构（改进）

```
┌─────────────────────────────────────────────────────┐
│  InputManagerImpl 层 (input_manager_impl.cpp)       │
│  ├─ MouseControllerImpl (核心实现)                  │
│  │   ├─ 状态管理 (buttonStates_, cursorPos_)       │
│  │   ├─ 事件构造 (CreatePointerEvent)              │
│  │   └─ 事件注入 (InputManager::SimulateInputEvent)│
│  └─ KeyboardControllerImpl (核心实现)               │
│      ├─ 状态管理 (pressedKeys_, keyDownTimes_)     │
│      ├─ 事件构造 (CreateKeyEvent)                  │
│      └─ 事件注入 (InputManager::SimulateInputEvent)│
└─────────────────────────────────────────────────────┘
                          ↑ 共享核心实现
        ┌─────────────────┼─────────────────┐
        │                 │                 │
┌───────┴────────┐ ┌──────┴──────┐ ┌───────┴────────┐
│ NAPI 层        │ │ ANI 层      │ │ NDK 层         │
│ (薄包装)       │ │ (薄包装)    │ │ (薄包装)       │
│ - 参数转换     │ │ - 参数转换  │ │ - C API 包装   │
│ - Promise 包装 │ │ - 回调处理  │ │ - 错误码转换   │
│ - libuv 异步   │ │ - 错误码    │ │                │
└────────────────┘ └─────────────┘ └────────────────┘
```

### 2.3 层次职责划分

| 层次 | 职责 | 示例 |
|------|------|------|
| **Impl 层** | 核心业务逻辑 | 状态管理、事件构造、注入 |
| **NAPI 层** | NAPI 适配 | 参数转换、Promise、libuv 异步 |
| **ANI 层** | ANI 适配 | 参数转换、回调处理、错误码映射 |
| **NDK 层** | C API 适配 | C 函数包装、错误码转换 |

---

## 三、技术选型：libuv vs std::thread

### 3.1 为什么不能使用 std::thread？

参考 `js_event_target.cpp` 的实现，OpenHarmony NAPI 层统一使用 **libuv 事件循环机制**，原因：

1. **与 Node.js 集成**：NAPI 运行在 Node.js 环境，必须使用 libuv
2. **线程安全**：libuv 保证回调在正确的线程执行
3. **生命周期管理**：自动管理异步任务的生命周期
4. **统一规范**：所有 NAPI 异步接口都使用此模式

### 3.2 libuv 异步模式对比

```cpp
// ❌ 错误：使用 std::thread
auto asyncWork = [impl, params, deferred, env]() {
    int32_t ret = impl->MoveTo(params);
    // 直接操作 NAPI 对象 - 线程不安全！
    napi_resolve_deferred(env, deferred, result);
};
std::thread(asyncWork).detach();

// ✅ 正确：使用 libuv
uv_loop_s *loop = nullptr;
napi_get_uv_event_loop(env, &loop);

uv_work_t *work = new uv_work_t;
work->data = callbackInfo;

uv_queue_work_with_qos_internal(
    loop, work,
    [](uv_work_t *work) {
        // 工作线程：执行耗时操作
        CallMoveToTask(work);
    },
    [](uv_work_t *work, int32_t status) {
        // 主线程回调：处理 Promise
        CallMoveToPromise(work, status);
    },
    uv_qos_user_initiated,
    "moveTo");
```

### 3.3 libuv 工作流程

```
┌──────────────┐
│ NAPI 调用    │ (主线程)
│ MoveTo()     │
└──────┬───────┘
       │ 1. 创建 uv_work_t
       │ 2. 设置回调信息
       │ 3. 提交到 libuv
       ↓
┌──────────────┐
│ 工作线程池   │ (libuv 管理)
│ CallMoveToTask│
│ - 执行 impl->MoveTo()
│ - 保存结果到 cb->errCode
└──────┬───────┘
       │ 任务完成
       ↓
┌──────────────┐
│ 主线程回调   │ (libuv 调度)
│ CallMoveToPromise│
│ - 读取 cb->errCode
│ - resolve/reject Promise
└──────────────┘
```
