# MouseController 实现约束条件补充

本文档记录了在实现 MouseController 过程中，通过交流确认的补充约束条件和设计决策。

## 日期
2025年（根据代码版权信息）

## 补充约束条件

### 1. PointerEvent 的 displayId 处理
**问题**：PointerEvent 没有直接的 displayId 字段

**解决方案**：
- 使用 `SetTargetDisplayId()` 方法（继承自 InputEvent 基类）
- 示例：`pointerEvent->SetTargetDisplayId(displayId)`

### 2. SimulateInputEvent 返回值
**问题**：最初误认为 SimulateInputEvent 返回 int32_t

**实际情况**：
- `SimulateInputEvent()` 返回 `void`，无返回值
- 调用方式：`InputManager::GetInstance()->SimulateInputEvent(event, false, PointerEvent::DISPLAY_COORDINATE)`
- 不需要检查返回值

### 3. NAPI 实现架构约束
**约束**：NAPI 实现中不要引用 ANI 实现的头文件

**具体要求**：
- ❌ 不要包含 `ani_common.h`
- ✅ 应该引用 `util_napi_error.h`
- ✅ 必须包含 `napi_constants.h`
- 错误码可以在 NAPI 层临时定义，添加 TODO 注释说明后续需要移到 util_napi_error.h

### 4. 权限校验架构（方案B）
**决策**：服务端不维护状态，只做权限校验

**实现方式**：
- 客户端（NAPI层）：维护所有状态（按键状态、轴事件状态、光标位置）
- 服务端（MMIService）：只进行权限校验
- 权限检查：只检查 `INPUT_DEVICE_CONTROLLER` 权限
- **不需要**系统应用校验（`VerifySystemApp()`）

**IPC 调用链**：
```
NAPI (CreateMouseController)
  → InputManager::CreateMouseController()
    → InputManagerImpl::CreateMouseController()
      → MultimodalInputConnectManager::CreateMouseController()
        → MMIService::CreateMouseController()  // 权限校验
```

### 5. 线程模型
**约束**：不要在 NAPI 实现中使用 std::thread 创建线程

**参考实现**：
- 参考 `js_register_module.cpp` 中的接口实现
- 如 `InjectMouseEvent`、`InjectTouchEvent` 等
- 采用同步执行方式，直接调用后返回 Promise

**实现模式**：
```cpp
// 同步执行
int32_t result = controller->SomeMethod(params);

// 创建 Promise
napi_deferred deferred;
napi_value promise;
napi_create_promise(env, &deferred, &promise);

// 根据结果 resolve 或 reject
if (result == RET_OK) {
    napi_resolve_deferred(env, deferred, nullptr);
} else {
    napi_value error = CreateBusinessError(env, result, "Operation failed");
    napi_reject_deferred(env, deferred, error);
}

return promise;
```

### 6. NAPI 常量定义
**约束**：使用正确的 NAPI 常量名称

**具体要求**：
- ❌ 不要使用 `GET_INT32`（未定义）
- ✅ 使用 `GET_VALUE_INT32`
- 这些常量定义在 `napi_constants.h` 中

### 7. IDL 接口声明
**要求**：新增 IPC 接口需要在 IDL 文件中声明

**文件位置**：
- `service/connect_manager/IMultimodalInputConnect.idl`

**声明格式**：
```idl
void CreateMouseController();
```

## 实现检查清单

- [x] 使用 `SetTargetDisplayId()` 设置 displayId
- [x] `SimulateInputEvent()` 不检查返回值
- [x] 不包含 `ani_common.h`，使用 `util_napi_error.h`
- [x] 包含 `napi_constants.h`
- [x] 服务端只做权限校验，不维护状态
- [x] 不使用 `VerifySystemApp()` 检查
- [x] 不使用 `std::thread`，采用同步执行
- [x] 使用 `GET_VALUE_INT32` 而非 `GET_INT32`
- [x] 在 IDL 文件中添加接口声明

## 文件清单

### 新增文件
1. `frameworks/napi/input_event_client/include/js_mouse_controller.h`
2. `frameworks/napi/input_event_client/src/js_mouse_controller.cpp`
3. `frameworks/napi/input_event_client/include/js_mouse_controller_napi.h`
4. `frameworks/napi/input_event_client/src/js_mouse_controller_napi.cpp`

### 修改文件
1. `frameworks/napi/input_event_client/src/js_register_module.cpp` - 添加模块导出
2. `frameworks/napi/input_event_client/BUILD.gn` - 添加源文件
3. `service/module_loader/include/mmi_service.h` - 添加接口声明
4. `service/module_loader/src/mmi_service.cpp` - 实现权限检查
5. `interfaces/native/innerkits/proxy/include/input_manager.h` - 添加接口
6. `frameworks/proxy/events/src/input_manager.cpp` - 添加实现
7. `frameworks/proxy/event_handler/include/input_manager_impl.h` - 添加接口
8. `frameworks/proxy/event_handler/src/input_manager_impl.cpp` - 添加实现
9. `service/connect_manager/include/multimodal_input_connect_manager.h` - 添加接口
10. `service/connect_manager/src/multimodal_input_connect_manager.cpp` - 添加实现
11. `service/connect_manager/IMultimodalInputConnect.idl` - 添加 IDL 声明

## 关键代码片段

### 权限检查（服务端）
```cpp
ErrCode MMIService::CreateMouseController()
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        return MMISERVICE_NOT_RUNNING;
    }
    // 只检查 INPUT_DEVICE_CONTROLLER 权限
    if (!PER_HELPER->CheckInputDeviceController()) {
        MMI_HILOGE("Check INPUT_DEVICE_CONTROLLER permission failed");
        return ERROR_NO_PERMISSION;
    }
    return RET_OK;
}
```

### NAPI 同步执行模式
```cpp
napi_value MouseControllerMoveTo(napi_env env, napi_callback_info info)
{
    // 参数提取
    int32_t displayId, x, y;
    CHKRP(napi_get_value_int32(env, argv[0], &displayId), GET_VALUE_INT32);
    CHKRP(napi_get_value_int32(env, argv[1], &x), GET_VALUE_INT32);
    CHKRP(napi_get_value_int32(env, argv[2], &y), GET_VALUE_INT32);

    // 获取实例
    JsMouseController* controller = nullptr;
    CHKRP(napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controller)), UNWRAP);

    // 同步执行
    int32_t result = controller->MoveTo(displayId, x, y);

    // 返回 Promise
    napi_deferred deferred;
    napi_value promise;
    CHKRP(napi_create_promise(env, &deferred, &promise), CREATE_PROMISE);

    if (result == RET_OK) {
        CHKRP(napi_resolve_deferred(env, deferred, nullptr), RESOLVE_DEFERRED);
    } else {
        napi_value error = CreateBusinessError(env, result, "MoveTo failed");
        CHKRP(napi_reject_deferred(env, deferred, error), REJECT_DEFERRED);
    }

    return promise;
}
```

## 注意事项

1. **客户端状态管理**：所有状态（按键、轴事件、光标位置）都在客户端维护
2. **服务端职责**：仅负责权限校验，不维护任何 MouseController 相关状态
3. **同步执行**：NAPI 层采用同步调用，不创建额外线程
4. **错误处理**：通过 Promise reject 返回错误，使用 CreateBusinessError 创建业务错误对象
5. **头文件依赖**：严格区分 NAPI 层和 ANI 层的头文件依赖关系
