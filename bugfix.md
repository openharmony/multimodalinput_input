# 用户切换时光标闪烁问题修复

## 1. 问题现象

多用户场景下，激活多个用户后分别设置不同光标颜色和大小，在某用户中 kill 多模进程后切换至其他用户时，光标出现短暂闪烁。

### 复现步骤
1. 启动多用户功能并创建多个用户（如用户1、用户2）；
2. 分别激活用户1和用户2，并为每个用户设置不同的光标颜色和大小；
3. 在用户1中执行 `kill -9 $(pidof multimodalinput)` 强制终止多模进程；
4. 切换到用户2时，光标出现短暂的默认样式闪烁。

### 视频参考
https://onebox.huawei.com/perfect/preview/previewPage/2947550/158?type=video&1771920539388

---

## 2. 问题原因

多模进程死亡后，内存中缓存的鼠标相关的设置。项丢失，再次重启后首次切换到某用户时存在下面问题：

### 线程时序与异步加载冲突

1. **事件回调线程**：监听到 `COMMON_EVENT_USER_SWITCHED` 事件后，系统在回调线程中通过 ffrt 线程异步加载目标用户（用户2）的光标配置到内存（从数据库读取）；
2. **窗口同步线程**：用户点击切换用户后，窗口服务通过同步窗口信息到多模进程（工作线程），并触发光标绘制逻辑；
3. **时序问题**：
   - 窗口同步优先执行，触发光标绘制逻辑；
   - 此时 ffrt 线程的异步加载任务尚未完成，系统查询到默认光标配置；
   - 异步加载完成后，光标样式更新为正确配置，导致短暂闪烁。

### 异步加载机制缺陷

- 未在光标绘制逻辑中加入对配置加载状态的检查；
- 未设置等待机制或回调通知，确保配置加载完成后再执行绘制。

---

## 3. 定位结论

### 根本原因
`COMMON_EVENT_USER_SWITCHED` 事件的回调线程通过 ffrt 线程异步加载配置，与窗口同步线程的执行时序冲突，导致光标绘制时查询到默认配置。

### 关键代码/模块
- **公共事件回调逻辑**：`COMMON_EVENT_USER_SWITCHED` 事件的处理函数 `OnSwitchUser`（service/account_manager/src/account_manager.cpp）
- **ffrt 线程管理**：异步加载用户配置的 ffrt 队列 `OnSwitchUser` 中 `ffrtHandler_->submit` 处理逻辑（service/setting_manager/src/setting_manager.cpp）
- **窗口同步逻辑**：`InputWindowsManager::UpdateDisplayInfo` 中触发 `CursorDrawingComponent::OnWindowInfo`（service/window_manager/src/input_windows_manager.cpp）
- **光标绘制逻辑**：多模进程的工作线程中触发光标绘制的代码 `OnWindowInfo -> UpdatePointerVisible -> InitLayer -> HardwareCursorRender -> CreateRenderConfig`（获取当前用户的鼠标颜色、大小等）（service/window_manager/src/pointer_drawing_manager.cpp）

---

## 4. 问题影响评估

### 影响范围
- 所有多用户场景中涉及光标自定义配置的用户；
- 仅在多模进程被 kill 后首次切换用户时复现（冷启动场景）。

### 严重性
- **低**：影响用户体验（视觉异常），但不导致功能失效或系统崩溃。

---

## 5. 优化方案

### 方案选择
**状态检查 + 缓存回退机制**

### 核心思路
1. **添加用户配置加载状态追踪**：在 `SettingManager` 中追踪每个用户的配置加载状态
2. **缓存上次有效配置**：在 `PointerDrawingManager` 中缓存上次成功获取的配置
3. **双重检查回退机制**：配置未加载完成时，使用缓存配置而非默认配置
4. **异步加载完成通知**：配置加载完成后通知 `PointerDrawingManager` 重新绘制光标

### 方案优势
- ✅ 保持异步加载机制，不影响性能
- ✅ 接口完全兼容，无需修改外部调用
- ✅ 响应时间敏感，无阻塞等待
- ✅ 解决冷启动场景的闪烁问题
- ✅ 模块解耦：光标操作都在 `PointerDrawingManager` 中处理

### 潜在问题
- ⚠️ 缓存一致性：缓存仅在配置加载期间使用，加载完成后立即更新
- ⚠️ 短暂显示错误配置：切换用户时可能短暂显示其他用户的配置，但比显示默认值好

---

## 6. 实施修改

### 6.1 SettingManager 模块修改

#### setting_manager.h
**添加用户配置加载状态追踪数据结构：**
```cpp
// 在 private 部分添加
std::unordered_map<int32_t, bool> userConfigLoadedMap_;
std::mutex userConfigLoadedMutex_;

// 添加辅助方法
void MarkUserConfigLoading(int32_t userId);
void MarkUserConfigLoaded(int32_t userId);
bool IsUserConfigLoaded(int32_t userId) const;
```

#### i_setting_manager.h
**添加查询配置加载状态的纯虚函数：**
```cpp
// 在 public 部分添加
virtual bool IsUserConfigLoaded(int32_t userId) const = 0;
```

#### setting_manager.cpp
**添加头文件：**
```cpp
#include "i_pointer_drawing_manager.h"
#include "cursor_drawing_component.h"
```

**添加辅助方法实现：**
```cpp
void SettingManager::MarkUserConfigLoading(int32_t userId)
{
    std::lock_guard<std::mutex> guard(userConfigLoadedMutex_);
    userConfigLoadedMap_[userId] = false;
    MMI_HILOGI("Mark user config loading, userId:%{private}d", userId);
}

void SettingManager::MarkUserConfigLoaded(int32_t userId)
{
    std::lock_guard<std::mutex> guard(userConfigLoadedMutex_);
    userConfigLoadedMap_[userId] = true;
    MMI_HILOGI("Mark user config loaded, userId:%{private}d", userId);
}

bool SettingManager::IsUserConfigLoaded(int32_t userId) const
{
    std::lock_guard<std::mutex> guard(userConfigLoadedMutex_);
    auto iter = userConfigLoadedMap_.find(userId);
    if (iter != userConfigLoadedMap_.end()) {
        return iter->second;
    }
    return false;
}
```

**修改 OnDataShareReady()：**
```cpp
ffrtHandler_->submit([this] {
    flushFlag_.store(true);
    int32_t userId = ACCOUNT_MGR->QueryCurrentAccountId();
    MMI_HILOGI("Run task in data share ready, current id:%{private}d", userId);
    
    // Mark user config loading
    MarkUserConfigLoading(userId);
    
    ReadSettingData(userId);
    if (GetVersion(userId) != VERSION_NUMBERS_LATEST) {
        MMI_HILOGI("Migrate settings for all user");
        INPUT_SETTING_MIGRATOR.Initialize(defaultSettingData_);
        if (!INPUT_SETTING_MIGRATOR.Migrator()) {
            MMI_HILOGE("MigrateSettings failed");
        }
        ReadSettingData(userId);
    }
    CommitStagedChanges();
#ifdef OHOS_BUILD_ENABLE_TOUCHPAD
    TouchPadTransformProcessor::OnDataShareReady(userId);
#endif  // OHOS_BUILD_ENABLE_TOUCHPAD
    flushFlag_.store(false);
    databaseReadyFlag_.store(true);
    
    // Mark user config loaded
    MarkUserConfigLoaded(userId);
});
```

**修改 OnSwitchUser()：**
```cpp
ffrtHandler_->submit([this, userId] {
    MMI_HILOGI("Run task on switch, id:%{private}d", userId);
    
    // Mark user config loading
    MarkUserConfigLoading(userId);
    
    flushFlag_.store(true);
    if (CheckAddUser(userId)) {
        MMI_HILOGI("Add id switch, id:%{private}d", userId);
        flushFlag_.store(false);
        // Mark user config loaded
        MarkUserConfigLoaded(userId);
        // Notify PointerDrawingManager
        CursorDrawingComponent::GetInstance().OnSwitchUser(userId);
        return;
    }
    ReadSettingData(userId);
    if (GetVersion(userId) != VERSION_NUMBERS_LATEST) {
        MMI_HILOGI("Need migrateSettings");
        if (!INPUT_SETTING_MIGRATOR.MigratorUserData(userId)) {
            MMI_HILOGE("MigrateSettings failed");
        }
        ReadSettingData(userId);
    }
    CommitStagedChanges();
#ifdef OHOS_BUILD_ENABLE_TOUCHPAD
    TouchPadTransformProcessor::OnSwitchUser(userId);
#endif  // OHOS_BUILD_ENABLE_TOUCHPAD
    flushFlag_.store(false);
    
    // Mark user config loaded
    MarkUserConfigLoaded(userId);
    
    // Notify PointerDrawingManager to redraw cursor
    CursorDrawingComponent::GetInstance().OnSwitchUser(userId);
});
```

**修改 OnRemoveUser()：**
```cpp
void SettingManager::OnRemoveUser(int32_t userId)
{
    MMI_HILOGI("In remove, id:%{private}d", userId);
    std::lock_guard<std::mutex> guard(cacheMapMutex_);
    if (auto it = cacheSettingMap_.find(userId); it != cacheSettingMap_.end()) {
        cacheSettingMap_.erase(it);
        MMI_HILOGI("Account(%d) has been removed", userId);
    } else {
        MMI_HILOGW("No account(%d)", userId);
    }
    INPUT_SETTING_MANAGER->OnRemoveUser(userId);
    
    // Clear user config loaded status
    {
        std::lock_guard<std::mutex> loadGuard(userConfigLoadedMutex_);
        userConfigLoadedMap_.erase(userId);
    }
}
```

---

### 6.2 PointerDrawingManager 模块修改

#### i_pointer_drawing_manager.h
**添加 OnSwitchUser 纯虚函数：**
```cpp
// 在 public 部分添加
virtual void OnSwitchUser(int32_t userId) {}
```

#### pointer_drawing_manager.h
**添加配置缓存结构体和成员变量：**
```cpp
// 在文件开头添加
struct CachedPointerConfig {
    int32_t color;
    int32_t size;
    bool isValid;
    CachedPointerConfig() : color(DEFAULT_VALUE), size(DEFAULT_POINTER_SIZE), isValid(false) {}
};

// 在 public 部分添加
void OnSwitchUser(int32_t userId) override;

// 在 private 部分添加
CachedPointerConfig cachedPointerConfig_;
std::mutex configCacheMutex_;
```

#### pointer_drawing_manager.cpp
**实现 OnSwitchUser() 方法：**
```cpp
void PointerDrawingManager::OnSwitchUser(int32_t userId)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGI("OnSwitchUser called, userId:%{private}d", userId);
    
    // Get current user's configuration from CursorDrawingInformation
    PointerStyle curPointerStyle;
    CursorDrawingInformation::GetInstance().GetPointerStyle(userId, pid_, GLOBAL_WINDOW_ID, curPointerStyle);
    
    // Preserve options from lastMouseStyle_
    curPointerStyle.options = lastMouseStyle_.options;
    
    // Notify InputWindowsManager of new pointer style
    if (WIN_MGR->SetPointerStyle(pid_, GLOBAL_WINDOW_ID, curPointerStyle) != RET_OK) {
        MMI_HILOGE("Set pointer style failed");
        return;
    }
    
    // Call DrawPointerStyle to redraw cursor (this will update lastMouseStyle_ internally)
    DrawPointerStyle(curPointerStyle);
    
    MMI_HILOGI("OnSwitchUser completed, pointerStyle.id:%{public}d, color:%{public}d, size:%{public}d", 
        curPointerStyle.id, curPointerStyle.color, curPointerStyle.size);
}
```

**修改 GetPointerColor()：**
```cpp
int32_t PointerDrawingManager::GetPointerColor(int32_t userId)
{
    CALL_DEBUG_ENTER;
    std::string name = POINTER_COLOR;
    GetPreferenceKey(name);
    int32_t pointerColor = DEFAULT_VALUE;
    
    // Check if config is loaded
    bool configLoaded = INPUT_SETTING_MANAGER->IsUserConfigLoaded(userId);
    
    INPUT_SETTING_MANAGER->GetIntValue(userId, MOUSE_KEY_SETTING, name, pointerColor);
    
    if (configLoaded) {
        // Config loaded, update cache
        {
            std::lock_guard<std::mutex> guard(configCacheMutex_);
            cachedPointerConfig_.color = pointerColor;
            cachedPointerConfig_.isValid = true;
        }
        tempPointerColor_ = pointerColor;
    } else {
        // Config not loaded, use last valid config (without userId validation)
        MMI_HILOGW("User config not loaded, using last valid config, userId:%{private}d", userId);
        std::lock_guard<std::mutex> guard(configCacheMutex_);
        if (cachedPointerConfig_.isValid) {
            pointerColor = cachedPointerConfig_.color;
            MMI_HILOGI("Use cached pointer color:%{public}d", pointerColor);
        } else {
            // Cache invalid, use default value
            pointerColor = MIN_POINTER_COLOR;
            MMI_HILOGW("No valid cached config, use default color");
        }
        tempPointerColor_ = pointerColor;
    }
    
    if (pointerColor == DEFAULT_VALUE) {
        pointerColor = MIN_POINTER_COLOR;
    }
    MMI_HILOGD("Get pointer color successfully, pointerColor:%{public}d", pointerColor);
    return pointerColor;
}
```

**修改 GetPointerSize()：**
```cpp
int32_t PointerDrawingManager::GetPointerSize(int32_t userId)
{
    CALL_DEBUG_ENTER;
    std::string name = POINTER_SIZE;
    GetPreferenceKey(name);
    int32_t pointerSize = DEFAULT_POINTER_SIZE;
    
    // Check if config is loaded
    bool configLoaded = INPUT_SETTING_MANAGER->IsUserConfigLoaded(userId);
    
    INPUT_SETTING_MANAGER->GetIntValue(userId, MOUSE_KEY_SETTING, name, pointerSize);
    
    if (configLoaded) {
        // Config loaded, update cache
        {
            std::lock_guard<std::mutex> guard(configCacheMutex_);
            cachedPointerConfig_.size = pointerSize;
            cachedPointerConfig_.isValid = true;
        }
        MMI_HILOGD("Get pointer size successfully, pointerSize:%{public}d", pointerSize);
    } else {
        // Config not loaded, use last valid config (without userId validation)
        MMI_HILOGW("User config not loaded, using last valid config, userId:%{private}d", userId);
        std::lock_guard<std::mutex> guard(configCacheMutex_);
        if (cachedPointerConfig_.isValid) {
            pointerSize = cachedPointerConfig_.size;
            MMI_HILOGI("Use cached pointer size:%{public}d", pointerSize);
        } else {
            // Cache invalid, use default value
            pointerSize = DEFAULT_POINTER_SIZE;
            MMI_HILOGW("No valid cached config, use default size");
        }
        MMI_HILOGD("Get pointer size successfully, pointerSize:%{public}d", pointerSize);
    }
    
    return pointerSize;
}
```

---

### 6.3 CursorDrawingComponent 模块修改

#### cursor_drawing_component.h
**添加方法声明：**
```cpp
// 在 public 部分添加
void OnSwitchUser(int32_t userId);
```

#### cursor_drawing_component.cpp
**添加方法实现：**
```cpp
void CursorDrawingComponent::OnSwitchUser(int32_t userId)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->OnSwitchUser(userId);
}
```

---

## 7. 测试验证计划

### 7.1 单元测试
- 验证 `IsUserConfigLoaded()` 接口正确返回状态
- 验证配置缓存机制正常工作
- 验证 `OnSwitchUser()` 方法正确更新光标样式

### 7.2 集成测试
- 多用户场景下切换用户，验证光标不闪烁
- kill 多模进程后重启，验证首次切换用户光标不闪烁
- 验证配置加载完成后光标样式正确更新

### 7.3 回归测试
- 验证现有功能不受影响：
  - 单用户场景光标设置
  - 光标颜色/大小修改
  - 其他设置项读写

---

## 8. 风险评估

### 低风险
- ✅ 接口兼容：新增接口，不修改现有接口
- ✅ 性能影响：仅增加简单的状态检查和缓存访问，性能影响可忽略
- ✅ 线程安全：使用 mutex 保护共享数据
- ✅ 模块解耦：光标操作都在 `PointerDrawingManager` 中处理

### 需要注意
- ⚠️ 缓存一致性：缓存仅在配置加载期间使用，加载完成后立即更新
- ⚠️ 短暂显示错误配置：切换用户时可能短暂显示其他用户的配置，但比显示默认值好

---

## 9. 实施步骤

1. ✅ 修改 SettingManager（setting_manager.h, setting_manager.cpp, i_setting_manager.h）
2. ✅ 修改 PointerDrawingManager（i_pointer_drawing_manager.h, pointer_drawing_manager.h, pointer_drawing_manager.cpp）
3. ✅ 修改 CursorDrawingComponent（cursor_drawing_component.h, cursor_drawing_component.cpp）
4. ⏳️ 编译验证：确保代码编译通过
5. ⏳️ 单元测试：运行相关单元测试
6. ⏳️ 集成测试：在真实环境中验证修复效果
7. ⏳️ 代码审查：提交代码审查

---

## 10. 总结

通过状态检查 + 缓存回退机制解决用户切换时光标闪烁问题：

1. **配置加载状态追踪**：`SettingManager` 追踪每个用户的配置加载状态
2. **异步加载完成通知**：配置加载完成后通知 `PointerDrawingManager` 重新绘制光标
3. **缓存回退机制**：配置未加载完成时，使用上一次有效配置而非默认配置
4. **不校验 userId**：缓存不校验 userId，切换用户时可以使用其他用户的配置作为临时值

这个方案解决了 kill 多模进程后重启时，首次切换用户光标闪烁的问题。
