/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TRIPLE_FINGER_SNAPSHOT_MANAGER_H
#define TRIPLE_FINGER_SNAPSHOT_MANAGER_H

#include <memory>
#include <string>
#include <mutex>
#include <atomic>
#include <map>

#include "i_delegate_interface.h"
#include "nocopyable.h"
#include "setting_observer.h"
#include "iremote_object.h"

namespace OHOS {
namespace MMI {

class PointerEvent;

/**
 * 三指截屏插件接口
 */
class ITripleFingerSnapshot {
public:
    ITripleFingerSnapshot() = default;
    virtual ~ITripleFingerSnapshot() = default;

    virtual bool HandleTouchEvent(std::shared_ptr<PointerEvent> event) = 0;
    virtual void Enable() = 0;
    virtual void Disable() = 0;
    virtual void UpdateDisplayInfo(int32_t displayWidth, int32_t displayHeight, int32_t direction) = 0;
    virtual void Dump(int32_t fd) = 0;
    virtual void UpdateAppsEnable(bool enabled) = 0;
};

/**
 * 三指截屏上下文接口
 */
class ITripleFingerSnapshotContext {
public:
    ITripleFingerSnapshotContext() = default;
    virtual ~ITripleFingerSnapshotContext() = default;

    virtual void TriggerScreenshot() = 0;
    virtual void TriggerAncoTripleFingerSnapshot() = 0;
};

/**
 * 三指截屏管理器组件
 * 负责动态加载和卸载三指截屏插件
 */
class TripleFingerSnapshotManager {
public:
    static TripleFingerSnapshotManager &GetInstance();

    /**
     * 初始化管理器
     * @return 成功返回true
     */
    bool Init();

    /**
     * 处理触摸事件
     * @param event 触摸事件
     * @return true表示事件被消费，false表示事件继续传递
     */
    bool HandleTouchEvent(std::shared_ptr<PointerEvent> event);

    /**
     * 启用三指截屏（加载插件）
     * @return 成功返回true
     */
    bool Enable();

    /**
     * 禁用三指截屏（卸载插件）
     * @return 成功返回true
     */
    bool Disable();

    /**
     * 更新显示信息
     * @param displayWidth 显示宽度
     * @param displayHeight 显示高度
     * @param direction 旋转角度
     */
    void UpdateDisplayInfo(int32_t displayWidth, int32_t displayHeight, int32_t direction);

    /**
     * 调试信息输出
     * @param fd 文件描述符
     */
    void Dump(int32_t fd);

    /**
     * 更新应用的三指截屏权限
     * @param uid 应用UID
     * @param enable 是否启用
     */
    void UpdateAppPermission(int32_t uid, bool enable);

    /**
     * 注册三指截屏开关监听
     * @param userId 用户id
     * @return 成功返回true
     */
    bool RegisterSwitchObserver(int32_t userId);

    void SetDelegateProxy(std::shared_ptr<IDelegateInterface> proxy);
    std::shared_ptr<IDelegateInterface> GetDelegateProxy();

    void SetDatashareReady(int32_t userId);

private:
    DISALLOW_COPY_AND_MOVE(TripleFingerSnapshotManager);
    TripleFingerSnapshotManager() = default;
    ~TripleFingerSnapshotManager() = default;

    std::shared_ptr<ITripleFingerSnapshot> GetImpl();
    std::shared_ptr<ITripleFingerSnapshot> Load();
    void Unload();
    void OnSwitchChanged(bool enabled);
    bool CheckAllAppsEnabled();
    bool LoadLibrary();
    bool LoadSymbols();
    bool CreateImpl();
    void CleanupOnError();
    bool IsObserverRegistered(int32_t userId);
    void UnregisterObserverForUser(int32_t userId);
    bool CreateAndRegisterObserver(int32_t userId);
private:
    using GetTripleFingerSnapshotFunc = ITripleFingerSnapshot*(*)(const std::shared_ptr<ITripleFingerSnapshotContext>&);
    using DestroyTripleFingerSnapshotFunc = void(*)(ITripleFingerSnapshot*);

    void *handle_ { nullptr };
    GetTripleFingerSnapshotFunc create_ { nullptr };
    DestroyTripleFingerSnapshotFunc destroy_ { nullptr };
    std::shared_ptr<ITripleFingerSnapshot> impl_;
    std::mutex mutex_;
    bool enabled_ { false };
    std::map<int32_t, bool> appPermissions_;
    std::shared_ptr<IDelegateInterface> delegateProxy_ { nullptr };
    int32_t currentAccountId_ { -1 };
    sptr<SettingObserver> switchObserver_;
    std::atomic_bool isDataShareReady_ { false };
};

/**
 * 三指截屏上下文实现
 * 提供插件所需的系统服务
 */
class TripleFingerSnapshotContext : public ITripleFingerSnapshotContext {
public:
    TripleFingerSnapshotContext() = default;
    ~TripleFingerSnapshotContext() override = default;

    void TriggerScreenshot() override;
    void TriggerAncoTripleFingerSnapshot() override;
    void TriggerAncoTripleFingerSnapshotExt();
};

} // namespace MMI
} // namespace OHOS

#endif // TRIPLE_FINGER_SNAPSHOT_MANAGER_H