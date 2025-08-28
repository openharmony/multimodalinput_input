/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef KEY_MONITOR_MANAGER_H
#define KEY_MONITOR_MANAGER_H

#include <map>
#include <mutex>

#include "key_event.h"
#include "key_option.h"

namespace OHOS {
namespace MMI {
class KeyMonitorManager final {
    struct PendingMonitor {
        int32_t timerId_ { -1 };
        std::shared_ptr<KeyEvent> keyEvent_;
    };

public:
    struct Monitor {
        int32_t session_ { -1 };
        int32_t key_ { KeyEvent::KEYCODE_UNKNOWN };
        int32_t action_ { KeyEvent::KEY_ACTION_UNKNOWN };
        bool isRepeat_ { false };

        bool operator<(const Monitor &other) const;
        std::string Dump() const;
        bool IsFocused() const;
        bool Want(std::shared_ptr<KeyEvent> keyEvent) const;
    };

    enum MonitorType : int32_t {
        MONITOR_ACTION_UNKNOWN = 0,
        MONITOR_ACTION_CANCEL = 1,
        MONITOR_ACTION_ONLY_DOWN = 2,
        MONITOR_ACTION_DOWN_AND_UP = 3
    };

    KeyMonitorManager();
    ~KeyMonitorManager() = default;
    DISALLOW_COPY_AND_MOVE(KeyMonitorManager);

    int32_t AddMonitor(const Monitor &monitor);
    void RemoveMonitor(const Monitor &monitor);
    bool Intercept(std::shared_ptr<KeyEvent> keyEvent);
    bool Intercept(std::shared_ptr<KeyEvent> KeyEvent, int32_t delay);
    void NotifyPendingMonitors();
    void ResetAll(int32_t keyCode);

    static std::shared_ptr<KeyMonitorManager> GetInstance();

private:
    void OnSessionLost(int32_t session);
    bool CheckMonitor(const Monitor &monitor);
    void NotifyKeyMonitor(std::shared_ptr<KeyEvent> keyEvent, int32_t session);

    std::set<Monitor> monitors_;
    std::map<Monitor, PendingMonitor> pending_;
    static const std::set<int32_t> allowedKeys_;
};

#define KEY_MONITOR_MGR KeyMonitorManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // KEY_MONITOR_MANAGER_H
