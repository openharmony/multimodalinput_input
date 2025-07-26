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

#ifndef MMI_KEY_MONITOR_MANAGER_MOCK_H
#define MMI_KEY_MONITOR_MANAGER_MOCK_H
#include <cstdint>
#include <gmock/gmock.h>
#include "key_event.h"

namespace OHOS {
namespace MMI {
class IKeyMonitorManager {
public:
    struct Monitor {
        int32_t session_ { -1 };
        int32_t key_ { KeyEvent::KEYCODE_UNKNOWN };
        int32_t action_ { KeyEvent::KEY_ACTION_UNKNOWN };
        bool isRepeat_ { false };
    };

    IKeyMonitorManager() = default;
    virtual ~IKeyMonitorManager() = default;

    virtual int32_t AddMonitor(const Monitor &monitor) = 0;
    virtual void RemoveMonitor(const Monitor &monitor) = 0;
};

class KeyMonitorManager final : public IKeyMonitorManager {
public:
    KeyMonitorManager() = default;
    ~KeyMonitorManager() override = default;

    MOCK_METHOD(int32_t, AddMonitor, (const Monitor&));
    MOCK_METHOD(void, RemoveMonitor, (const Monitor&));

    static std::shared_ptr<KeyMonitorManager> GetInstance();
    static void ReleaseInstance();

private:
    static std::shared_ptr<KeyMonitorManager> instance_;
};

#define KEY_MONITOR_MGR KeyMonitorManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MMI_KEY_MONITOR_MANAGER_MOCK_H