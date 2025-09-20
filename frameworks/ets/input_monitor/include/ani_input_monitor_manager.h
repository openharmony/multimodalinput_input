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

#ifndef ANI_INPUT_MONITOR_MANAGER_H
#define ANI_INPUT_MONITOR_MANAGER_H

#include <map>
#include <memory>
#include <mutex>

#include "ani_input_monitor_consumer.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class AniInputMonitorManager final {
public:
    static AniInputMonitorManager& GetInstance();
    DISALLOW_COPY_AND_MOVE(AniInputMonitorManager);
    ~AniInputMonitorManager() = default;

    std::shared_ptr<AniInputMonitorConsumer> GetMonitor(int32_t monitorId);
    TaiheTouchEventArray QueryTouchEvents(int32_t count);

    bool CreateCallback(callbackType &&cb, uintptr_t opq, std::shared_ptr<CallbackObject> &callback);
    bool IsExistCallback(const std::shared_ptr<CallbackObject> &callback, taihe::optional_view<uintptr_t> opq);

    bool AddMonitor(MONITORFUNTYPE funType, const ConsumerParmType &param,
        callbackType &&cb, uintptr_t opq);

    bool RemoveMonitor(MONITORFUNTYPE funType, taihe::optional_view<uintptr_t> opq, int32_t fingers = 0);

    bool CheckKeyCode(const int32_t keycode);
    void ThrowError(int32_t code);
private:
    AniInputMonitorManager() = default;
private:
     std::mutex mutex_;
     std::map<int32_t, std::shared_ptr<AniInputMonitorConsumer>> monitors_;
     std::mutex jsCbMapMutex;
};
#define ANI_INPUT_MONITOR_MGR ::OHOS::MMI::AniInputMonitorManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // JS_INPUT_MONITOR_MANAGER_H
