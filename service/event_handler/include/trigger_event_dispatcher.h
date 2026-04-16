/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TRIGGER_EVENT_DISPATCHER_H
#define TRIGGER_EVENT_DISPATCHER_H

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <set>
#include <cstdint>

#include "key_event.h"
#include "key_option.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {

enum KeyCommandTriggerType {
    PRESSED = 1,
    REPEAT_PRESSED = 2,
    ALL_RELEASED = 3
};

class TriggerEventDispatcher {
public:
    static TriggerEventDispatcher* GetInstance();
    ~TriggerEventDispatcher() = default;

    bool ShouldDispatch(std::shared_ptr<KeyOption> keyOption,
                       std::shared_ptr<KeyEvent> keyEvent);

    bool ShouldConsume(std::shared_ptr<KeyOption> keyOption,
                      std::shared_ptr<KeyEvent> keyEvent);

    void ClearSubscribeState(const std::string& subscribeKey);

    void ClearSubscribeState(std::shared_ptr<KeyOption> keyOption);

private:
    TriggerEventDispatcher() = default;
    TriggerEventDispatcher(const TriggerEventDispatcher&) = delete;
    TriggerEventDispatcher& operator=(const TriggerEventDispatcher&) = delete;

    bool ShouldDispatchPRESSED(std::shared_ptr<KeyOption> keyOption,
                              std::shared_ptr<KeyEvent> keyEvent);

    bool ShouldDispatchREPEAT_PRESSED(std::shared_ptr<KeyOption> keyOption,
                                    std::shared_ptr<KeyEvent> keyEvent);

    bool ShouldDispatchALL_RELEASED(std::shared_ptr<KeyOption> keyOption,
                                    std::shared_ptr<KeyEvent> keyEvent);

    bool MatchPreKeys(std::shared_ptr<KeyOption> keyOption,
                      std::shared_ptr<KeyEvent> keyEvent);

    bool CheckDuration(std::shared_ptr<KeyOption> keyOption,
                       std::shared_ptr<KeyEvent> keyEvent);
    bool HasOtherKeyPressedInWindow(const std::string& subscribeKey);
    void StartDurationWindow(const std::string& subscribeKey, int32_t duration);
    void MarkDurationPassed(const std::string& subscribeKey);
    std::string GenerateSubscribeKey(std::shared_ptr<KeyOption> keyOption);

private:
    bool CheckDurationWindowPassed(const std::string& subscribeKey);
    bool CheckDurationWindowWithOtherKey(const std::string& subscribeKey);
    struct AllReleasedDispatchState {
        bool comboActivated { false };
        std::set<int32_t> pressedComboKeys;
    };

private:
    std::mutex mutex_;
    std::map<std::string, bool> firstDownSent_;
    std::map<std::string, int64_t> downStartTime_;
    std::map<std::string, bool> durationPassed_;
    std::map<std::string, bool> hasOtherKey_;
    std::map<std::string, AllReleasedDispatchState> allReleasedDispatchStates_;
};
} // namespace MMI
} // namespace OHOS

#endif // TRIGGER_EVENT_DISPATCHER_H
