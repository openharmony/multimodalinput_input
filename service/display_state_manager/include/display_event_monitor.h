/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef DISPLAY_EVENT_MONITOR_H
#define DISPLAY_EVENT_MONITOR_H

#include "nocopyable.h"
#include "singleton.h"

#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "want.h"

#include "define_multimodal.h"
#include "fingersense_manager.h"
#include "fingersense_wrapper.h"
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
#include "key_event_normalize.h"
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#include "mmi_log.h"
#include "util.h"

namespace OHOS {
namespace MMI {
class DelegateInterface;
class DisplayEventMonitor final {
    DECLARE_DELAYED_SINGLETON(DisplayEventMonitor);
    public:
        DISALLOW_COPY_AND_MOVE(DisplayEventMonitor);

        void UpdateShieldStatusOnScreenOn();
        void UpdateShieldStatusOnScreenOff();
        void InitCommonEventSubscriber();
        bool IsCommonEventSubscriberInit();
        void SetScreenStatus(const std::string &screenStatus)
        {
            screenStatus_ = screenStatus;
        }
        const std::string GetScreenStatus()
        {
            return screenStatus_;
        }
        void SetScreenLocked(bool isLocked)
        {
            isScreenLocked_ = isLocked;
        }
        bool GetScreenLocked() const
        {
            return isScreenLocked_;
        }
        void SetDelegateProxy(std::shared_ptr<DelegateInterface> proxy)
        {
            delegateProxy_ = proxy;
        }
        void SendCancelEventWhenLock();
    private:
        int32_t shieldModeBeforeSreenOff_ { -1 };
        std::atomic<bool> hasInit_ { false };
        std::string screenStatus_;
        bool isScreenLocked_ { true };
        std::shared_ptr<DelegateInterface> delegateProxy_ { nullptr };
};
#define DISPLAY_MONITOR ::OHOS::DelayedSingleton<DisplayEventMonitor>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // DISPLAY_EVENT_MONITOR_H
