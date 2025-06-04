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

#ifndef INPUT_DEVICE_CONSUMER_HANDLER_H
#define INPUT_DEVICE_CONSUMER_HANDLER_H

#include <map>

#include <singleton.h>

#include "gesture_monitor_handler.h"
#include "i_input_event_collection_handler.h"
#include "i_input_event_handler.h"
#include "nap_process.h"

namespace OHOS {
namespace MMI {
class InputDeviceConsumerHandler {

public:

    int32_t SetDeviceConsumerHandler(const std::vector<std::string>& deviceName, SessionPtr sess);
    void OnSessionLost(SessionPtr session);
    int32_t ClearDeviceConsumerHandler(const std::vector<std::string>& deviceNames, SessionPtr sess);

    void HandleDeviceConsumerEvent(std::string name, const std::shared_ptr<PointerEvent> pointerEvent);
private:

    class SessionHandler {
    public:

        SessionHandler(SessionPtr session) : session_(session)
        {
        }

        SessionHandler(const SessionHandler& other)
        {
            session_ = other.session_;
        }

        void SendToClient(std::shared_ptr<PointerEvent> pointerEvent, NetPacket &pkt) const;
        void operator()(const SessionHandler& other)
        {
            session_ = other.session_;
        }
        bool operator<(const SessionHandler& other) const
        {
            return (session_ < other.session_);
        }
        std::string deviceName_ {""};
        SessionPtr session_ { nullptr };
    };
    class DeviceHandler {
    public:
        void HandleEvent(std::string name, std::shared_ptr<PointerEvent> pointerEvent);
        int32_t RemoveDeviceHandler(const std::vector<std::string>& deviceNames, SessionPtr sess);

        std::unordered_map<std::string, std::set<SessionHandler>> deviceHandler_;
    };
    DeviceHandler deviceConsumerHandler_;
};

#define DEVICEHANDLER ::OHOS::DelayedSingleton<InputDeviceConsumerHandler>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // INPUT_DEVICE_CONSUMER_HANDLER_H
