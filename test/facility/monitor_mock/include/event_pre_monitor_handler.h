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

#ifndef MMI_EVENT_PRE_MONITOR_HANDLER_MOCK_H
#define MMI_EVENT_PRE_MONITOR_HANDLER_MOCK_H

#include <cstdint>

#include "gmock/gmock.h"
#include "input_event_handler.h"
#include "uds_session.h"

namespace OHOS {
namespace MMI {
class IEventPreMonitorHandler {
public:
    IEventPreMonitorHandler() = default;
    virtual ~IEventPreMonitorHandler() = default;

    int32_t AddInputHandler(SessionPtr, int32_t, HandleEventType, std::vector<int32_t>);
    void RemoveInputHandler(SessionPtr, int32_t);
};

class EventPreMonitorHandler : public IEventPreMonitorHandler {
public:
    EventPreMonitorHandler() = default;
    virtual ~EventPreMonitorHandler() override = default;

    MOCK_METHOD(int32_t, AddInputHandler, (SessionPtr, int32_t, HandleEventType, std::vector<int32_t>));
    MOCK_METHOD(void, RemoveInputHandler, (SessionPtr, int32_t));
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_EVENT_PRE_MONITOR_HANDLER_MOCK_H
