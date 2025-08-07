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

#ifndef MMI_SWITCH_SUBSCRIBER_HANDLER_MOCK_H
#define MMI_SWITCH_SUBSCRIBER_HANDLER_MOCK_H
#include <cstdint>
#include <gmock/gmock.h>
#include "key_option.h"
#include "uds_session.h"

namespace OHOS {
namespace MMI {
class ISwitchSubscriberHandler {
public:
    ISwitchSubscriberHandler() = default;
    virtual ~ISwitchSubscriberHandler() = default;

    virtual int32_t SubscribeSwitchEvent(SessionPtr sess, int32_t subscribeId, int32_t switchType) = 0;
    virtual int32_t UnsubscribeSwitchEvent(SessionPtr sess, int32_t subscribeId) = 0;
    virtual int32_t QuerySwitchStatus(int32_t switchType, int32_t& state) = 0;
};

class SwitchSubscriberHandler : public ISwitchSubscriberHandler {
public:
    SwitchSubscriberHandler() = default;
    virtual ~SwitchSubscriberHandler() override = default;

    MOCK_METHOD(int32_t, SubscribeSwitchEvent, (SessionPtr, int32_t, int32_t));
    MOCK_METHOD(int32_t, UnsubscribeSwitchEvent, (SessionPtr, int32_t));
    MOCK_METHOD(int32_t, QuerySwitchStatus, (int32_t, int32_t&));
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_SWITCH_SUBSCRIBER_HANDLER_MOCK_H