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

#ifndef MMI_KEY_SUBSCRIBER_HANDLER_MOCK_H
#define MMI_KEY_SUBSCRIBER_HANDLER_MOCK_H

#include <cstdint>

#include "gmock/gmock.h"
#include "i_input_event_handler.h"
#include "key_option.h"
#include "uds_session.h"

namespace OHOS {
namespace MMI {
class IKeySubscriberHandler : public IInputEventHandler {
public:
    IKeySubscriberHandler() = default;
    virtual ~IKeySubscriberHandler() = default;

    virtual int32_t SubscribeKeyEvent(SessionPtr, int32_t, const std::shared_ptr<KeyOption>) = 0;
    virtual int32_t UnsubscribeKeyEvent(SessionPtr, int32_t) = 0;
};

class KeySubscriberHandler : public IKeySubscriberHandler {
public:
    KeySubscriberHandler() = default;
    virtual ~KeySubscriberHandler() override = default;

    MOCK_METHOD(void, HandleKeyEvent, (const std::shared_ptr<KeyEvent>));
    MOCK_METHOD(void, HandlePointerEvent, (const std::shared_ptr<PointerEvent>));
    MOCK_METHOD(void, HandleTouchEvent, (const std::shared_ptr<PointerEvent>));
    MOCK_METHOD(int32_t, SubscribeKeyEvent, (SessionPtr, int32_t, const std::shared_ptr<KeyOption>));
    MOCK_METHOD(int32_t, UnsubscribeKeyEvent, (SessionPtr, int32_t));
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_KEY_SUBSCRIBER_HANDLER_MOCK_H