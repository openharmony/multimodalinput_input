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

#ifndef MMI_INPUT_ACTIVE_SUBSCRIBER_HANDLER_MOCK_H
#define MMI_INPUT_ACTIVE_SUBSCRIBER_HANDLER_MOCK_H

#include <memory>

#include "nocopyable.h"

#include "i_input_event_handler.h"
#include "key_event.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class IInputActiveSubscriberHandler : public IInputEventHandler {
public:
    IInputActiveSubscriberHandler() = default;
    virtual ~IInputActiveSubscriberHandler() = default;
};

class InputActiveSubscriberHandler final : public IInputActiveSubscriberHandler {
public:
    InputActiveSubscriberHandler() = default;
    ~InputActiveSubscriberHandler() override = default;
    DISALLOW_COPY_AND_MOVE(InputActiveSubscriberHandler);

    MOCK_METHOD(void, HandleKeyEvent, (const std::shared_ptr<KeyEvent>));
    MOCK_METHOD(void, HandlePointerEvent, (const std::shared_ptr<PointerEvent>));
    MOCK_METHOD(void, HandleTouchEvent, (const std::shared_ptr<PointerEvent>));
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_INPUT_ACTIVE_SUBSCRIBER_HANDLER_MOCK_H