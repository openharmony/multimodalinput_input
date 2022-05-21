/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef I_INPUT_EVENT_CONSUMER_H
#define I_INPUT_EVENT_CONSUMER_H

#include <memory>

#include "axis_event.h"
#include "key_event.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
struct IInputEventConsumer {
public:
    IInputEventConsumer() = default;
    virtual ~IInputEventConsumer() = default;

    virtual void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const;
    virtual void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const;
    virtual void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const;
};
} // namespace MMI
} // namespace OHOS
#endif // I_INPUT_EVENT_CONSUMER_H