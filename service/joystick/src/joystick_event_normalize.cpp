/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "joystick_event_normalize.h"

#include "input_device_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JoystickEventNormalize"

namespace OHOS {
namespace MMI {
std::shared_ptr<KeyEvent> JoystickEventNormalize::OnButtonEvent(struct libinput_event *event)
{
    CHKPP(event);
    auto inputDev = libinput_event_get_device(event);
    CHKPP(inputDev);
    auto processor = GetProcessor(inputDev);
    CHKPP(processor);
    return processor->OnButtonEvent(event);
}

std::shared_ptr<PointerEvent> JoystickEventNormalize::OnAxisEvent(struct libinput_event *event)
{
    CHKPP(event);
    auto inputDev = libinput_event_get_device(event);
    CHKPP(inputDev);
    auto processor = GetProcessor(inputDev);
    CHKPP(processor);
    return processor->OnAxisEvent(event);
}

void JoystickEventNormalize::CheckIntention(std::shared_ptr<PointerEvent> pointerEvent,
    std::function<void(std::shared_ptr<KeyEvent>)> handler)
{
    auto processor = FindProcessor(pointerEvent->GetDeviceId());
    if (processor == nullptr) {
        MMI_HILOGE("No processor associated with input device(%{public}d)", pointerEvent->GetDeviceId());
        return;
    }
    processor->CheckIntention(pointerEvent, handler);
}

std::shared_ptr<JoystickEventProcessor> JoystickEventNormalize::GetProcessor(struct libinput_device *inputDev)
{
    if (auto iter = processors_.find(inputDev); iter != processors_.end()) {
        return iter->second;
    }
    auto deviceId = INPUT_DEV_MGR->FindInputDeviceId(inputDev);
    auto [iter, _] = processors_.emplace(inputDev, std::make_shared<JoystickEventProcessor>(deviceId));
    return iter->second;
}

std::shared_ptr<JoystickEventProcessor> JoystickEventNormalize::FindProcessor(int32_t deviceId) const
{
    auto iter = std::find_if(processors_.cbegin(), processors_.cend(),
        [deviceId](const auto &item) {
            return ((item.second != nullptr) && (item.second->GetDeviceId() == deviceId));
        });
    return (iter != processors_.cend() ? iter->second : nullptr);
}
} // namespace MMI
} // namespace OHOS
