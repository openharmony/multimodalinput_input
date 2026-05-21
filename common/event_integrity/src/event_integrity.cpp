/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "event_integrity.h"

#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventIntegrity"

namespace OHOS {
namespace MMI {

EventIntegrity::EventIntegrity()
{
}

bool EventIntegrity::IsCompleteEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    if (pointerEvent == nullptr) {
        MMI_HILOGE("pointerEvent is null");
        return false;
    }

    int32_t action = pointerEvent->GetPointerAction();
    switch (action) {
        case PointerEvent::POINTER_ACTION_SWIPE_BEGIN: {
            return HandleSwipeBegin(pointerEvent);
        }
        case PointerEvent::POINTER_ACTION_SWIPE_UPDATE: {
            return HandleSwipeUpdate(pointerEvent);
        }
        case PointerEvent::POINTER_ACTION_SWIPE_END: {
            return HandleSwipeEnd(pointerEvent);
        }
        default: {
            break;
        }
    }
    return true;
}

bool EventIntegrity::HandleSwipeBegin(const std::shared_ptr<PointerEvent>& pointerEvent)
{
    int32_t action = pointerEvent->GetPointerAction();
    eventAction_ = action;
    return true;
}

bool EventIntegrity::HandleSwipeUpdate(const std::shared_ptr<PointerEvent>& pointerEvent)
{
    if (eventAction_ == PointerEvent::POINTER_ACTION_SWIPE_BEGIN ||
        eventAction_ == PointerEvent::POINTER_ACTION_SWIPE_UPDATE) {
        int32_t action = pointerEvent->GetPointerAction();
        eventAction_ = action;
        return true;
    }
    return false;
}

bool EventIntegrity::HandleSwipeEnd(const std::shared_ptr<PointerEvent>& pointerEvent)
{
    if (eventAction_ == PointerEvent::POINTER_ACTION_SWIPE_BEGIN ||
        eventAction_ == PointerEvent::POINTER_ACTION_SWIPE_UPDATE) {
        eventAction_ = PointerEvent::POINTER_ACTION_UNKNOWN;
        return true;
    }
    return false;
}
} // namespace MMI
} // namespace OHOS
