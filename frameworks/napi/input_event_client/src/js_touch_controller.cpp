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

#include "js_touch_controller.h"

#include <map>
#include <memory>
#include <mutex>

#include "define_multimodal.h"
#include "input_event.h"
#include "input_manager.h"
#include "mmi_log.h"
#include "pointer_event.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsTouchController"

namespace OHOS {
namespace MMI {

namespace {
constexpr int32_t TOUCH_ID_MIN = 0;
constexpr int32_t TOUCH_ID_MAX = 9;
constexpr int32_t TOUCH_INPUT_SERVICE_EXCEPTION = 3800001;
constexpr int32_t TOUCH_INPUT_PARAMETER_ERROR = 401;

struct TouchContact {
    int32_t displayId {-1};
    int32_t displayX {0};
    int32_t displayY {0};
    int64_t downTime {0};
};

bool IsValidTouchId(int32_t touchId)
{
    return touchId >= TOUCH_ID_MIN && touchId <= TOUCH_ID_MAX;
}
} // namespace

class JsTouchController::Impl {
public:
    int32_t TouchDown(int32_t id, int32_t displayId, int32_t displayX, int32_t displayY)
    {
        if (!IsValidTouchId(id)) {
            MMI_HILOGE("Touch id invalid: %{public}d", id);
            return TOUCH_INPUT_PARAMETER_ERROR;
        }

        std::shared_ptr<PointerEvent> pointerEvent;
        TouchContact currentContact;
        currentContact.displayId = displayId;
        currentContact.displayX = displayX;
        currentContact.displayY = displayY;
        currentContact.downTime = GetSysClockTime();

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (activeContacts_.find(id) != activeContacts_.end()) {
                MMI_HILOGE("Touch id %{public}d already active", id);
                return ERROR_CODE_TOUCH_SEQUENCE;
            }
            if (!activeContacts_.empty() && activeDisplayId_ != displayId) {
                MMI_HILOGE("Touch display mismatch, expected %{public}d, got %{public}d",
                    activeDisplayId_, displayId);
                return ERROR_CODE_TOUCH_SEQUENCE;
            }

            std::map<int32_t, TouchContact> contacts = activeContacts_;
            contacts[id] = currentContact;
            int32_t sessionDisplayId = activeContacts_.empty() ? displayId : activeDisplayId_;
            pointerEvent = BuildPointerEvent(PointerEvent::POINTER_ACTION_DOWN, id, sessionDisplayId, contacts, true);
        }

        int32_t ret = InjectPointerEvent(pointerEvent);
        if (ret == RET_OK) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (activeContacts_.empty()) {
                activeDisplayId_ = displayId;
            }
            activeContacts_[id] = currentContact;
        }
        return ret;
    }

    int32_t TouchMove(int32_t id, int32_t displayId, int32_t displayX, int32_t displayY)
    {
        if (!IsValidTouchId(id)) {
            MMI_HILOGE("Touch id invalid: %{public}d", id);
            return TOUCH_INPUT_PARAMETER_ERROR;
        }

        std::shared_ptr<PointerEvent> pointerEvent;
        TouchContact currentContact;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto iter = activeContacts_.find(id);
            if (iter == activeContacts_.end()) {
                MMI_HILOGE("Touch id %{public}d not active", id);
                return ERROR_CODE_TOUCH_SEQUENCE;
            }
            if (activeDisplayId_ != displayId) {
                MMI_HILOGE("Touch display mismatch, expected %{public}d, got %{public}d",
                    activeDisplayId_, displayId);
                return ERROR_CODE_TOUCH_SEQUENCE;
            }

            currentContact = iter->second;
            currentContact.displayId = displayId;
            currentContact.displayX = displayX;
            currentContact.displayY = displayY;

            std::map<int32_t, TouchContact> contacts = activeContacts_;
            contacts[id] = currentContact;
            pointerEvent = BuildPointerEvent(PointerEvent::POINTER_ACTION_MOVE, id, activeDisplayId_, contacts, true);
        }

        int32_t ret = InjectPointerEvent(pointerEvent);
        if (ret == RET_OK) {
            std::lock_guard<std::mutex> lock(mutex_);
            activeContacts_[id] = currentContact;
        }
        return ret;
    }

    int32_t TouchUp(int32_t id, int32_t displayId, int32_t displayX, int32_t displayY)
    {
        if (!IsValidTouchId(id)) {
            MMI_HILOGE("Touch id invalid: %{public}d", id);
            return TOUCH_INPUT_PARAMETER_ERROR;
        }

        std::shared_ptr<PointerEvent> pointerEvent;
        TouchContact currentContact;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto iter = activeContacts_.find(id);
            if (iter == activeContacts_.end()) {
                MMI_HILOGE("Touch id %{public}d not active", id);
                return ERROR_CODE_TOUCH_SEQUENCE;
            }
            if (activeDisplayId_ != displayId) {
                MMI_HILOGE("Touch display mismatch, expected %{public}d, got %{public}d",
                    activeDisplayId_, displayId);
                return ERROR_CODE_TOUCH_SEQUENCE;
            }

            currentContact = iter->second;
            currentContact.displayId = displayId;
            currentContact.displayX = displayX;
            currentContact.displayY = displayY;

            std::map<int32_t, TouchContact> contacts = activeContacts_;
            contacts[id] = currentContact;
            pointerEvent = BuildPointerEvent(PointerEvent::POINTER_ACTION_UP, id, activeDisplayId_, contacts, false);
        }

        int32_t ret = InjectPointerEvent(pointerEvent);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            activeContacts_.erase(id);
            if (activeContacts_.empty()) {
                activeDisplayId_ = -1;
            }
        }
        return ret;
    }

private:
    static constexpr int32_t ERROR_CODE_TOUCH_SEQUENCE = 4300001;

    PointerEvent::PointerItem BuildPointerItem(int32_t pointerId, const TouchContact& contact, bool pressed) const
    {
        PointerEvent::PointerItem item;
        item.SetPointerId(pointerId);
        item.SetDisplayX(contact.displayX);
        item.SetDisplayY(contact.displayY);
        item.SetDisplayXPos(contact.displayX);
        item.SetDisplayYPos(contact.displayY);
        item.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
        item.SetDeviceId(-1);
        item.SetDownTime(contact.downTime);
        item.SetPressed(pressed);
        return item;
    }

    std::shared_ptr<PointerEvent> BuildPointerEvent(int32_t action, int32_t pointerId, int32_t displayId,
        const std::map<int32_t, TouchContact>& contacts, bool currentPressed) const
    {
        auto pointerEvent = PointerEvent::Create();
        if (pointerEvent == nullptr) {
            MMI_HILOGE("Failed to create PointerEvent");
            return nullptr;
        }

        pointerEvent->SetPointerAction(action);
        pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
        pointerEvent->SetPointerId(pointerId);
        pointerEvent->SetTargetDisplayId(displayId);
        pointerEvent->SetDeviceId(-1);
        pointerEvent->SetActionTime(GetSysClockTime());
        pointerEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);
        pointerEvent->AddFlag(InputEvent::EVENT_FLAG_CONTROLLER);

        for (const auto& [touchId, contact] : contacts) {
            bool pressed = (touchId == pointerId) ? currentPressed : true;
            PointerEvent::PointerItem item = BuildPointerItem(touchId, contact, pressed);
            pointerEvent->AddPointerItem(item);
        }

        return pointerEvent;
    }

    int32_t InjectPointerEvent(const std::shared_ptr<PointerEvent>& pointerEvent) const
    {
        if (pointerEvent == nullptr) {
            MMI_HILOGE("pointerEvent is null");
            return TOUCH_INPUT_SERVICE_EXCEPTION;
        }
        InputManager::GetInstance()->SimulateInputEvent(pointerEvent, false, PointerEvent::DISPLAY_COORDINATE);
        return RET_OK;
    }

    int32_t activeDisplayId_ {-1};
    std::map<int32_t, TouchContact> activeContacts_;
    mutable std::mutex mutex_;
};

JsTouchController::~JsTouchController() = default;

JsTouchController::JsTouchController()
    : impl_(std::make_unique<Impl>())
{
    MMI_HILOGD("Creating JsTouchController");
}

int32_t JsTouchController::TouchDown(int32_t id, int32_t displayId, int32_t displayX, int32_t displayY)
{
    if (impl_ == nullptr) {
        MMI_HILOGE("TouchControllerImpl is null");
        return TOUCH_INPUT_SERVICE_EXCEPTION;
    }
    return impl_->TouchDown(id, displayId, displayX, displayY);
}

int32_t JsTouchController::TouchMove(int32_t id, int32_t displayId, int32_t displayX, int32_t displayY)
{
    if (impl_ == nullptr) {
        MMI_HILOGE("TouchControllerImpl is null");
        return TOUCH_INPUT_SERVICE_EXCEPTION;
    }
    return impl_->TouchMove(id, displayId, displayX, displayY);
}

int32_t JsTouchController::TouchUp(int32_t id, int32_t displayId, int32_t displayX, int32_t displayY)
{
    if (impl_ == nullptr) {
        MMI_HILOGE("TouchControllerImpl is null");
        return TOUCH_INPUT_SERVICE_EXCEPTION;
    }
    return impl_->TouchUp(id, displayId, displayX, displayY);
}

} // namespace MMI
} // namespace OHOS
