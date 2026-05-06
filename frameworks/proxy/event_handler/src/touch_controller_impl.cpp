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

#include "touch_controller_impl.h"

#include "define_multimodal.h"
#include "mmi_log.h"
#include "multimodal_input_connect_manager.h"
#include "util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchControllerImpl"

namespace OHOS {
namespace MMI {

namespace {
constexpr int32_t ERROR_CODE_TOUCH_SEQUENCE_ERROR = 4300001;
constexpr int32_t ERROR_CODE_TOUCH_ID_INVALID = 4300003;
constexpr int32_t TOUCH_TOOL_TYPE_FINGER = PointerEvent::TOOL_TYPE_FINGER;
constexpr int32_t INVALID_DEVICE_ID = -1;
constexpr int32_t MIN_TOUCH_ID = 0;
constexpr int32_t MAX_TOUCH_ID = 9;
} // namespace

TouchControllerImpl::TouchControllerImpl()
{
    MMI_HILOGD("TouchControllerImpl created");
}

TouchControllerImpl::~TouchControllerImpl()
{
    MMI_HILOGD("TouchControllerImpl destroyed");
}

bool TouchControllerImpl::IsTouchIdValid(int32_t touchId) const
{
    return touchId >= MIN_TOUCH_ID && touchId <= MAX_TOUCH_ID;
}

std::shared_ptr<PointerEvent> TouchControllerImpl::CreatePointerEvent(const PointerEventContext &context,
    const std::map<int32_t, TouchContactState> &contacts)
{
    auto pointerEvent = PointerEvent::Create();
    if (pointerEvent == nullptr) {
        MMI_HILOGE("Failed to create PointerEvent");
        return nullptr;
    }

    pointerEvent->SetPointerAction(context.action);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(context.touchId);
    pointerEvent->SetDeviceId(INVALID_DEVICE_ID);
    pointerEvent->SetTargetDisplayId(context.displayId);
    pointerEvent->SetActionTime(context.actionTime);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_CONTROLLER);
    pointerEvent->RemoveAllPointerItems();
    AddPointerItems(pointerEvent, context, contacts);
    pointerEvent->UpdateId();
    return pointerEvent;
}

void TouchControllerImpl::AddPointerItems(const std::shared_ptr<PointerEvent> &pointerEvent,
    const PointerEventContext &context, const std::map<int32_t, TouchContactState> &contacts) const
{
    for (const auto &itemPair : contacts) {
        const auto &contact = itemPair.second;
        PointerEvent::PointerItem item;
        item.SetPointerId(itemPair.first);
        item.SetOriginPointerId(itemPair.first);
        item.SetDisplayX(contact.displayX);
        item.SetDisplayY(contact.displayY);
        item.SetDisplayXPos(contact.displayX);
        item.SetDisplayYPos(contact.displayY);
        item.SetToolType(TOUCH_TOOL_TYPE_FINGER);
        item.SetDeviceId(INVALID_DEVICE_ID);
        item.SetDownTime(contact.downTime);
        item.SetPressed(itemPair.first == context.touchId ? context.currentPressed : true);
        pointerEvent->AddPointerItem(item);
    }
}

int32_t TouchControllerImpl::InjectPointerEvent(const std::shared_ptr<PointerEvent> &event)
{
    if (event == nullptr) {
        MMI_HILOGE("PointerEvent is nullptr");
        return RET_ERR;
    }

    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->InjectPointerEvent(event, false, PointerEvent::DISPLAY_COORDINATE);
    if (ret != RET_OK) {
        MMI_HILOGE("InjectPointerEvent failed, ret=%{public}d", ret);
    }
    return ret;
}

std::shared_ptr<PointerEvent> TouchControllerImpl::BuildTouchDownEvent(int32_t touchId, int32_t displayId,
    int32_t displayX, int32_t displayY, int64_t actionTime)
{
    std::lock_guard<std::mutex> lock(activePointsMutex_);
    if (activePoints_.count(touchId) != 0) {
        MMI_HILOGE("Touch id %{public}d already pressed", touchId);
        return nullptr;
    }
    if (!activePoints_.empty() && activeDisplayId_ != displayId) {
        MMI_HILOGE("Touch display mismatch, activeDisplayId=%{public}d, input=%{public}d",
            activeDisplayId_, displayId);
        return nullptr;
    }

    std::map<int32_t, TouchContactState> contacts { activePoints_ };
    contacts[touchId] = { displayId, displayX, displayY, actionTime };
    PointerEventContext context { PointerEvent::POINTER_ACTION_DOWN, touchId, displayId, actionTime, true };
    return CreatePointerEvent(context, contacts);
}

std::shared_ptr<PointerEvent> TouchControllerImpl::BuildTouchMoveEvent(int32_t touchId, int32_t displayId,
    int32_t displayX, int32_t displayY, int64_t actionTime)
{
    std::lock_guard<std::mutex> lock(activePointsMutex_);
    auto it = activePoints_.find(touchId);
    if (it == activePoints_.end()) {
        MMI_HILOGE("Touch id %{public}d is not active", touchId);
        return nullptr;
    }
    if (activeDisplayId_ != displayId) {
        MMI_HILOGE("Touch display mismatch, activeDisplayId=%{public}d, input=%{public}d",
            activeDisplayId_, displayId);
        return nullptr;
    }

    std::map<int32_t, TouchContactState> contacts { activePoints_ };
    contacts[touchId] = { displayId, displayX, displayY, it->second.downTime };
    PointerEventContext context { PointerEvent::POINTER_ACTION_MOVE, touchId, displayId, actionTime, true };
    return CreatePointerEvent(context, contacts);
}

std::shared_ptr<PointerEvent> TouchControllerImpl::BuildTouchUpEvent(int32_t touchId, int32_t displayId,
    int32_t displayX, int32_t displayY, int64_t actionTime)
{
    std::lock_guard<std::mutex> lock(activePointsMutex_);
    auto it = activePoints_.find(touchId);
    if (it == activePoints_.end()) {
        MMI_HILOGE("Touch id %{public}d is not active", touchId);
        return nullptr;
    }
    if (activeDisplayId_ != displayId) {
        MMI_HILOGE("Touch display mismatch, activeDisplayId=%{public}d, input=%{public}d",
            activeDisplayId_, displayId);
        return nullptr;
    }

    std::map<int32_t, TouchContactState> contacts { activePoints_ };
    contacts[touchId] = { displayId, displayX, displayY, it->second.downTime };
    PointerEventContext context { PointerEvent::POINTER_ACTION_UP, touchId, displayId, actionTime, false };
    return CreatePointerEvent(context, contacts);
}

void TouchControllerImpl::CommitTouchDownState(int32_t touchId, int32_t displayId, int32_t displayX,
    int32_t displayY, int64_t downTime)
{
    std::lock_guard<std::mutex> lock(activePointsMutex_);
    activePoints_[touchId] = { displayId, displayX, displayY, downTime };
    activeDisplayId_ = displayId;
}

void TouchControllerImpl::CommitTouchMoveState(int32_t touchId, int32_t displayId, int32_t displayX, int32_t displayY)
{
    std::lock_guard<std::mutex> lock(activePointsMutex_);
    auto it = activePoints_.find(touchId);
    if (it != activePoints_.end()) {
        it->second.displayId = displayId;
        it->second.displayX = displayX;
        it->second.displayY = displayY;
    }
}

void TouchControllerImpl::ClearTouchState(int32_t touchId)
{
    std::lock_guard<std::mutex> lock(activePointsMutex_);
    activePoints_.erase(touchId);
    if (activePoints_.empty()) {
        activeDisplayId_ = -1;
    }
}

int32_t TouchControllerImpl::TouchDown(int32_t touchId, int32_t displayId, int32_t displayX, int32_t displayY)
{
    if (!IsTouchIdValid(touchId)) {
        MMI_HILOGE("Invalid touch id %{public}d", touchId);
        return ERROR_CODE_TOUCH_ID_INVALID;
    }

    int64_t now = GetSysClockTime();
    auto pointerEvent = BuildTouchDownEvent(touchId, displayId, displayX, displayY, now);
    if (pointerEvent == nullptr) {
        return ERROR_CODE_TOUCH_SEQUENCE_ERROR;
    }

    int32_t ret = RET_OK;
    {
        std::lock_guard<std::mutex> lock(injectMutex_);
        ret = InjectPointerEvent(pointerEvent);
    }
    if (ret == RET_OK) {
        CommitTouchDownState(touchId, displayId, displayX, displayY, now);
    }
    return ret;
}

int32_t TouchControllerImpl::TouchMove(int32_t touchId, int32_t displayId, int32_t displayX, int32_t displayY)
{
    if (!IsTouchIdValid(touchId)) {
        MMI_HILOGE("Invalid touch id %{public}d", touchId);
        return ERROR_CODE_TOUCH_ID_INVALID;
    }

    auto pointerEvent = BuildTouchMoveEvent(touchId, displayId, displayX, displayY, GetSysClockTime());
    if (pointerEvent == nullptr) {
        return ERROR_CODE_TOUCH_SEQUENCE_ERROR;
    }

    int32_t ret = RET_OK;
    {
        std::lock_guard<std::mutex> lock(injectMutex_);
        ret = InjectPointerEvent(pointerEvent);
    }
    if (ret == RET_OK) {
        CommitTouchMoveState(touchId, displayId, displayX, displayY);
    }
    return ret;
}

int32_t TouchControllerImpl::TouchUp(int32_t touchId, int32_t displayId, int32_t displayX, int32_t displayY)
{
    if (!IsTouchIdValid(touchId)) {
        MMI_HILOGE("Invalid touch id %{public}d", touchId);
        return ERROR_CODE_TOUCH_ID_INVALID;
    }

    auto pointerEvent = BuildTouchUpEvent(touchId, displayId, displayX, displayY, GetSysClockTime());
    if (pointerEvent == nullptr) {
        ClearTouchState(touchId);
        return ERROR_CODE_TOUCH_SEQUENCE_ERROR;
    }

    int32_t ret = RET_OK;
    {
        std::lock_guard<std::mutex> lock(injectMutex_);
        ret = InjectPointerEvent(pointerEvent);
    }
    ClearTouchState(touchId);
    return ret;
}

} // namespace MMI
} // namespace OHOS
