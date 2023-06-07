/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "mouse_transform_processor.h"

#include <cinttypes>

#include "input-event-codes.h"

#include "define_multimodal.h"
#include "event_log_helper.h"
#include "i_pointer_drawing_manager.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "input_windows_manager.h"
#include "mouse_device_state.h"
#include "preferences.h"
#include "preferences_impl.h"
#include "preferences_errno.h"
#include "preferences_helper.h"
#include "preferences_xml_utils.h"
#include "timer_manager.h"
#include "util_ex.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MouseTransformProcessor" };
constexpr int32_t MIN_SPEED = 1;
constexpr int32_t MAX_SPEED = 11;
constexpr int32_t DEFAULT_SPEED = 5;
constexpr int32_t DEFAULT_ROWS = 3;
constexpr int32_t MIN_ROWS = 1;
constexpr int32_t MAX_ROWS = 100;
constexpr int32_t CALCULATE_MIDDLE = 2;
const std::string mouseFileName = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
} // namespace

double MouseTransformProcessor::absolutionX_ = -1.0;
double MouseTransformProcessor::absolutionY_ = -1.0;
int32_t MouseTransformProcessor::currentDisplayId_ = -1;
int32_t MouseTransformProcessor::globalPointerSpeed_ = DEFAULT_SPEED;
bool MouseTransformProcessor::isUserSetSpeedStatus_ = false;

MouseTransformProcessor::MouseTransformProcessor(int32_t deviceId)
    : pointerEvent_(PointerEvent::Create()), deviceId_(deviceId)
{}

std::shared_ptr<PointerEvent> MouseTransformProcessor::GetPointerEvent() const
{
    return pointerEvent_;
}

int32_t MouseTransformProcessor::HandleMotionInner(struct libinput_event_pointer* data)
{
    CALL_DEBUG_ENTER;
    CHKPR(data, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent_->SetButtonId(buttonId_);

    InitAbsolution();
    if (currentDisplayId_ == -1) {
        absolutionX_ = -1;
        absolutionY_ = -1;
        MMI_HILOGI("The currentDisplayId_ is -1");
        return RET_ERR;
    }

    Offset offset = {libinput_event_pointer_get_dx_unaccelerated(data),
        libinput_event_pointer_get_dy_unaccelerated(data)};
    int32_t ret = HandleMotionAccelerate(&offset, WinMgr->GetMouseIsCaptureMode(), &absolutionX_,
        &absolutionY_, GetSpeed());
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to handle motion correction");
        return ret;
    }
    WinMgr->UpdateAndAdjustMouseLocation(currentDisplayId_, absolutionX_, absolutionY_);
    pointerEvent_->SetTargetDisplayId(currentDisplayId_);
    MMI_HILOGD("Change coordinate: x:%{public}lf, y:%{public}lf, currentDisplayId_:%{public}d",
        absolutionX_, absolutionY_, currentDisplayId_);
    return RET_OK;
}

void MouseTransformProcessor::InitAbsolution()
{
    CALL_DEBUG_ENTER;
    if (absolutionX_ != -1 || absolutionY_ != -1 || currentDisplayId_ != -1) {
        MMI_HILOGW("Unable to initialize coordinate information");
        return;
    }
    auto displayGroupInfo = WinMgr->GetDisplayGroupInfo();
    if (displayGroupInfo.displaysInfo.empty()) {
        MMI_HILOGI("The displayInfo is empty");
        return;
    }
    currentDisplayId_ = displayGroupInfo.displaysInfo[0].id;
    absolutionX_ = displayGroupInfo.displaysInfo[0].width * 1.0 / CALCULATE_MIDDLE;
    absolutionY_ = displayGroupInfo.displaysInfo[0].height * 1.0 / CALCULATE_MIDDLE;
}

int32_t MouseTransformProcessor::HandleButtonInner(struct libinput_event_pointer* data)
{
    CALL_DEBUG_ENTER;
    CHKPR(data, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    MMI_HILOGD("Current action:%{public}d", pointerEvent_->GetPointerAction());

    auto ret = HandleButtonValueInner(data);
    if (ret != RET_OK) {
        MMI_HILOGE("The button value does not exist");
        return RET_ERR;
    }
    uint32_t button = libinput_event_pointer_get_button(data);
    auto state = libinput_event_pointer_get_button_state(data);
    if (state == LIBINPUT_BUTTON_STATE_RELEASED) {
        MouseState->MouseBtnStateCounts(button, BUTTON_STATE_RELEASED);
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
        int32_t buttonId = MouseState->LibinputChangeToPointer(button);
        pointerEvent_->DeleteReleaseButton(buttonId);
        isPressed_ = false;
        buttonId_ = PointerEvent::BUTTON_NONE;
    } else if (state == LIBINPUT_BUTTON_STATE_PRESSED) {
        MouseState->MouseBtnStateCounts(button, BUTTON_STATE_PRESSED);
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
        int32_t buttonId = MouseState->LibinputChangeToPointer(button);
        pointerEvent_->SetButtonPressed(buttonId);
        isPressed_ = true;
        buttonId_ = pointerEvent_->GetButtonId();
    } else {
        MMI_HILOGE("Unknown state, state:%{public}u", state);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MouseTransformProcessor::HandleButtonValueInner(struct libinput_event_pointer* data)
{
    CALL_DEBUG_ENTER;
    CHKPR(data, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    uint32_t button = libinput_event_pointer_get_button(data);
    int32_t buttonId = MouseState->LibinputChangeToPointer(button);
    if (buttonId == PointerEvent::BUTTON_NONE) {
        MMI_HILOGE("Unknown btn, btn:%{public}u", button);
        return RET_ERR;
    }

    std::string file = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
    std::shared_ptr<NativePreferences::Preferences> pref =
        NativePreferences::PreferencesHelper::GetPreferences(file, errno);
    if (pref == nullptr) {
        MMI_HILOGE("pref is nullptr,  errno: %{public}d", errno);
        return RET_ERR;
    }
    std::string name = "primaryButton";
    int32_t primaryButton = pref->GetInt(name, 0);
    MMI_HILOGD("Set mouse primary button:%{public}d", primaryButton);
    if (primaryButton == RIGHT_BUTTON) {
        if (buttonId == PointerEvent::MOUSE_BUTTON_LEFT) {
            buttonId = PointerEvent::MOUSE_BUTTON_RIGHT;
        } else if (buttonId == PointerEvent::MOUSE_BUTTON_RIGHT) {
            buttonId = PointerEvent::MOUSE_BUTTON_LEFT;
        } else {
            MMI_HILOGD("buttonId does not switch.");
        }
    }

    pointerEvent_->SetButtonId(buttonId);
    NativePreferences::PreferencesHelper::
        RemovePreferencesFromCache("/data/service/el1/public/multimodalinput/mouse_settings");
    return RET_OK;
}

int32_t MouseTransformProcessor::SetMouseScrollRows(int32_t rows)
{
    CALL_DEBUG_ENTER;
    if (rows < MIN_ROWS) {
        rows = MIN_ROWS;
    } else if (rows > MAX_ROWS) {
        rows = MAX_ROWS;
    }
    int32_t errCode = RET_OK;
    std::shared_ptr<NativePreferences::Preferences> pref =
        NativePreferences::PreferencesHelper::GetPreferences(mouseFileName, errCode);
    if (pref == nullptr) {
        MMI_HILOGE("pref is nullptr,  errCode: %{public}d", errCode);
        return RET_ERR;
    }
    std::string name = "rows";
    int32_t ret = pref->PutInt(name, rows);
    if (ret != RET_OK) {
        MMI_HILOGE("Put rows is failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    ret = pref->FlushSync();
    if (ret != RET_OK) {
        MMI_HILOGE("Flush sync is failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    MMI_HILOGD("Set mouse scroll rows successfully, rows:%{public}d", rows);
    NativePreferences::PreferencesHelper::RemovePreferencesFromCache(mouseFileName);
    return RET_OK;
}

int32_t MouseTransformProcessor::GetMouseScrollRows()
{
    CALL_DEBUG_ENTER;
    int32_t errCode = RET_OK;
    std::shared_ptr<NativePreferences::Preferences> pref =
        NativePreferences::PreferencesHelper::GetPreferences(mouseFileName, errCode);
    if (pref == nullptr) {
        MMI_HILOGE("pref is nullptr,  errCode: %{public}d", errCode);
        return RET_ERR;
    }
    std::string name = "rows";
    int32_t rows = pref->GetInt(name, DEFAULT_ROWS);
    MMI_HILOGD("Get mouse scroll rows successfully, rows:%{public}d", rows);
    NativePreferences::PreferencesHelper::RemovePreferencesFromCache(mouseFileName);
    return rows;
}

int32_t MouseTransformProcessor::HandleAxisInner(struct libinput_event_pointer* data)
{
    CALL_DEBUG_ENTER;
    CHKPR(data, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    if (buttonId_ == PointerEvent::BUTTON_NONE && pointerEvent_->GetButtonId() != PointerEvent::BUTTON_NONE) {
        pointerEvent_->SetButtonId(PointerEvent::BUTTON_NONE);
    }
    if (TimerMgr->IsExist(timerId_)) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
        TimerMgr->ResetTimer(timerId_);
        MMI_HILOGD("Axis update");
    } else {
        static constexpr int32_t timeout = 100;
        std::weak_ptr<MouseTransformProcessor> weakPtr = shared_from_this();
        timerId_ = TimerMgr->AddTimer(timeout, 1, [weakPtr]() {
            CALL_DEBUG_ENTER;
            auto sharedPtr = weakPtr.lock();
            CHKPV(sharedPtr);
            MMI_HILOGD("timer:%{public}d", sharedPtr->timerId_);
            sharedPtr->timerId_ = -1;
            auto pointerEvent = sharedPtr->GetPointerEvent();
            CHKPV(pointerEvent);
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
            pointerEvent->UpdateId();
            auto inputEventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
            CHKPV(inputEventNormalizeHandler);
            inputEventNormalizeHandler->HandlePointerEvent(pointerEvent);
        });

        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
        MMI_HILOGD("Axis begin");
    }

    const int32_t initRows = 3;
    if (libinput_event_pointer_has_axis(data, LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL)) {
        double axisValue = libinput_event_pointer_get_axis_value(data, LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL);
        axisValue = GetMouseScrollRows() * (axisValue / initRows);
        pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, axisValue);
    }
    if (libinput_event_pointer_has_axis(data, LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL)) {
        double axisValue = libinput_event_pointer_get_axis_value(data, LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL);
        axisValue = GetMouseScrollRows() * (axisValue / initRows);
        pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, axisValue);
    }
    return RET_OK;
}

void MouseTransformProcessor::HandlePostInner(struct libinput_event_pointer* data,
    PointerEvent::PointerItem &pointerItem)
{
    CALL_DEBUG_ENTER;
    CHKPV(data);
    CHKPV(pointerEvent_);
    auto mouseInfo = WinMgr->GetMouseInfo();
    MouseState->SetMouseCoords(mouseInfo.physicalX, mouseInfo.physicalY);
    pointerItem.SetDisplayX(mouseInfo.physicalX);
    pointerItem.SetDisplayY(mouseInfo.physicalY);
    pointerItem.SetWindowX(0);
    pointerItem.SetWindowY(0);
    pointerItem.SetPointerId(0);
    pointerItem.SetPressed(isPressed_);

    uint64_t time = libinput_event_pointer_get_time_usec(data);
    pointerItem.SetDownTime(time);
    pointerItem.SetWidth(0);
    pointerItem.SetHeight(0);
    pointerItem.SetPressure(0);
    pointerItem.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    pointerItem.SetDeviceId(deviceId_);
    SetDxDyForDInput(pointerItem, data);
    pointerEvent_->UpdateId();
    pointerEvent_->UpdatePointerItem(pointerEvent_->GetPointerId(), pointerItem);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->SetPointerId(0);
    pointerEvent_->SetTargetDisplayId(currentDisplayId_);
    pointerEvent_->SetTargetWindowId(-1);
    pointerEvent_->SetAgentWindowId(-1);
}

int32_t MouseTransformProcessor::Normalize(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    CHKPR(pointerEvent_, ERROR_NULL_POINTER);
    auto data = libinput_event_get_pointer_event(event);
    CHKPR(data, ERROR_NULL_POINTER);
    pointerEvent_->ClearAxisValue();
    int32_t result;
    const int32_t type = libinput_event_get_type(event);
    switch (type) {
        case LIBINPUT_EVENT_POINTER_MOTION:
        case LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE: {
            result = HandleMotionInner(data);
            break;
        }
        case LIBINPUT_EVENT_POINTER_BUTTON: {
            result = HandleButtonInner(data);
            break;
        }
        case LIBINPUT_EVENT_POINTER_AXIS: {
            result = HandleAxisInner(data);
            break;
        }
        default: {
            MMI_HILOGE("Unknown type:%{public}d", type);
            return RET_ERR;
        }
    }
    PointerEvent::PointerItem pointerItem;
    HandlePostInner(data, pointerItem);
    WinMgr->UpdateTargetPointer(pointerEvent_);
    DumpInner();
    return result;
}

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
void MouseTransformProcessor::HandleMotionMoveMouse(int32_t offsetX, int32_t offsetY)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    InitAbsolution();
    absolutionX_ += offsetX;
    absolutionY_ += offsetY;
    WinMgr->UpdateAndAdjustMouseLocation(currentDisplayId_, absolutionX_, absolutionY_);
}

void MouseTransformProcessor::OnDisplayLost(int32_t displayId)
{
    if (currentDisplayId_ != displayId) {
        currentDisplayId_ = -1;
        absolutionX_ = -1;
        absolutionY_ = -1;
        InitAbsolution();
        WinMgr->UpdateAndAdjustMouseLocation(currentDisplayId_, absolutionX_, absolutionY_);
    }
}

int32_t MouseTransformProcessor::GetDisplayId()
{
    return currentDisplayId_;
}

void MouseTransformProcessor::HandlePostMoveMouse(PointerEvent::PointerItem& pointerItem)
{
    CALL_DEBUG_ENTER;
    auto mouseInfo = WinMgr->GetMouseInfo();
    CHKPV(pointerEvent_);
    MouseState->SetMouseCoords(mouseInfo.physicalX, mouseInfo.physicalY);
    pointerItem.SetDisplayX(mouseInfo.physicalX);
    pointerItem.SetDisplayY(mouseInfo.physicalY);
    pointerItem.SetWindowX(0);
    pointerItem.SetWindowY(0);
    pointerItem.SetPointerId(0);
    pointerItem.SetPressed(isPressed_);

    int64_t time = GetSysClockTime();
    pointerItem.SetDownTime(time);
    pointerItem.SetWidth(0);
    pointerItem.SetHeight(0);
    pointerItem.SetPressure(0);

    pointerEvent_->UpdateId();
    pointerEvent_->UpdatePointerItem(pointerEvent_->GetPointerId(), pointerItem);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetActionStartTime(time);

    pointerEvent_->SetPointerId(0);
    pointerEvent_->SetTargetDisplayId(-1);
    pointerEvent_->SetTargetWindowId(-1);
    pointerEvent_->SetAgentWindowId(-1);
}

bool MouseTransformProcessor::NormalizeMoveMouse(int32_t offsetX, int32_t offsetY)
{
    CALL_DEBUG_ENTER;
    CHKPF(pointerEvent_);
    bool bHasPointerDevice = InputDevMgr->HasPointerDevice();
    if (!bHasPointerDevice) {
        MMI_HILOGE("There hasn't any pointer device");
        return false;
    }

    PointerEvent::PointerItem pointerItem;
    HandleMotionMoveMouse(offsetX, offsetY);
    HandlePostMoveMouse(pointerItem);
    DumpInner();
    return bHasPointerDevice;
}
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

void MouseTransformProcessor::DumpInner()
{
    EventLogHelper::PrintEventData(pointerEvent_);
}

void MouseTransformProcessor::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    PointerEvent::PointerItem item;
    CHKPV(pointerEvent_);
    pointerEvent_->GetPointerItem(pointerEvent_->GetPointerId(), item);
    mprintf(fd, "Mouse device state information:\t");
    mprintf(fd,
            "PointerId:%d | SourceType:%s | PointerAction:%s | WindowX:%d | WindowY:%d | ButtonId:%d "
            "| AgentWindowId:%d | TargetWindowId:%d | DownTime:%" PRId64 " | IsPressed:%s \t",
            pointerEvent_->GetPointerId(), pointerEvent_->DumpSourceType(), pointerEvent_->DumpPointerAction(),
            item.GetWindowX(), item.GetWindowY(), pointerEvent_->GetButtonId(), pointerEvent_->GetAgentWindowId(),
            pointerEvent_->GetTargetWindowId(), item.GetDownTime(), item.IsPressed() ? "true" : "false");
}

int32_t MouseTransformProcessor::SetMousePrimaryButton(int32_t primaryButton)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Set mouse primary button:%{public}d", primaryButton);
    std::string file = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
    std::shared_ptr<NativePreferences::Preferences> pref =
        NativePreferences::PreferencesHelper::GetPreferences(file, errno);
    if (pref == nullptr) {
        MMI_HILOGE("pref is nullptr,  errno: %{public}d", errno);
        return RET_ERR;
    }
    std::string name = "primaryButton";
    pref->PutInt(name, primaryButton);
    int32_t ret = pref->FlushSync();
    if (ret != RET_OK) {
        MMI_HILOGE("flush sync is failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    NativePreferences::PreferencesHelper::
        RemovePreferencesFromCache("/data/service/el1/public/multimodalinput/mouse_settings");
    return RET_OK;
}

int32_t MouseTransformProcessor::GetMousePrimaryButton()
{
    CALL_DEBUG_ENTER;
    std::string file = "/data/service/el1/public/multimodalinput/mouse_settings.xml";
    std::shared_ptr<NativePreferences::Preferences> pref =
        NativePreferences::PreferencesHelper::GetPreferences(file, errno);
    if (pref == nullptr) {
        MMI_HILOGE("pref is nullptr,  errno: %{public}d", errno);
        return RET_ERR;
    }
    std::string name = "primaryButton";
    int32_t primaryButton = pref->GetInt(name, 0);
    NativePreferences::PreferencesHelper::
        RemovePreferencesFromCache("/data/service/el1/public/multimodalinput/mouse_settings");
    MMI_HILOGD("Set mouse primary button:%{public}d", primaryButton);
    return primaryButton;
}

int32_t MouseTransformProcessor::SetPointerSpeed(int32_t speed)
{
    CALL_DEBUG_ENTER;
    if (speed < MIN_SPEED) {
        globalPointerSpeed_ = MIN_SPEED;
    } else if (speed > MAX_SPEED) {
        globalPointerSpeed_ = MAX_SPEED;
    } else {
        globalPointerSpeed_ = speed;
    }
    isUserSetSpeedStatus_ = true;
    MMI_HILOGD("Set pointer speed:%{public}d", globalPointerSpeed_);
    return RET_OK;
}

int32_t MouseTransformProcessor::GetPointerSpeed()
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Get pointer speed:%{public}d", globalPointerSpeed_);
    return globalPointerSpeed_;
}


void MouseTransformProcessor::SetDxDyForDInput(PointerEvent::PointerItem& pointerItem,
    struct libinput_event_pointer* data)
{
    double dx = libinput_event_pointer_get_dx(data);
    double dy = libinput_event_pointer_get_dy(data);
    int32_t rawDx = static_cast<int32_t>(dx);
    int32_t rawDy = static_cast<int32_t>(dy);
    pointerItem.SetRawDx(rawDx);
    pointerItem.SetRawDy(rawDy);
    MMI_HILOGD("MouseTransformProcessor SetDxDyForDInput, dx:%{public}d, dy:%{public}d", rawDx, rawDy);
}

int32_t MouseTransformProcessor::SetPointerLocation(int32_t x, int32_t y)
{
    MMI_HILOGI("Location, x:%{public}d, y:%{public}d", x, y);
    auto displayGroupInfo = WinMgr->GetDisplayGroupInfo();
    if (currentDisplayId_ == -1) {
        if (displayGroupInfo.displaysInfo.empty()) {
            MMI_HILOGI("The displayInfo is empty");
            return RET_ERR;
        }
        currentDisplayId_ = displayGroupInfo.displaysInfo[0].id;
    }
    absolutionX_ = static_cast<double>(x);
    absolutionY_ = static_cast<double>(y);
    WinMgr->UpdateAndAdjustMouseLocation(currentDisplayId_, absolutionX_, absolutionY_);
    int32_t physicalX = WinMgr->GetMouseInfo().physicalX;
    int32_t physicalY = WinMgr->GetMouseInfo().physicalY;
    IPointerDrawingManager::GetInstance()->SetPointerLocation(getpid(), physicalX, physicalY);
    return RET_OK;
}

int32_t MouseTransformProcessor::GetSpeed() const
{
    if ((vendorConfigPointerSpeed_ == -1) || isUserSetSpeedStatus_) {
        return globalPointerSpeed_;
    }
    return vendorConfigPointerSpeed_;
}

void MouseTransformProcessor::SetConfigPointerSpeed(int32_t speed)
{
    if (speed < MIN_SPEED) {
        vendorConfigPointerSpeed_ = MIN_SPEED;
    } else if (speed > MAX_SPEED) {
        vendorConfigPointerSpeed_ = MAX_SPEED;
    } else {
        vendorConfigPointerSpeed_ = speed;
    }
}
} // namespace MMI
} // namespace OHOS
