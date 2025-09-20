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

#include "ani_input_monitor_consumer.h"

#include <utility>

#include "ani_input_monitor_manager.h"
#include "input_manager.h"
#include "mmi_log.h"


#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AniInputMonitorConsumer"

namespace OHOS {
namespace MMI {
namespace {
std::map<MONITORFUNTYPE, std::string> FUNCTTOYPENAME = {
    { MONITORFUNTYPE::ON_TOUCH, "touch"},
    { MONITORFUNTYPE::ON_TOUCH_BOOL, "touch"},
    { MONITORFUNTYPE::ON_MOUSE, "mouse"},
    { MONITORFUNTYPE::ON_MOUSE_RECT, "mouse"},
    { MONITORFUNTYPE::ON_PINCH, "pinch"},
    { MONITORFUNTYPE::ON_PINCH_FINGERS, "pinch"},
    { MONITORFUNTYPE::ON_ROTATE_FINGERS, "rotate"},
    { MONITORFUNTYPE::ON_THREEFINGERSWIPE, "threeFingersSwipe"},
    { MONITORFUNTYPE::ON_FOURFINGERSWIPE, "fourFingersSwipe"},
    { MONITORFUNTYPE::ON_THREEFINGERSTAP, "threeFingersTap"},
    { MONITORFUNTYPE::ON_FINGERPRINT, "fingerprint"},
    { MONITORFUNTYPE::ON_SWIPEINWARD, "swipeInward"},
    { MONITORFUNTYPE::ON_TOUCHSCREENSWIPE_FINGERS, "touchscreenSwipe"},
    { MONITORFUNTYPE::ON_TOUCHSCREENPINCH_FINGERS, "touchscreenPinch"},
    { MONITORFUNTYPE::ON_KEYPRESSED_KEYS, "keyPressed"},
    { MONITORFUNTYPE::OFF_TOUCH, "touch"},
    { MONITORFUNTYPE::OFF_MOUSE, "mouse"},
    { MONITORFUNTYPE::OFF_PINCH, "pinch"},
    { MONITORFUNTYPE::OFF_PINCH_FINGERS, "pinch"},
    { MONITORFUNTYPE::OFF_ROTATE_FINGERS, "rotate"},
    { MONITORFUNTYPE::OFF_THREEFINGERSWIPE, "threeFingersSwipe"},
    { MONITORFUNTYPE::OFF_FOURFINGERSWIPE, "fourFingersSwipe"},
    { MONITORFUNTYPE::OFF_THREEFINGERSTAP, "threeFingersTap"},
    { MONITORFUNTYPE::OFF_FINGERPRINT, "fingerprint"},
    { MONITORFUNTYPE::OFF_SWIPEINWARD, "swipeInward"},
    { MONITORFUNTYPE::OFF_TOUCHSCREENSWIPE_FINGERS, "touchscreenSwipe"},
    { MONITORFUNTYPE::OFF_TOUCHSCREENPINCH_FINGERS, "touchscreenPinch"},
    { MONITORFUNTYPE::OFF_KEYPRESSED_KEYS, "keyPressed"},
};

constexpr int32_t MOUSE_FLOW { 10 };
const std::string INVALID_TYPE_NAME { "" };
constexpr int32_t ONE_FINGERS { 1 };
constexpr int32_t THREE_FINGERS { 3 };
constexpr int32_t FOUR_FINGERS { 4 };

inline const std::string TOUCH_SWIPE_GESTURE = "touchscreenSwipe";
inline const std::string TOUCH_PINCH_GESTURE = "touchscreenPinch";
inline const std::string TOUCH_ALL_GESTURE = "touchAllGesture";

std::map<std::string, TouchGestureType> TO_GESTURE_TYPE = {
    { TOUCH_PINCH_GESTURE, TOUCH_GESTURE_TYPE_PINCH },
    { TOUCH_SWIPE_GESTURE, TOUCH_GESTURE_TYPE_SWIPE },
    { TOUCH_ALL_GESTURE, TOUCH_GESTURE_TYPE_ALL },
};

std::map<std::string, int32_t> TO_HANDLE_EVENT_TYPE = {
    { "none", HANDLE_EVENT_TYPE_NONE },
    { "key", HANDLE_EVENT_TYPE_KEY },
    { "pointer", HANDLE_EVENT_TYPE_POINTER },
    { "touch", HANDLE_EVENT_TYPE_TOUCH },
    { "mouse", HANDLE_EVENT_TYPE_MOUSE },
    { "pinch", HANDLE_EVENT_TYPE_PINCH },
    { "threeFingersSwipe", HANDLE_EVENT_TYPE_THREEFINGERSSWIP },
    { "fourFingersSwipe", HANDLE_EVENT_TYPE_FOURFINGERSSWIP },
    { "swipeInward", HANDLE_EVENT_TYPE_SWIPEINWARD },
    { "rotate", HANDLE_EVENT_TYPE_ROTATE },
    { "threeFingersTap", HANDLE_EVENT_TYPE_THREEFINGERSTAP },
    { "fingerprint", HANDLE_EVENT_TYPE_FINGERPRINT },
#ifdef OHOS_BUILD_ENABLE_X_KEY
    { "xKey", HANDLE_EVENT_TYPE_X_KEY },
#endif // OHOS_BUILD_ENABLE_X_KEY
};

std::map<std::string, int32_t> TO_HANDLE_PRE_EVENT_TYPE = {
    { "keyPressed", HANDLE_EVENT_TYPE_PRE_KEY },
};
}

struct MonitorInfo {
    int32_t monitorId {0};
};

void CleanData(MonitorInfo** monitorInfo, uv_work_t** work)
{
    if (monitorInfo != nullptr && *monitorInfo != nullptr) {
        delete *monitorInfo;
        *monitorInfo = nullptr;
    }
    if (work != nullptr && *work != nullptr) {
        delete *work;
        *work = nullptr;
    }
}

AniInputMonitorConsumer::AniInputMonitorConsumer(MONITORFUNTYPE funType, int32_t fingers,
    std::vector<Rect> hotRectArea, std::vector<int32_t> keys,
    std::shared_ptr<CallbackObject> &aniCallback)
    : funType_(funType),
      fingers_(fingers),
      keys_(keys),
      hotRectArea_(hotRectArea),
      aniCallback_(aniCallback)
{
}

int32_t AniInputMonitorConsumer::GetId() const
{
    return monitorId_;
}

int32_t AniInputMonitorConsumer::GetFingers() const
{
    return fingers_;
}

std::string AniInputMonitorConsumer::GetTypeName() const
{
    auto itFind = FUNCTTOYPENAME.find(funType_);
    if (itFind != FUNCTTOYPENAME.end()) {
        return itFind->second;
    }
    return "";
}

MONITORFUNTYPE AniInputMonitorConsumer::GetFunType() const
{
    return funType_;
}

bool AniInputMonitorConsumer::IsOnFunc() const
{
    if (funType_ >= MONITORFUNTYPE::ON_TOUCH && funType_ <= MONITORFUNTYPE::ON_KEYPRESSED_KEYS) {
        return true;
    }
    return false;
}

bool AniInputMonitorConsumer::CheckOffFuncParam(MONITORFUNTYPE funType, int32_t fingers) const
{
    bool bCheck = false;
    if (GetFunType() == funType) {
        if (funType == MONITORFUNTYPE::OFF_TOUCHSCREENPINCH_FINGERS ||
            funType ==  MONITORFUNTYPE::OFF_TOUCHSCREENPINCH_FINGERS) {
                if (fingers == GetFingers()) {
                    bCheck = true;
                }
        } else {
            bCheck = true;
        }
    }
    return bCheck;
}

int32_t AniInputMonitorConsumer::Start()
{
    CALL_DEBUG_ENTER;
    auto typeName = GetTypeName();
    std::lock_guard<std::mutex> guard(mutex_);
    int32_t ret = RET_ERR;
    bool bFindType = false;
    auto iter = TO_HANDLE_PRE_EVENT_TYPE.find(typeName.c_str());
    if (iter != TO_HANDLE_PRE_EVENT_TYPE.end()) {
        ret = InputManager::GetInstance()->AddPreMonitor(shared_from_this(), iter->second, keys_);
        bFindType = true;
    }

    auto it = TO_GESTURE_TYPE.find(typeName);
    if (it != TO_GESTURE_TYPE.end()) {
        ret = InputManager::GetInstance()->AddGestureMonitor(shared_from_this(), it->second, fingers_);
        bFindType = true;
    }

    int32_t eventType = 0;
    auto itFind = TO_HANDLE_EVENT_TYPE.find(typeName);
    if (itFind != TO_HANDLE_EVENT_TYPE.end()) {
        eventType = itFind->second;
        ret = InputManager::GetInstance()->AddMonitor(shared_from_this(), eventType);
        bFindType = true;
    }

    if (!bFindType) {
        MMI_HILOGE("not found type:%{public}s", typeName.c_str());
        return ret;
    }
    if (ret >= 0) {
        monitorId_ = ret;
        isMonitoring_ = true;
    }
    return ret;
}

void AniInputMonitorConsumer::Stop()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    if (!isMonitoring_) {
        MMI_HILOGE("not start");
        return;
    }
    isMonitoring_ = false;
    if (monitorId_ < 0) {
        MMI_HILOGE("Invalid values");
        return;
    }

    auto iter = TO_HANDLE_PRE_EVENT_TYPE.find(GetTypeName().c_str());
    if (iter != TO_HANDLE_PRE_EVENT_TYPE.end()) {
        InputManager::GetInstance()->RemovePreMonitor(monitorId_);
        monitorId_ = -1;
        return;
    }

    auto it = TO_GESTURE_TYPE.find(GetTypeName());
    if (it != TO_GESTURE_TYPE.end()) {
        InputManager::GetInstance()->RemoveGestureMonitor(monitorId_);
    } else {
        InputManager::GetInstance()->RemoveMonitor(monitorId_);
    }
    monitorId_ = -1;
}

std::shared_ptr<AniInputMonitorConsumer> AniInputMonitorConsumer::CreateAniInputMonitorConsumer(MONITORFUNTYPE funType,
    const ConsumerParmType &param, callbackType &&cb, uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<AniInputMonitorConsumer> ret = { nullptr };
    int32_t fingers { 0 };
    std::vector<Rect> rect;
    std::vector<int32_t> keys;
    switch (funType) {
        case MONITORFUNTYPE::ON_PINCH_FINGERS:
        case MONITORFUNTYPE::ON_ROTATE_FINGERS:
        case MONITORFUNTYPE::ON_TOUCHSCREENSWIPE_FINGERS:
        case MONITORFUNTYPE::ON_TOUCHSCREENPINCH_FINGERS: {
            auto *pVal =  std::get_if<int32_t>(&param);
            if (pVal == nullptr) {
                return ret;
            }
            fingers = *pVal;
            break;
        }
        case MONITORFUNTYPE::ON_MOUSE_RECT: {
            auto *pVal =  std::get_if<std::vector<OHOS::MMI::Rect>>(&param);
            if (pVal == nullptr) {
                return ret;
            }
            rect = *pVal;
            break;
        }
        case MONITORFUNTYPE::ON_KEYPRESSED_KEYS: {
            auto *pVal =  std::get_if<std::vector<int32_t>>(&param);
            if (pVal == nullptr) {
                return ret;
            }
            keys = *pVal;
            break;
        }
    default:
        break;
    }
    std::shared_ptr<CallbackObject> callback;
    if (!ANI_INPUT_MONITOR_MGR.CreateCallback(std::forward<callbackType>(cb), opq, callback)) {
        return ret;
    }
    ret = std::make_shared<AniInputMonitorConsumer>(funType, fingers, rect, keys, callback);
    return ret;
}

void AniInputMonitorConsumer::OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    {
        std::lock_guard<std::mutex> guard(mutex_);
        auto typeName = GetTypeName();
        if (typeName== INVALID_TYPE_NAME || typeName != "keyPressed") {
            MMI_HILOGE("Failed to process key event.");
            return;
        }
        OnAniKeyEvent(keyEvent);
    }
}

bool AniInputMonitorConsumer::IsBeginAndEnd(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHKPF(pointerEvent);
    bool res = pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_SWIPE_BEGIN ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_SWIPE_END;
    return res;
}

void AniInputMonitorConsumer::OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (!PrepareData(pointerEvent)) {
        MMI_HILOGE("The Parepate Data failed");
        return;
    }
    if (!evQueue_.empty()) {
        uv_work_t *work = new (std::nothrow) uv_work_t;
        CHKPV(work);
        MonitorInfo *monitorInfo = new (std::nothrow) MonitorInfo();
        if (monitorInfo == nullptr) {
            MMI_HILOGE("The monitorInfo is nullptr");
            delete work;
            work = nullptr;
            return;
        }
        monitorInfo->monitorId = monitorId_;
        work->data = monitorInfo;
        uv_loop_s *loop = uv_default_loop();
        if (loop == nullptr) {
            MMI_HILOGE("The loop is nullptr");
            CleanData(&monitorInfo, &work);
            return;
        }
        MMI_HILOGD("the loop status %{public}d", loop->stop_flag);
        int32_t ret = uv_queue_work_with_qos(
            loop, work,
            [](uv_work_t *work) {
                MMI_HILOGD("uv_queue_work async callback function is called");
            },
            [] (uv_work_t *work, int32_t status) {
                MMI_HILOGD("uv_queue_work done callback function is called%{public}d", status);
                AniInputMonitorConsumer::AniWorkCallback(work, status);
            },
            uv_qos_user_initiated);
        if (ret != 0) {
            MMI_HILOGE("Add uv_queue failed, ret is %{public}d", ret);
            CleanData(&monitorInfo, &work);
        }
        if (!loop->stop_flag) {
            uv_run(loop, UV_RUN_DEFAULT);
        }
    }
}

bool AniInputMonitorConsumer::PrepareData(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CALL_DEBUG_ENTER;
    CHKPF(pointerEvent);
    std::lock_guard<std::mutex> guard(mutex_);
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE
        && pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE) {
        if (++flowCtrl_ < MOUSE_FLOW) {
            MMI_HILOGE("Failed to flowCtrl_");
            return false;
        } else { flowCtrl_ = 0; }
    }
    auto typeName = GetTypeName();
    CHKFR(typeName != INVALID_TYPE_NAME, false, "Failed to process pointer event");
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        if (typeName != "touch" && typeName != TOUCH_SWIPE_GESTURE &&
            typeName != TOUCH_PINCH_GESTURE && typeName != TOUCH_ALL_GESTURE) {
            MMI_HILOGD("NOT TOUCH");
            return false;
        }
        SetConsumeState(pointerEvent);
    }
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
        if (typeName != "mouse" && typeName != "pinch" && typeName != "rotate") {
            MMI_HILOGD("NOT pinch");
            return false;
        }
        SetConsumeState(pointerEvent);
    }
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHPAD) {
        CHKFR(IsGestureEvent(pointerEvent), false, "not gesture event");
    }
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_JOYSTICK && (GetTypeName() != "joystick")) {
        MMI_HILOGE("Failed to process joystick event");
        return false;
    }
    if (!evQueue_.empty() && IsBeginAndEnd(pointerEvent)) {
        std::queue<std::shared_ptr<PointerEvent>> tmp;
        std::swap(evQueue_, tmp);
    }
    evQueue_.push(pointerEvent);
    return true;
}

void AniInputMonitorConsumer::AniWorkCallback(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    auto temp = static_cast<MonitorInfo*>(work->data);
    delete work;
    work = nullptr;
    auto monitor = ANI_INPUT_MONITOR_MGR.GetMonitor(temp->monitorId);
    if (monitor) {
        monitor->OnPointerEventInEvThread();
    }
    delete temp;
    temp = nullptr;
}

void AniInputMonitorConsumer::OnPointerEventInEvThread()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    if (!isMonitoring_) {
        MMI_HILOGE("Js monitor stop");
        return;
    }
    while (!evQueue_.empty()) {
        if (!isMonitoring_) {
            MMI_HILOGE("Js monitor stop handle callback");
            break;
        }
        auto pointerEvent = evQueue_.front();
        evQueue_.pop();
        if (pointerEvent == nullptr) {
            MMI_HILOGE("Scope is nullptr");
            continue;
        }
        OnPerPointerEvent(pointerEvent);
    }
}

void AniInputMonitorConsumer::OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const
{
    CALL_DEBUG_ENTER;
}

void AniInputMonitorConsumer::SetConsumeState(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHKPV(pointerEvent);
    if (pointerEvent->GetPointerIds().size() == 1) {
        if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
            consumed_ = false;
        }
    }
}

bool AniInputMonitorConsumer::IsGestureEvent(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHKPF(pointerEvent);
    auto ret = GetTypeName();
    if (ret != "pinch" && ret != "threeFingersSwipe" &&
        ret != "fourFingersSwipe" && ret != "threeFingersTap" &&
        ret != "swipeInward") {
        return false;
    }
    if (pointerEvent->GetPointerIds().size() == 1) {
        if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_BEGIN ||
            PointerEvent::POINTER_ACTION_SWIPE_BEGIN) {
            consumed_ = false;
        }
    }
    return true;
}

bool AniInputMonitorConsumer::IsPinch(std::shared_ptr<PointerEvent> pointerEvent, const int32_t fingers) const
{
    CHKPF(pointerEvent);
    if ((fingers > 0 && ((pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_MOUSE &&
        pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD) ||
        pointerEvent->GetFingerCount() != fingers)) ||
        (fingers == 0 && (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD ||
        pointerEvent->GetFingerCount() < THREE_FINGERS))) {
        return false;
    }
    if ((pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_AXIS_BEGIN &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_AXIS_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_AXIS_END)) {
        return false;
    }
    return true;
}

bool AniInputMonitorConsumer::IsRotate(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHKPF(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_MOUSE ||
        (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_ROTATE_BEGIN &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_ROTATE_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_ROTATE_END)) {
        return false;
    }
    return true;
}

bool AniInputMonitorConsumer::IsThreeFingersSwipe(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHKPF(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD ||
        pointerEvent->GetFingerCount() != THREE_FINGERS ||
        (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_BEGIN &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_END)) {
        return false;
    }
    return true;
}

bool AniInputMonitorConsumer::IsFourFingersSwipe(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHKPF(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD ||
        pointerEvent->GetFingerCount() != FOUR_FINGERS ||
        (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_BEGIN &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_END)) {
        return false;
    }
    return true;
}

bool AniInputMonitorConsumer::IsThreeFingersTap(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHKPF(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD ||
        pointerEvent->GetFingerCount() != THREE_FINGERS ||
        (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_TRIPTAP)) {
        return false;
    }
    return true;
}

bool AniInputMonitorConsumer::IsJoystick(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);

    return (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_JOYSTICK &&
        (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_UP ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_DOWN ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_UPDATE));
}

bool AniInputMonitorConsumer::IsSwipeInward(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHKPF(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD) {
        MMI_HILOGE("Failed to do swipe inward, wrong source:%{public}d ", pointerEvent->GetSourceType());
        return false;
    } else if (pointerEvent->GetFingerCount() != ONE_FINGERS) {
        MMI_HILOGE("Failed to do swipe inward, more than one finger");
        return false;
    } else if (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_DOWN &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_MOVE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_UP &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_CANCEL) {
        MMI_HILOGE("Failed to do swipe inward, wrong action");
        return false;
    }
    return true;
}

bool AniInputMonitorConsumer::IsFingerprint(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_FINGERPRINT &&
        ((PointerEvent::POINTER_ACTION_FINGERPRINT_DOWN <= pointerEvent->GetPointerAction() &&
        pointerEvent->GetPointerAction() <= PointerEvent::POINTER_ACTION_FINGERPRINT_CLICK) ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_FINGERPRINT_CANCEL ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_FINGERPRINT_HOLD ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_FINGERPRINT_TOUCH)) {
        return true;
    }
    MMI_HILOGD("Not fingerprint event");
    return false;
}

#ifdef OHOS_BUILD_ENABLE_X_KEY
bool AniInputMonitorConsumer::IsXKey(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_X_KEY) {
        return true;
    }
    MMI_HILOGD("Not X-key event.");
    return false;
}
#endif // OHOS_BUILD_ENABLE_X_KEY

void AniInputMonitorConsumer::CheckConsumed(bool retValue, std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (retValue) {
        auto eventId = pointerEvent->GetId();
        MarkConsumed(eventId);
    }
}

void AniInputMonitorConsumer::MarkConsumed(int32_t eventId)
{
    if (consumed_) {
        MMI_HILOGD("The consumed_ is true");
        return;
    }
    if (monitorId_ < 0) {
        MMI_HILOGE("Invalid values");
        return;
    }
    InputManager::GetInstance()->MarkConsumed(monitorId_, eventId);
    consumed_ = true;
}

bool AniInputMonitorConsumer::IsLocaledWithinRect(
    std::shared_ptr<PointerEvent> pointerEvent, std::vector<Rect> hotRectArea) const
{
    bool bFind = false;
    int32_t currentPointerId = pointerEvent->GetPointerId();
    std::vector<int32_t> pointerIds { pointerEvent->GetPointerIds() };
    PointerEvent::PointerItem item;
    for (const auto& pointerId : pointerIds) {
        if (pointerId == currentPointerId) {
            if (!pointerEvent->GetPointerItem(pointerId, item)) {
                MMI_HILOGE("Invalid pointer:%{public}d", pointerId);
                return false;
            }
            bFind = true;
            break;
        }
    }
    if (!bFind) {
        return false;
    }
    auto xInt = item.GetDisplayX();
    auto yInt = item.GetDisplayY();
    for (uint32_t i = 0; i < hotRectArea.size(); i++) {
        int32_t hotAreaX = hotRectArea.at(i).x;
        int32_t hotAreaY = hotRectArea.at(i).y;
        int32_t hotAreaWidth = hotRectArea.at(i).width;
        int32_t hotAreaHeight = hotRectArea.at(i).height;
        if ((xInt >= hotAreaX) && (xInt <= hotAreaX + hotAreaWidth)
            && (yInt >= hotAreaY) && (yInt <= hotAreaY + hotAreaHeight)) {
            return true;
        }
    }
    return false;
}

void AniInputMonitorConsumer::OnTouchCallback(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    TaiheTouchEvent result {.action = TaiheTouchAction::key_t::CANCEL,
                .touch = TaiheTouch {.toolType = TaiheToolType::key_t::FINGER},
                .sourceType = TaiheSourceType::key_t::TOUCH_SCREEN };
    auto ret = TaiheMonitorConverter::TouchEventToTaihe(*pointerEvent, result);
    if (ret != RET_OK) {
        MMI_HILOGE("Faild to change taihe.");
        return;
    }
    auto &func = std::get<taihe::callback<void(TaiheTouchEvent const &)>>(aniCallback_->callback);
    func(result);
}

void AniInputMonitorConsumer::OnTouchNeedResultCallback(std::shared_ptr<PointerEvent> pointerEvent, bool &retValue)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    retValue = false;
    TaiheTouchEvent result {.action = TaiheTouchAction::key_t::CANCEL,
                .touch = TaiheTouch {.toolType = TaiheToolType::key_t::FINGER},
                .sourceType = TaiheSourceType::key_t::TOUCH_SCREEN };
    auto ret = TaiheMonitorConverter::TouchEventToTaihe(*pointerEvent, result);
    if (ret != RET_OK) {
        MMI_HILOGE("Faild to change taihe.");
        return;
    }
    auto &func = std::get<taihe::callback<bool(TaiheTouchEvent const &)>>(aniCallback_->callback);
    retValue = func(result);
}

void AniInputMonitorConsumer::OnMouseCallback(std::shared_ptr<PointerEvent> pointerEvent, bool retRectArea)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (retRectArea && IsLocaledWithinRect(pointerEvent, hotRectArea_)) {
        MMI_HILOGD("not in area.");
        return;
    }
    TaiheMouseEvent result {.action = TaiheMouseAction::key_t::CANCEL,
        .button = TaiheMouseButton::key_t::LEFT,
        .toolType = TaiheMouseToolType::key_t::UNKNOWN, };
    auto &func = std::get<taihe::callback<void(TaiheMouseEvent const &)>>(aniCallback_->callback);
    auto ret = TaiheMonitorConverter::MouseEventToTaihe(pointerEvent, result);
    if (ret != RET_OK) {
        MMI_HILOGE("Faild to change taihe.");
        return;
    }
    func(result);
}

void AniInputMonitorConsumer::OnPinchCallback(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (!IsPinch(pointerEvent, fingers_)) {
        MMI_HILOGD("not pinch.");
        return;
    }
    TaihePinchEvent result {.type = TaiheGestureActionType::from_value(RET_ERR)};
    auto ret = TaiheMonitorConverter::PinchToTaihe(*pointerEvent, result);
    if (ret != RET_OK) {
        MMI_HILOGE("Faild to change taihe.");
        return;
    }
    auto &func = std::get<taihe::callback<void(TaihePinchEvent const &)>>(aniCallback_->callback);
    func(result);
}

void AniInputMonitorConsumer::OnRotateCallback(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (!IsRotate(pointerEvent)) {
        MMI_HILOGD("not rotate.");
        return;
    }
    TaiheRotate result{.type = TaiheGestureActionType::from_value(RET_ERR)};
    auto ret = TaiheMonitorConverter::RotateToTaihe(*pointerEvent, result);
    if (ret != RET_OK) {
        MMI_HILOGE("Faild to change taihe.");
        return;
    }
    auto &func = std::get<taihe::callback<void(TaiheRotate const &)>>(aniCallback_->callback);
    func(result);
}

void AniInputMonitorConsumer::OnThreeFingersSwipeCallback(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (!IsThreeFingersSwipe(pointerEvent)) {
        MMI_HILOGE("Not three fingers swipe");
        return;
    }
    TaiheThreeFingersSwipe result{.type = TaiheGestureActionType::from_value(RET_ERR)};
    auto ret = TaiheMonitorConverter::ThreeFingersSwipeToTaihe(*pointerEvent, result);
    if (ret == RET_OK) {
        MMI_HILOGE("Faild to change taihe.");
        return;
    }
    auto &func = std::get<taihe::callback<void(TaiheThreeFingersSwipe const &)>>(aniCallback_->callback);
    func(result);
}

void AniInputMonitorConsumer::OnFourFingersSwipeCallback(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (!IsFourFingersSwipe(pointerEvent)) {
        MMI_HILOGE("Not four fingers swipe");
        return;
    }
    TaiheFourFingersSwipe result{.type = TaiheGestureActionType::from_value(RET_ERR)};
    auto ret = TaiheMonitorConverter::FourFingersSwipeToTaihe(*pointerEvent, result);
    if (ret != RET_OK) {
        MMI_HILOGE("Faild to change taihe.");
        return;
    }
    auto &func = std::get<taihe::callback<void(TaiheFourFingersSwipe const &)>>(aniCallback_->callback);
    func(result);
}

void AniInputMonitorConsumer::OnThreeFingersTapCallback(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (!IsThreeFingersTap(pointerEvent)) {
        MMI_HILOGE("Not three fingers tap");
        return;
    }
    TaiheThreeFingersTap result{.type = TaiheGestureActionType::from_value(RET_ERR)};
    auto ret = TaiheMonitorConverter::ThreeFingersTapToTaihe(*pointerEvent, result);
    if (ret != RET_OK) {
        MMI_HILOGE("Faild to change taihe.");
        return;
    }
    auto &func = std::get<taihe::callback<void(TaiheThreeFingersTap const &)>>(aniCallback_->callback);
    func(result);
}

#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
void AniInputMonitorConsumer::OnFingerprintCallback(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (!IsFingerprint(pointerEvent)) {
        MMI_HILOGE("Not fingerprint");
        return;
    }
    TaiheFingerprintEvent result{.action = TaiheFingerprintAction::from_value(RET_ERR)};
    auto ret = TaiheMonitorConverter::FingerprintEventToTaihe(*pointerEvent, result);
    if (ret != RET_OK) {
        MMI_HILOGE("Faild to change taihe.");
        return;
    }
    auto &func = std::get<taihe::callback<void(TaiheFingerprintEvent const &)>>(aniCallback_->callback);
    func(result);
}
#endif // OHOS_BUILD_ENABLE_FINGERPRINT

void AniInputMonitorConsumer::OnSwipeInwardCallback(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (!IsSwipeInward(pointerEvent)) {
        MMI_HILOGE("Not swipeinward");
        return;
    }
    TaiheSwipeInward result{.type = TaiheGestureActionType::from_value(RET_ERR)};
    auto ret = TaiheMonitorConverter::SwipeInwardToTaihe(*pointerEvent, result);
    if (ret != RET_OK) {
        MMI_HILOGE("Faild to change taihe.");
        return;
    }
    auto &func = std::get<taihe::callback<void(TaiheSwipeInward const &)>>(aniCallback_->callback);
    func(result);
}

void AniInputMonitorConsumer::OnTouchScreenPinchCallback(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    TaiheTouchGestureEvent result{.action = TaiheTouchGestureAction::from_value(RET_ERR)};
    auto ret = TaiheMonitorConverter::TouchGestureEventToTaihe(*pointerEvent, result);
    if (ret != RET_OK) {
        MMI_HILOGE("Faild to change taihe.");
        return;
    }
    auto &func = std::get<taihe::callback<void(TaiheTouchGestureEvent const &)>>(aniCallback_->callback);
    func(result);
}

#ifdef OHOS_BUILD_ENABLE_X_KEY
void AniInputMonitorConsumer::OnXkeyCallback(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (!IsXKey(pointerEvent)) {
        MMI_HILOGE("Not Xkey.");
        return;
    }
    // 0702 The definition is not found in the interface.
}
#endif // OHOS_BUILD_ENABLE_X_KEY

void AniInputMonitorConsumer::OnPerPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    if (!isMonitoring_) {
        MMI_HILOGE("AniInputMonitorConsumer stop");
        return;
    }
    MMI_HILOGD("pointer event:%{public}s", pointerEvent->ToString().c_str());
    LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
    bool retValue = false;
    switch (funType_) {
        case MONITORFUNTYPE::ON_TOUCH: {
            OnTouchCallback(pointerEvent);
            break;
        }
        case MONITORFUNTYPE::ON_TOUCH_BOOL: {
            OnTouchNeedResultCallback(pointerEvent, retValue);
            break;
        }
        case MONITORFUNTYPE::ON_MOUSE:
        case MONITORFUNTYPE::ON_MOUSE_RECT: {
            OnMouseCallback(pointerEvent, funType_ == MONITORFUNTYPE::ON_MOUSE_RECT);
            break;
        }
        case MONITORFUNTYPE::ON_PINCH:
        case MONITORFUNTYPE::ON_PINCH_FINGERS: {
            OnPinchCallback(pointerEvent);
            break;
        }
        case MONITORFUNTYPE::ON_ROTATE_FINGERS: {
            OnRotateCallback(pointerEvent);
            break;
        }
        case MONITORFUNTYPE::ON_THREEFINGERSWIPE: {
            OnThreeFingersSwipeCallback(pointerEvent);
            break;
        }
        case MONITORFUNTYPE::ON_FOURFINGERSWIPE: {
            OnFourFingersSwipeCallback(pointerEvent);
            break;
        }
        case MONITORFUNTYPE::ON_THREEFINGERSTAP: {
            OnThreeFingersTapCallback(pointerEvent);
            break;
        }
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
        case MONITORFUNTYPE::ON_FINGERPRINT: {
            OnFingerprintCallback(pointerEvent);
            break;
        }
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
        case MONITORFUNTYPE::ON_SWIPEINWARD: {
            OnSwipeInwardCallback(pointerEvent);
            break;
        }
        case MONITORFUNTYPE::ON_TOUCHSCREENSWIPE_FINGERS:
        case MONITORFUNTYPE::ON_TOUCHSCREENPINCH_FINGERS: {
            OnTouchScreenPinchCallback(pointerEvent);
            break;
        }
#ifdef OHOS_BUILD_ENABLE_X_KEY
        case MONITORFUNTYPE::ON_KEYPRESSED_KEYS: {
            OnXkeyCallback(pointerEvent);
            break;
        }
#endif // OHOS_BUILD_ENABLE_X_KEY
        default:
           MMI_HILOGE("This event is invalid");
           break;
    }
    pointerEvent->MarkProcessed();
    // 0702: It feels like something other than a mouse
    std::string typeName = GetTypeName();
    bool typeNameFlag = typeName == "touch" || typeName == "pinch" || typeName == "threeFingersSwipe" ||
        typeName == "fourFingersSwipe" || typeName == "rotate" || typeName == "threeFingersTap" ||
        typeName == "joystick" || typeName == "fingerprint" || typeName == "swipeInward" ||
        typeName == TOUCH_SWIPE_GESTURE || typeName == TOUCH_PINCH_GESTURE || typeName == TOUCH_ALL_GESTURE ||
        typeName == "xKey";
    if (typeNameFlag) {
        if (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_UPDATE &&
            pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_PULL_MOVE) {
            MMI_HILOGI("PointerId:%{public}d, PointerAction:%{public}s", pointerEvent->GetPointerId(),
                pointerEvent->DumpPointerAction());
        }
        // 0702: The function for obtaining callback success needs to be modified.
        if (funType_ == MONITORFUNTYPE::ON_TOUCH_BOOL) {
            CheckConsumed(retValue, pointerEvent);
        }
    }
}

void AniInputMonitorConsumer::OnAniKeyEvent(std::shared_ptr<KeyEvent> keyEvent) const
{
    CALL_DEBUG_ENTER;
    if (!isMonitoring_) {
        MMI_HILOGE("Js monitor stop");
        return;
    }
    auto typeName = GetTypeName();
    int32_t ret = RET_ERR;
    switch (funType_) {
        case MONITORFUNTYPE::ON_KEYPRESSED_KEYS: {
            MMI_HILOGD("recv keys info:%{public}s", keyEvent->ToString().c_str());
            TaiheKeyEvent result{.action =  TaiheKeyEventAction::from_value(RET_ERR),
                                 .key = {.code = KeyCode::key_t::KEYCODE_UNKNOWN}};
            ret = TaiheMonitorConverter::TaiheKeyEventToTaihe(*keyEvent, result);
            if (ret == RET_OK) {
                auto &func = std::get<taihe::callback<void(TaiheKeyEvent const &)>>(aniCallback_->callback);
                func(result);
            }
            break;
        }
        default: {
            MMI_HILOGE("This event is invalid");
            break;
        }
    }
}
} // namespace MMI
} // namespace OHOS
