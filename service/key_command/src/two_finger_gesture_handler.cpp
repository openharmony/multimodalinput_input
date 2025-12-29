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

#include "two_finger_gesture_handler.h"

#include "ability_launcher.h"
#include "bytrace_adapter.h"
#include "dfx_hisysevent.h"
#include "key_command_handler_util.h"
#include "timer_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TwoFingerGestureHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr int64_t SCREEN_TIME_OUT { 100 };
} // namespace

#ifdef OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
void TwoFingerGestureHandler::HandleFingerGestureDownEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    if (!context_.twoFingerGesture_.active) {
        MMI_HILOGD("Two finger gesture is not active");
        return;
    }
    auto num = touchEvent->GetPointerIds().size();
    if (num == TwoFingerGesture::MAX_TOUCH_NUM) {
        StartTwoFingerGesture();
    } else {
        StopTwoFingerGesture();
    }
    if (num > 0 && num <= TwoFingerGesture::MAX_TOUCH_NUM) {
        int32_t id = touchEvent->GetPointerId();
        PointerEvent::PointerItem item;
        touchEvent->GetPointerItem(id, item);
        context_.twoFingerGesture_.touches[num - 1].id = id;
        context_.twoFingerGesture_.touches[num - 1].x = item.GetDisplayX();
        context_.twoFingerGesture_.touches[num - 1].y = item.GetDisplayY();
        context_.twoFingerGesture_.touches[num - 1].downTime = item.GetDownTime();
    }
}
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void TwoFingerGestureHandler::HandlePointerActionMoveEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    int32_t id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    if (!context_.twoFingerGesture_.active) {
        return;
    }
    if (context_.twoFingerGesture_.timerId == -1) {
        MMI_HILOGD("Two finger gesture timer id is -1");
        return;
    }
    auto pos = std::find_if(std::begin(context_.twoFingerGesture_.touches),
        std::end(context_.twoFingerGesture_.touches),
        [id](const auto& item) { return item.id == id; });
    if (pos == std::end(context_.twoFingerGesture_.touches)) {
        MMI_HILOGE("Cant't find the pointer id");
        return;
    }
    auto dx = std::abs(pos->x - item.GetDisplayX());
    auto dy = std::abs(pos->y - item.GetDisplayY());
    auto moveDistance = sqrt(pow(dx, 2) + pow(dy, 2));
    if (moveDistance > ConvertVPToPX(TOUCH_MAX_THRESHOLD)) {
#ifdef OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
        MMI_HILOGD("Finger movement distance greater than 20VP, defaultDistance:%{public}d, moveDistance:%{public}f",
            ConvertVPToPX(TOUCH_MAX_THRESHOLD), moveDistance);
        StopTwoFingerGesture();
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
    }
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
void TwoFingerGestureHandler::HandleFingerGestureUpEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    if (!context_.twoFingerGesture_.active) {
        MMI_HILOGD("Two finger gesture is not active");
        return;
    }
    StopTwoFingerGesture();
}

void TwoFingerGestureHandler::StartTwoFingerGesture()
{
    CALL_DEBUG_ENTER;
    context_.twoFingerGesture_.startTime = 0;
    context_.twoFingerGesture_.longPressFlag = false;
    context_.twoFingerGesture_.windowId = -1;
    context_.twoFingerGesture_.windowPid = -1;
    context_.twoFingerGesture_.timerId = TimerMgr->AddTimer(context_.twoFingerGesture_.abilityStartDelay,
        1, [this]() {
        context_.twoFingerGesture_.timerId = -1;
        if (!CheckTwoFingerGestureAction()) {
            return;
        }
        context_.twoFingerGesture_.ability.params["displayX1"] =
            std::to_string(context_.twoFingerGesture_.touches[0].x);
        context_.twoFingerGesture_.ability.params["displayY1"] =
            std::to_string(context_.twoFingerGesture_.touches[0].y);
        context_.twoFingerGesture_.ability.params["displayX2"] =
            std::to_string(context_.twoFingerGesture_.touches[1].x);
        context_.twoFingerGesture_.ability.params["displayY2"] =
            std::to_string(context_.twoFingerGesture_.touches[1].y);
        MMI_HILOGI("Dual-finger long press capability information saving");
        context_.twoFingerGesture_.longPressFlag = true;
        context_.twoFingerGesture_.windowId = context_.twoFingerGesture_.touchEvent->GetTargetWindowId();
        context_.twoFingerGesture_.windowPid = WIN_MGR->GetWindowPid(context_.twoFingerGesture_.windowId);
        auto now = std::chrono::high_resolution_clock::now();
        auto duration = now.time_since_epoch();
        context_.twoFingerGesture_.startTime = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
        DfxHisysevent::ReportPointerEventExitTimes(PointerEventStatistics::AIBASE_GESTURE);
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
    }, "TwoFingerGestureHandler-StartTwoFingerGesture");
}

void TwoFingerGestureHandler::StopTwoFingerGesture()
{
    CALL_DEBUG_ENTER;
    if (context_.twoFingerGesture_.timerId != -1) {
        TimerMgr->RemoveTimer(context_.twoFingerGesture_.timerId);
        context_.twoFingerGesture_.timerId = -1;
    }
}

bool TwoFingerGestureHandler::CheckTwoFingerGestureAction() const
{
    if (!context_.twoFingerGesture_.active) {
        MMI_HILOGI("Two fingers active:%{public}d is fasle", context_.twoFingerGesture_.active);
        return false;
    }

    auto firstFinger = context_.twoFingerGesture_.touches[0];
    auto secondFinger = context_.twoFingerGesture_.touches[1];

    auto pressTimeInterval = fabs(firstFinger.downTime - secondFinger.downTime);
    if (pressTimeInterval > TWO_FINGERS_TIME_LIMIT) {
        MMI_HILOGI("Two fingers time too long firstdownTime:%{public}" PRId64 ",seconddownTime:%{public}" PRId64,
            firstFinger.downTime, secondFinger.downTime);
        return false;
    }

#ifdef OHOS_BUILD_ENABLE_TOUCH
    auto devX = firstFinger.x - secondFinger.x;
    auto devY = firstFinger.y - secondFinger.y;
    auto distance = sqrt(pow(devX, 2) + pow(devY, 2));
    if (distance < ConvertVPToPX(TWO_FINGERS_DISTANCE_LIMIT)) {
        MMI_HILOGI("Two fingers distance:%{public}f too small", distance);
        return false;
    }

    auto displayInfo = WIN_MGR->GetDefaultDisplayInfo();
    CHKPR(displayInfo, false);
    auto leftLimit = ConvertVPToPX(TOUCH_LIFT_LIMIT);
    auto rightLimit = displayInfo->width - ConvertVPToPX(TOUCH_RIGHT_LIMIT);
    auto topLimit = ConvertVPToPX(TOUCH_TOP_LIMIT);
    auto bottomLimit = displayInfo->height - ConvertVPToPX(TOUCH_BOTTOM_LIMIT);
    if (firstFinger.x <= leftLimit || firstFinger.x >= rightLimit ||
        firstFinger.y <= topLimit || firstFinger.y >= bottomLimit ||
        secondFinger.x <= leftLimit || secondFinger.x >= rightLimit ||
        secondFinger.y <= topLimit || secondFinger.y >= bottomLimit) {
        MMI_HILOGI("Any finger out of region");
        return false;
    }
#endif // OHOS_BUILD_ENABLE_TOUCH

    return true;
}
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER

int32_t TwoFingerGestureHandler::CheckTwoFingerGesture(int32_t pid)
{
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    int64_t milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    int64_t timeOut = milliseconds - context_.twoFingerGesture_.startTime;
    if (context_.twoFingerGesture_.touchEvent == nullptr) {
        MMI_HILOGE("context_.twoFingerGesture_.touchEvent == nullptr");
        return RET_ERR;
    }
    if (timeOut > SCREEN_TIME_OUT) {
        return RET_ERR;
    }

    if ((context_.twoFingerGesture_.windowId < 0) ||
        (context_.twoFingerGesture_.touchEvent->GetTargetWindowId() != context_.twoFingerGesture_.windowId)) {
        MMI_HILOGE("Window changefocusWindowId:%{public}d, twoFingerGesture_.focusWindowId:%{public}d",
            context_.twoFingerGesture_.touchEvent->GetTargetWindowId(),
            context_.twoFingerGesture_.windowId);
        return RET_ERR;
    }

    if (context_.twoFingerGesture_.windowPid != pid) {
        MMI_HILOGE("context_.twoFingerGesture_.windowPid:%{public}d, pid:%{public}d",
            context_.twoFingerGesture_.windowPid, pid);
        return RET_ERR;
    }

    if (!context_.twoFingerGesture_.longPressFlag) {
        MMI_HILOGE("The long press state is not set");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t TwoFingerGestureHandler::LaunchAiScreenAbility(int32_t pid)
{
    if (CheckTwoFingerGesture(pid) != RET_OK) {
        context_.twoFingerGesture_.startTime = 0;
        context_.twoFingerGesture_.longPressFlag = false;
        context_.twoFingerGesture_.windowId = -1;
        context_.twoFingerGesture_.windowPid = -1;
        return RET_ERR;
    }

    MMI_HILOGI("Start launch ai screen ability immediately");
    LaunchTwoFingerAbility(context_.twoFingerGesture_);

    context_.twoFingerGesture_.startTime = 0;
    context_.twoFingerGesture_.longPressFlag = false;
    context_.twoFingerGesture_.windowId = -1;
    context_.twoFingerGesture_.windowPid = -1;
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_TOUCH
int32_t TwoFingerGestureHandler::ConvertVPToPX(int32_t vp) const
{
    if (vp <= 0) {
        return 0;
    }
    auto displayInfo = WIN_MGR->GetDefaultDisplayInfo();
    CHKPR(displayInfo, 0);
    int32_t dpi = displayInfo->dpi;
    if (dpi <= 0) {
        return 0;
    }
    const int32_t base = 160;
    return vp * (dpi / base);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

void TwoFingerGestureHandler::LaunchTwoFingerAbility(const TwoFingerGesture &twoFinger)
{
    BytraceAdapter::StartLaunchAbility(KeyCommandType::TYPE_MULTI_FINGERS, twoFinger.ability.bundleName);
    LAUNCHER_ABILITY->LaunchAbility(twoFinger.ability, twoFinger.abilityStartDelay);
    DfxHisysevent::ReportKeyEvent(twoFinger.ability.bundleName);
    BytraceAdapter::StopLaunchAbility();
}
} // namespace MMI
} // namespace OHOS
