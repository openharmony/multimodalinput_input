/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "key_command_handler.h"

#include "ability_manager_client.h"
#include "device_event_monitor.h"
#include "event_log_helper.h"
#include "gesturesense_wrapper.h"
#include "input_screen_capture_agent.h"
#ifdef SHORTCUT_KEY_MANAGER_ENABLED
#include "key_shortcut_manager.h"
#endif // SHORTCUT_KEY_MANAGER_ENABLED
#include "key_command_handler_util.h"
#include "long_press_subscriber_handler.h"
#include "pull_throw_subscriber_handler.h"
#ifndef OHOS_BUILD_ENABLE_WATCH
#include "pointer_drawing_manager.h"
#endif // OHOS_BUILD_ENABLE_WATCH
#include "sensor_agent.h"
#include "sensor_agent_type.h"
#include "stylus_key_handler.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyCommandHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr float MOVE_TOLERANCE { 3.0f };
constexpr float MIN_GESTURE_STROKE_LENGTH { 200.0f };
constexpr float MIN_LETTER_GESTURE_SQUARENESS { 0.15f };
constexpr float MIN_START_GESTURE { 60.0f };
constexpr int32_t POINTER_NUMBER { 2 };
constexpr int32_t EVEN_NUMBER { 2 };
constexpr int64_t NO_DELAY { 0 };
constexpr int64_t FREQUENCY { 1000 };
constexpr int64_t TAP_DOWN_INTERVAL_MILLIS { 550000 };
constexpr int64_t SOS_INTERVAL_TIMES { 300000 };
constexpr int64_t SOS_DELAY_TIMES { 1000000 };
constexpr int64_t SOS_COUNT_DOWN_TIMES { 4000000 };
constexpr int32_t MAX_TAP_COUNT { 2 };
constexpr int32_t ANCO_KNUCKLE_POINTER_ID { 15000 };
constexpr int64_t SCREEN_TIME_OUT { 100 };
const char* AIBASE_BUNDLE_NAME { "com.hmos.aibase" };
const char* WAKEUP_ABILITY_NAME { "WakeUpExtAbility" };
const char* SCREENSHOT_BUNDLE_NAME { "com.hmos.screenshot" };
const char* SCREENSHOT_ABILITY_NAME { "com.hmos.screenshot.ServiceExtAbility" };
const char* SCREENRECORDER_BUNDLE_NAME { "com.hmos.screenrecorder" };
const char* SOS_BUNDLE_NAME { "com.hmos.emergencycommunication" };
const char* WALLET_BUNDLE_NAME { "com.hmos.wallet" };
constexpr int32_t DEFAULT_VALUE { -1 };
constexpr int64_t POWER_ACTION_INTERVAL { 600 };
constexpr int64_t SOS_WAIT_TIME { 3000 };
const char* PC_PRO_SCREENSHOT_BUNDLE_NAME { "com.hmos.screenshot" };
const char* PC_PRO_SCREENSHOT_ABILITY_NAME { "com.hmos.screenshot.ServiceExtAbility" };
const char* PC_PRO_SCREENRECORDER_BUNDLE_NAME { "com.hmos.screenrecorder" };
const char* PC_PRO_SCREENRECORDER_ABILITY_NAME { "com.hmos.screenrecorder.ServiceExtAbility" };
const char* KEY_ENABLE { "enable" };
const char* KEY_STATUS { "status" };
constexpr size_t DEFAULT_BUFFER_LENGTH { 512 };
const std::string SECURE_SETTING_URI_PROXY {
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_%d?Proxy=true" };
const char *TV_MENU_BUNDLE_NAME = "com.ohos.sceneboard";
const char *TV_MENU_ABILITY_NAME = "com.ohos.sceneboard.MultimodalInputService";
constexpr int32_t TIME_CONVERSION_UNIT { 1000 };
constexpr int32_t SENSOR_SAMPLING_INTERVAL = 100000000;
constexpr int32_t SENSOR_REPORT_INTERVAL = 100000000;
struct SensorUser g_user = {.name = {0}, .callback = nullptr, .userData = nullptr};
std::atomic<int32_t> g_distance { 0 };
} // namespace

static void SensorDataCallbackImpl(SensorEvent *event)
{
    if (event == nullptr) {
        MMI_HILOGE("Event is nullptr");
        return;
    }
    if (event->sensorTypeId != SENSOR_TYPE_ID_PROXIMITY) {
        MMI_HILOGE("Event sensorTypeId is not SENSOR_TYPE_ID_PROXIMITY");
        return;
    }
    ProximityData* proximityData = reinterpret_cast<ProximityData*>(event->data);
    int32_t distance = static_cast<int32_t>(proximityData->distance);
    MMI_HILOGI("Proximity distance %{public}d", distance);
    g_distance = distance;
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void KeyCommandHandler::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    if (TouchPadKnuckleDoubleClickHandle(keyEvent)) {
        return;
    }
    if (MenuClickHandle(keyEvent)) {
        MMI_HILOGD("MenuClickHandle return true, keyCode:%{public}d", keyEvent->GetKeyCode());
        return;
    }
    if (OnHandleEvent(keyEvent)) {
        if (DISPLAY_MONITOR->GetScreenStatus() == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
            auto monitorHandler = InputHandler->GetMonitorHandler();
            CHKPV(monitorHandler);
            keyEvent->SetFourceMonitorFlag(true);
#ifndef OHOS_BUILD_EMULATOR
            monitorHandler->OnHandleEvent(keyEvent);
#endif // OHOS_BUILD_EMULATOR
            keyEvent->SetFourceMonitorFlag(false);
        }
        MMI_HILOGD("The keyEvent start launch an ability, keyCode:%{private}d", keyEvent->GetKeyCode());
        BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::KEY_LAUNCH_EVENT);
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandleKeyEvent(keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void KeyCommandHandler::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    if (OnHandleEvent(pointerEvent)) {
        if (EventLogHelper::IsBetaVersion() && !pointerEvent->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
            MMI_HILOGD("The pointerEvent start launch an ability, pointAction:%{public}s",
                pointerEvent->DumpPointerAction());
        } else {
            MMI_HILOGD("The pointerEvent start launch an ability, pointAction:%s", pointerEvent->DumpPointerAction());
        }
    }
    CHKPV(nextHandler_);
    nextHandler_->HandlePointerEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void KeyCommandHandler::HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    CHKPV(nextHandler_);
    OnHandleTouchEvent(pointerEvent);
    int32_t id = pointerEvent->GetPointerId();
    PointerEvent::PointerItem item;
    pointerEvent->GetPointerItem(id, item);
    int32_t toolType = item.GetToolType();
    if (toolType == PointerEvent::TOOL_TYPE_KNUCKLE) {
        pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);
    }
    nextHandler_->HandleTouchEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

bool KeyCommandHandler::GetKnuckleSwitchValue()
{
    return gameForbidFingerKnuckle_;
}

bool KeyCommandHandler::SkipKnuckleDetect()
{
    return ((!screenshotSwitch_.statusConfigValue) && (!recordSwitch_.statusConfigValue)) ||
        gameForbidFingerKnuckle_;
}

#ifdef OHOS_BUILD_ENABLE_TOUCH
void KeyCommandHandler::OnHandleTouchEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    STYLUS_HANDLER->SetLastEventState(false);
    if (!isParseConfig_) {
        if (!ParseConfig()) {
            MMI_HILOGE("Parse configFile failed");
            return;
        }
        isParseConfig_ = true;
    }
    twoFingerGesture_.touchEvent = touchEvent;
    InitializeLongPressConfigurations();
    switch (touchEvent->GetPointerAction()) {
        case PointerEvent::POINTER_ACTION_PULL_MOVE:
            PULL_THROW_EVENT_HANDLER->HandleFingerGesturePullMoveEvent(touchEvent);
            break;
        case PointerEvent::POINTER_ACTION_CANCEL:
        case PointerEvent::POINTER_ACTION_UP: {
            HandlePointerActionUpEvent(touchEvent);
            break;
        }
        case PointerEvent::POINTER_ACTION_MOVE: {
            HandlePointerActionMoveEvent(touchEvent);
            LONG_PRESS_EVENT_HANDLER->HandleFingerGestureMoveEvent(touchEvent);
            PULL_THROW_EVENT_HANDLER->HandleFingerGestureMoveEvent(touchEvent);
            break;
        }
        case PointerEvent::POINTER_ACTION_DOWN: {
            HandlePointerActionDownEvent(touchEvent);
            break;
        }
        default:
            MMI_HILOGD("Unknown pointer action:%{public}d", touchEvent->GetPointerAction());
            break;
    }
#ifdef OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
    HandleKnuckleGestureEvent(touchEvent);
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
}

void KeyCommandHandler::InitializeLongPressConfigurations()
{
    if (!isParseLongPressConfig_) {
        if (!ParseLongPressConfig()) {
            MMI_HILOGE("Parse long press configFile failed");
        }
        isParseLongPressConfig_ = true;
    }
    if (!isDistanceConfig_) {
        distanceDefaultConfig_ = DOUBLE_CLICK_DISTANCE_DEFAULT_CONFIG * VPR_CONFIG;
        distanceLongConfig_ = DOUBLE_CLICK_DISTANCE_LONG_CONFIG * VPR_CONFIG;
        SetKnuckleDoubleTapDistance(distanceDefaultConfig_);
        isDistanceConfig_ = true;
    }
}

void KeyCommandHandler::HandlePointerActionDownEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    int32_t id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    int32_t toolType = item.GetToolType();
    MMI_HILOGD("Pointer tool type:%{public}d", toolType);
    singleKnuckleGesture_.state = false;
    doubleKnuckleGesture_.state = false;
    switch (toolType) {
#ifdef OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
        case PointerEvent::TOOL_TYPE_FINGER: {
            HandleFingerGestureDownEvent(touchEvent);
            if (CheckBundleName(touchEvent)) {
                LONG_PRESS_EVENT_HANDLER->HandleFingerGestureDownEvent(touchEvent);
            }
            PULL_THROW_EVENT_HANDLER->HandleFingerGestureDownEvent(touchEvent);
            break;
        }
        case PointerEvent::TOOL_TYPE_KNUCKLE: {
            DfxHisysevent::ReportKnuckleClickEvent();
            HandleKnuckleGestureDownEvent(touchEvent);
            break;
        }
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
        default: {
            MMI_HILOGD("Current touch event tool type:%{public}d", toolType);
            break;
        }
    }
    CheckAndUpdateTappingCountAtDown(touchEvent);
}

void KeyCommandHandler::HandlePointerActionMoveEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    int32_t id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    if (!twoFingerGesture_.active) {
        return;
    }
    if (twoFingerGesture_.timerId == -1) {
        MMI_HILOGD("Two finger gesture timer id is -1");
        return;
    }
    auto pos = std::find_if(std::begin(twoFingerGesture_.touches), std::end(twoFingerGesture_.touches),
        [id](const auto& item) { return item.id == id; });
    if (pos == std::end(twoFingerGesture_.touches)) {
        return;
    }
    auto dx = std::abs(pos->x - item.GetDisplayX());
    auto dy = std::abs(pos->y - item.GetDisplayY());
    auto moveDistance = sqrt(pow(dx, 2) + pow(dy, 2));
    if (moveDistance > ConvertVPToPX(TOUCH_MAX_THRESHOLD)) {
#ifdef OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
        MMI_HILOGI("Finger movement distance greater than 20VP, defaultDistance:%{public}d, moveDistance:%{public}f",
            ConvertVPToPX(TOUCH_MAX_THRESHOLD), moveDistance);
        StopTwoFingerGesture();
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
    }
}

void KeyCommandHandler::HandlePointerActionUpEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    int32_t id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    int32_t toolType = item.GetToolType();
    switch (toolType) {
#ifdef OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
        case PointerEvent::TOOL_TYPE_FINGER: {
            HandleFingerGestureUpEvent(touchEvent);
            LONG_PRESS_EVENT_HANDLER->HandleFingerGestureUpEvent(touchEvent);
            PULL_THROW_EVENT_HANDLER->HandleFingerGestureUpEvent(touchEvent);
            break;
        }
        case PointerEvent::TOOL_TYPE_KNUCKLE: {
            HandleKnuckleGestureUpEvent(touchEvent);
            break;
        }
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
        default: {
            MMI_HILOGW("Current touch event tool type:%{public}d", toolType);
            break;
        }
    }
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
void KeyCommandHandler::HandleFingerGestureDownEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    if (!twoFingerGesture_.active) {
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
        twoFingerGesture_.touches[num - 1].id = id;
        twoFingerGesture_.touches[num - 1].x = item.GetDisplayX();
        twoFingerGesture_.touches[num - 1].y = item.GetDisplayY();
        twoFingerGesture_.touches[num - 1].downTime = item.GetDownTime();
    }
}

void KeyCommandHandler::HandleFingerGestureUpEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    if (!twoFingerGesture_.active) {
        MMI_HILOGD("Two finger gesture is not active");
        return;
    }
    StopTwoFingerGesture();
}

void KeyCommandHandler::HandleKnuckleGestureDownEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    int32_t id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    int64_t currentDownTime = item.GetDownTime();
    if (!lastPointerDownTime_.empty()) {
        int64_t firstDownTime = lastPointerDownTime_.begin()->second;
        int64_t lastPointerDownTime = touchEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE) ?
            lastPointerDownTime_[SIMULATE_POINTER_ID] : firstDownTime;
        int64_t diffTime = currentDownTime - lastPointerDownTime;
        lastPointerDownTime_[id] = currentDownTime;
        MMI_HILOGW("Size:%{public}zu, firstDownTime:%{public}" PRId64 ", "
            "currentDownTime:%{public}" PRId64 ", diffTime:%{public}" PRId64,
            lastPointerDownTime_.size(), firstDownTime, currentDownTime, diffTime);
        if (diffTime > TWO_FINGERS_TIME_LIMIT) {
            MMI_HILOGE("Invalid double knuckle event, pointerId:%{public}d", id);
            return;
        }
    }

    lastPointerDownTime_[id] = currentDownTime;
    auto items = touchEvent->GetAllPointerItems();
    MMI_HILOGI("The itemsSize:%{public}zu", items.size());
    for (const auto &item : items) {
        if (item.GetToolType() != PointerEvent::TOOL_TYPE_KNUCKLE) {
            MMI_HILOGW("Touch event tool type:%{public}d not knuckle", item.GetToolType());
            return;
        }
    }
    if (gameForbidFingerKnuckle_) {
        MMI_HILOGI("Knuckle switch closed");
        return;
    }
    if (CheckInputMethodArea(touchEvent)) {
        MMI_HILOGW("Event skipping inputmethod area");
        return;
    }
    size_t pointercnt = touchEvent->GetPointerIds().size();
    if (pointercnt == SINGLE_KNUCKLE_SIZE) {
        SingleKnuckleGestureProcesser(touchEvent);
        isDoubleClick_ = false;
        knuckleCount_++;
    } else if (pointercnt == DOUBLE_KNUCKLE_SIZE) {
        DoubleKnuckleGestureProcesser(touchEvent);
        isDoubleClick_ = true;
    } else {
        MMI_HILOGW("Other kunckle pointercnt not process, pointercnt:%{public}zu", pointercnt);
    }
}

void KeyCommandHandler::HandleKnuckleGestureUpEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    int32_t id = touchEvent->GetPointerId();
    auto it = lastPointerDownTime_.find(id);
    if (it != lastPointerDownTime_.end()) {
        MMI_HILOGW("lastPointerDownTime_ has been erased, pointerId:%{public}d", id);
        lastPointerDownTime_.erase(it);
    }

    previousUpTime_ = touchEvent->GetActionTime();
    size_t pointercnt = touchEvent->GetPointerIds().size();
    if ((pointercnt == SINGLE_KNUCKLE_SIZE) && (!isDoubleClick_)) {
        singleKnuckleGesture_.lastPointerUpTime = touchEvent->GetActionTime();
    } else if (pointercnt == DOUBLE_KNUCKLE_SIZE) {
        doubleKnuckleGesture_.lastPointerUpTime = touchEvent->GetActionTime();
    } else {
        MMI_HILOGW("Other kunckle pointercnt not process, pointercnt:%{public}zu", pointercnt);
    }
}

void KeyCommandHandler::SingleKnuckleGestureProcesser(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    singleKnuckleGesture_.state = false;
    KnuckleGestureProcessor(touchEvent, singleKnuckleGesture_, KnuckleType::KNUCKLE_TYPE_SINGLE);
}

void KeyCommandHandler::DoubleKnuckleGestureProcesser(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    doubleKnuckleGesture_.state = false;
    KnuckleGestureProcessor(touchEvent, doubleKnuckleGesture_, KnuckleType::KNUCKLE_TYPE_DOUBLE);
}

void KeyCommandHandler::KnuckleGestureProcessor(std::shared_ptr<PointerEvent> touchEvent,
    KnuckleGesture &knuckleGesture, KnuckleType type)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    if (knuckleGesture.lastPointerDownEvent == nullptr) {
        MMI_HILOGI("Knuckle gesture first down Event");
        knuckleGesture.lastPointerDownEvent = touchEvent;
        UpdateKnuckleGestureInfo(touchEvent, knuckleGesture);
        return;
    }
    int64_t intervalTime = touchEvent->GetActionTime() - knuckleGesture.lastPointerUpTime;
    bool isTimeIntervalReady = intervalTime > 0 && intervalTime <= DOUBLE_CLICK_INTERVAL_TIME_SLOW;
    float downToPrevDownDistance = AbsDiff(knuckleGesture, touchEvent);
    bool isDistanceReady = downToPrevDownDistance < downToPrevDownDistanceConfig_;
    knuckleGesture.downToPrevUpTime = intervalTime;
    knuckleGesture.doubleClickDistance = downToPrevDownDistance;
    UpdateKnuckleGestureInfo(touchEvent, knuckleGesture);
    if (isTimeIntervalReady && (type == KnuckleType::KNUCKLE_TYPE_DOUBLE || isDistanceReady)) {
        MMI_HILOGI("Knuckle gesture start launch ability");
        knuckleCount_ = 0;
        if ((type == KnuckleType::KNUCKLE_TYPE_SINGLE && screenshotSwitch_.statusConfigValue) ||
            (type == KnuckleType::KNUCKLE_TYPE_DOUBLE && recordSwitch_.statusConfigValue)) {
            DfxHisysevent::ReportSingleKnuckleDoubleClickEvent(intervalTime, downToPrevDownDistance);
            BytraceAdapter::StartLaunchAbility(KeyCommandType::TYPE_FINGERSCENE, knuckleGesture.ability.bundleName);
            LaunchAbility(knuckleGesture.ability, NO_DELAY);
            BytraceAdapter::StopLaunchAbility();
            if (knuckleGesture.ability.bundleName == SCREENRECORDER_BUNDLE_NAME) {
                DfxHisysevent::ReportScreenRecorderGesture(intervalTime);
            }
            ReportKnuckleScreenCapture(touchEvent);
        }
        knuckleGesture.state = true;
    } else {
        if (knuckleCount_ > KNUCKLE_KNOCKS) {
            knuckleCount_ = 0;
            MMI_HILOGW("Time ready:%{public}d, distance ready:%{public}d", isTimeIntervalReady, isDistanceReady);
            if (!isTimeIntervalReady) {
                DfxHisysevent::ReportFailIfInvalidTime(touchEvent, intervalTime);
            }
            if (!isDistanceReady) {
                DfxHisysevent::ReportFailIfInvalidDistance(touchEvent, downToPrevDownDistance);
            }
        }
    }
    AdjustDistanceConfigIfNeed(downToPrevDownDistance);
}

void KeyCommandHandler::SendNotSupportMsg(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    auto tempEvent = std::make_shared<PointerEvent>(*touchEvent);
    std::list<PointerEvent::PointerItem> pointerItems = tempEvent->GetAllPointerItems();
    tempEvent->RemoveAllPointerItems();
    for (auto &pointerItem : pointerItems) {
        pointerItem.SetPointerId(ANCO_KNUCKLE_POINTER_ID);
        pointerItem.SetOriginPointerId(ANCO_KNUCKLE_POINTER_ID);
        tempEvent->AddPointerItem(pointerItem);
    }
    tempEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    tempEvent->SetPointerId(ANCO_KNUCKLE_POINTER_ID);
    tempEvent->SetAgentWindowId(tempEvent->GetTargetWindowId());
    MMI_HILOGW("Event is %{public}s", tempEvent->ToString().c_str());
    auto fd = WIN_MGR->GetClientFd(tempEvent);
    auto udsServer = InputHandler->GetUDSServer();
    CHKPV(udsServer);
    NetPacket pkt(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(tempEvent, pkt);
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    InputEventDataTransformation::MarshallingEnhanceData(tempEvent, pkt);
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    udsServer->SendMsg(fd, pkt);

    tempEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    std::list<PointerEvent::PointerItem> tmpPointerItems = tempEvent->GetAllPointerItems();
    tempEvent->RemoveAllPointerItems();
    for (auto &pointerItem : tmpPointerItems) {
        pointerItem.SetPressed(false);
        tempEvent->AddPointerItem(pointerItem);
    }
    NetPacket pktUp(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(tempEvent, pktUp);
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    InputEventDataTransformation::MarshallingEnhanceData(tempEvent, pktUp);
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    udsServer->SendMsg(fd, pktUp);
}

void KeyCommandHandler::UpdateKnuckleGestureInfo(const std::shared_ptr<PointerEvent> touchEvent,
    KnuckleGesture &knuckleGesture)
{
    int32_t id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    knuckleGesture.lastDownPointer.x = item.GetDisplayX();
    knuckleGesture.lastDownPointer.y = item.GetDisplayY();
    knuckleGesture.lastDownPointer.id = touchEvent->GetId();
}

void KeyCommandHandler::AdjustDistanceConfigIfNeed(float distance)
{
    CALL_DEBUG_ENTER;
    float newDistanceConfig;
    MMI_HILOGI("Down to prev down distance:%{public}f, config distance:%{public}f",
        distance, downToPrevDownDistanceConfig_);
    if (IsEqual(downToPrevDownDistanceConfig_, distanceDefaultConfig_)) {
        if (distance < distanceDefaultConfig_ || distance > distanceLongConfig_) {
            return;
        }
        newDistanceConfig = distanceLongConfig_;
    } else if (IsEqual(downToPrevDownDistanceConfig_, distanceLongConfig_)) {
        if (distance > distanceDefaultConfig_) {
            return;
        }
        newDistanceConfig = distanceDefaultConfig_;
    } else {
        return;
    }
    checkAdjustDistanceCount_++;
    if (checkAdjustDistanceCount_ < MAX_TIME_FOR_ADJUST_CONFIG) {
        return;
    }
    MMI_HILOGI("Adjust new double click distance:%{public}f", newDistanceConfig);
    downToPrevDownDistanceConfig_ = newDistanceConfig;
    checkAdjustDistanceCount_ = 0;
}

void KeyCommandHandler::ReportKnuckleScreenCapture(const std::shared_ptr<PointerEvent> touchEvent)
{
    CHKPV(touchEvent);
    size_t pointercnt = touchEvent->GetPointerIds().size();
    if (pointercnt == SINGLE_KNUCKLE_SIZE) {
        DfxHisysevent::ReportScreenCaptureGesture();
        return;
    }
    MMI_HILOGW("Current touch event pointercnt:%{public}zu", pointercnt);
}

void KeyCommandHandler::StartTwoFingerGesture()
{
    CALL_DEBUG_ENTER;
    twoFingerGesture_.startTime = 0;
    twoFingerGesture_.longPressFlag = false;
    twoFingerGesture_.windowId = -1;
    twoFingerGesture_.windowPid = -1;
    twoFingerGesture_.timerId = TimerMgr->AddTimer(twoFingerGesture_.abilityStartDelay, 1, [this]() {
        twoFingerGesture_.timerId = -1;
        if (!CheckTwoFingerGestureAction()) {
            return;
        }
        twoFingerGesture_.ability.params["displayX1"] = std::to_string(twoFingerGesture_.touches[0].x);
        twoFingerGesture_.ability.params["displayY1"] = std::to_string(twoFingerGesture_.touches[0].y);
        twoFingerGesture_.ability.params["displayX2"] = std::to_string(twoFingerGesture_.touches[1].x);
        twoFingerGesture_.ability.params["displayY2"] = std::to_string(twoFingerGesture_.touches[1].y);
        MMI_HILOGI("Dual-finger long press capability information saving");
        twoFingerGesture_.longPressFlag = true;
        twoFingerGesture_.windowId = twoFingerGesture_.touchEvent->GetTargetWindowId();
        twoFingerGesture_.windowPid = WIN_MGR->GetWindowPid(twoFingerGesture_.windowId);
        auto now = std::chrono::high_resolution_clock::now();
        auto duration = now.time_since_epoch();
        twoFingerGesture_.startTime = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    });
}

void KeyCommandHandler::StopTwoFingerGesture()
{
    CALL_DEBUG_ENTER;
    if (twoFingerGesture_.timerId != -1) {
        TimerMgr->RemoveTimer(twoFingerGesture_.timerId);
        twoFingerGesture_.timerId = -1;
    }
}

bool KeyCommandHandler::CheckTwoFingerGestureAction() const
{
    if (!twoFingerGesture_.active) {
        return false;
    }

    auto firstFinger = twoFingerGesture_.touches[0];
    auto secondFinger = twoFingerGesture_.touches[1];

    auto pressTimeInterval = fabs(firstFinger.downTime - secondFinger.downTime);
    if (pressTimeInterval > TWO_FINGERS_TIME_LIMIT) {
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

#ifdef OHOS_BUILD_ENABLE_TOUCH
int32_t KeyCommandHandler::ConvertVPToPX(int32_t vp) const
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

#ifdef OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
void KeyCommandHandler::HandleKnuckleGestureEvent(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    if (!CheckKnuckleCondition(touchEvent)) {
        return;
    }
    CHKPV(touchEvent);
    int32_t touchAction = touchEvent->GetPointerAction();
    if (IsValidAction(touchAction)) {
        switch (touchAction) {
            case PointerEvent::POINTER_ACTION_CANCEL:
            case PointerEvent::POINTER_ACTION_UP: {
                HandleKnuckleGestureTouchUp(touchEvent);
                break;
            }
            case PointerEvent::POINTER_ACTION_MOVE: {
                HandleKnuckleGestureTouchMove(touchEvent);
                break;
            }
            case PointerEvent::POINTER_ACTION_DOWN: {
                HandleKnuckleGestureTouchDown(touchEvent);
                break;
            }
            default:
                MMI_HILOGD("Unknown pointer action:%{public}d", touchAction);
                break;
        }
    }
}

bool KeyCommandHandler::CheckKnuckleCondition(std::shared_ptr<PointerEvent> touchEvent)
{
    CHKPF(touchEvent);
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(touchEvent->GetPointerId(), item);
    if (item.GetToolType() != PointerEvent::TOOL_TYPE_KNUCKLE ||
        touchEvent->GetPointerIds().size() != SINGLE_KNUCKLE_SIZE || singleKnuckleGesture_.state) {
        MMI_HILOGD("Touch tool type is:%{public}d", item.GetToolType());
        ResetKnuckleGesture();
        return false;
    }
    auto physicDisplayInfo = WIN_MGR->GetPhysicalDisplay(touchEvent->GetTargetDisplayId());
    if (physicDisplayInfo != nullptr && physicDisplayInfo->direction != lastDirection_) {
        lastDirection_ = physicDisplayInfo->direction;
        if (touchEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE && !gesturePoints_.empty()) {
            MMI_HILOGW("The screen has been rotated while knuckle is moving");
            ResetKnuckleGesture();
            return false;
        }
    }
    if (gameForbidFingerKnuckle_) {
        if (touchEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN ||
            touchEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP) {
            MMI_HILOGI("Knuckle switch closed");
        }
        return false;
    }
    if (!screenshotSwitch_.statusConfigValue) {
        if (touchEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN ||
            touchEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP) {
            MMI_HILOGI("Screenshot knuckle switch closed");
        }
        return false;
    }
    if (CheckInputMethodArea(touchEvent)) {
        if (touchEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN ||
            touchEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP) {
            MMI_HILOGI("In input method area, skip");
        }
        return false;
    }
    return true;
}

bool KeyCommandHandler::IsValidAction(int32_t action)
{
    CALL_DEBUG_ENTER;
    if (action == PointerEvent::POINTER_ACTION_DOWN ||
        ((action == PointerEvent::POINTER_ACTION_MOVE || action == PointerEvent::POINTER_ACTION_UP ||
        action == PointerEvent::POINTER_ACTION_CANCEL) && !gesturePoints_.empty())) {
        return true;
    }
    return false;
}

std::pair<int32_t, int32_t> KeyCommandHandler::CalcDrawCoordinate(const DisplayInfo& displayInfo,
    PointerEvent::PointerItem pointerItem)
{
    CALL_DEBUG_ENTER;
    double physicalX = pointerItem.GetRawDisplayX();
    double physicalY = pointerItem.GetRawDisplayY();
    if (!displayInfo.transform.empty()) {
        auto displayXY = WIN_MGR->TransformDisplayXY(displayInfo, physicalX, physicalY);
        physicalX = displayXY.first;
        physicalY = displayXY.second;
    }
    return {static_cast<int32_t>(physicalX), static_cast<int32_t>(physicalY)};
}

void KeyCommandHandler::HandleKnuckleGestureTouchDown(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    ResetKnuckleGesture();
    isStartBase_ = false;
    int32_t id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    sessionKey_ = "Base" + std::to_string(item.GetDownTime());
    auto displayInfo = WIN_MGR->GetPhysicalDisplay(touchEvent->GetTargetDisplayId());
    CHKPV(displayInfo);
    auto displayXY = CalcDrawCoordinate(*displayInfo, item);
    gestureLastX_ = displayXY.first;
    gestureLastY_ = displayXY.second;

    gesturePoints_.emplace_back(gestureLastX_);
    gesturePoints_.emplace_back(gestureLastY_);
    gestureTimeStamps_.emplace_back(touchEvent->GetActionTime());
}

void KeyCommandHandler::HandleKnuckleGestureTouchMove(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(touchEvent->GetPointerId(), item);
    auto displayInfo = WIN_MGR->GetPhysicalDisplay(touchEvent->GetTargetDisplayId());
    CHKPV(displayInfo);
    auto displayXY = CalcDrawCoordinate(*displayInfo, item);
    float eventX = displayXY.first;
    float eventY = displayXY.second;
    float dx = std::abs(eventX - gestureLastX_);
    float dy = std::abs(eventY - gestureLastY_);
    if (dx >= MOVE_TOLERANCE || dy >= MOVE_TOLERANCE) {
        gestureLastX_ = eventX;
        gestureLastY_ = eventY;
        gesturePoints_.emplace_back(gestureLastX_);
        gesturePoints_.emplace_back(gestureLastY_);
        gestureTimeStamps_.emplace_back(touchEvent->GetActionTime());
        if (!isStartBase_ && IsMatchedAbility(gesturePoints_, gestureLastX_, gestureLastY_)) {
            MMI_HILOGI("First time start aility, size:%{public}zu", gesturePoints_.size());
            ProcessKnuckleGestureTouchUp(NotifyType::REGIONGESTURE);
            isStartBase_ = true;
        }
        if (!isGesturing_) {
            gestureTrackLength_ += sqrt(dx * dx + dy * dy);
            if (gestureTrackLength_ > MIN_GESTURE_STROKE_LENGTH) {
                isGesturing_ = true;
            }
        }
        if (isGesturing_ && !isLetterGesturing_) {
            auto GetBoundingSquareness = GESTURESENSE_WRAPPER->getBoundingSquareness_;
            CHKPV(GetBoundingSquareness);
            auto boundingSquareness = GetBoundingSquareness(gesturePoints_);
            if (boundingSquareness > MIN_LETTER_GESTURE_SQUARENESS) {
                isLetterGesturing_ = true;
            }
        }
    }
}

void KeyCommandHandler::HandleKnuckleGestureTouchUp(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    auto touchUp = GESTURESENSE_WRAPPER->touchUp_;
    CHKPV(touchUp);
    MMI_HILOGI("Knuckle gesturePoints size:%{public}zu, isGesturing:%{public}d, isLetterGesturing:%{public}d",
        gesturePoints_.size(), isGesturing_, isLetterGesturing_);
    NotifyType notifyType = static_cast<NotifyType>(touchUp(gesturePoints_, gestureTimeStamps_,
        isGesturing_, isLetterGesturing_));
    switch (notifyType) {
        case NotifyType::REGIONGESTURE: {
            ProcessKnuckleGestureTouchUp(notifyType);
            drawOSuccTimestamp_ = touchEvent->GetActionTime();
            ReportRegionGesture();
            break;
        }
        case NotifyType::LETTERGESTURE: {
            ProcessKnuckleGestureTouchUp(notifyType);
            drawOFailTimestamp_ = touchEvent->GetActionTime();
            ReportLetterGesture();
            break;
        }
        default: {
            MMI_HILOGW("Not a region gesture or letter gesture, notifyType:%{public}d", notifyType);
            drawOFailTimestamp_ = touchEvent->GetActionTime();
            ReportIfNeed();
            break;
        }
    }
    ResetKnuckleGesture();
}

void KeyCommandHandler::ProcessKnuckleGestureTouchUp(NotifyType type)
{
    Ability ability;
    ability.abilityType = EXTENSION_ABILITY;
    if (type == NotifyType::REGIONGESTURE) {
        ability.abilityName = WAKEUP_ABILITY_NAME;
        ability.bundleName = AIBASE_BUNDLE_NAME;
        ability.params.emplace(std::make_pair("shot_type", "smart-shot"));
        MMI_HILOGI("The isStartBase_:%{public}d, sessionKey_:%{public}s", isStartBase_, sessionKey_.c_str());
        if (!isStartBase_) {
            ability.params.emplace(std::make_pair("fingerPath", ""));
            ability.params.emplace(std::make_pair("launch_type", "knuckle_gesture_pre"));
        } else {
            ability.params.emplace(std::make_pair("fingerPath", GesturePointsToStr()));
            ability.params.emplace(std::make_pair("launch_type", "knuckle_gesture"));
        }
        ability.params.emplace(std::make_pair("session_id", sessionKey_));
    } else if (type == NotifyType::LETTERGESTURE) {
        ability.abilityName = SCREENSHOT_ABILITY_NAME;
        ability.bundleName = SCREENSHOT_BUNDLE_NAME;
        ability.params.emplace(std::make_pair("shot_type", "scroll-shot"));
        ability.params.emplace(std::make_pair("trigger_type", "knuckle"));
    }
    LaunchAbility(ability, NO_DELAY);
}

void KeyCommandHandler::ResetKnuckleGesture()
{
    gestureLastX_ = 0.0f;
    gestureLastY_ = 0.0f;
    isGesturing_ = false;
    isLetterGesturing_ = false;
    gestureTrackLength_ = 0.0f;
    gesturePoints_.clear();
    gestureTimeStamps_.clear();
}

std::string KeyCommandHandler::GesturePointsToStr() const
{
    int32_t count = static_cast<int32_t>(gesturePoints_.size());
    if (count % EVEN_NUMBER != 0 || count == 0) {
        MMI_HILOGE("Invalid gesturePoints_ size");
        return {};
    }
    cJSON *jsonArray = cJSON_CreateArray();
    for (int32_t i = 0; i < count; i += EVEN_NUMBER) {
        cJSON *jsonData = cJSON_CreateObject();
        cJSON_AddItemToObject(jsonData, "x", cJSON_CreateNumber(gesturePoints_[i]));
        cJSON_AddItemToObject(jsonData, "y", cJSON_CreateNumber(gesturePoints_[i + 1]));
        cJSON_AddItemToArray(jsonArray, jsonData);
    }
    char *jsonString = cJSON_Print(jsonArray);
    std::string result = std::string(jsonString);
    cJSON_Delete(jsonArray);
    cJSON_free(jsonString);
    return result;
}

void KeyCommandHandler::ReportIfNeed()
{
    if (!isGesturing_) {
        return;
    }
    DfxHisysevent::ReportKnuckleGestureFaildTimes();
    DfxHisysevent::ReportKnuckleGestureTrackLength(gestureTrackLength_);
    DfxHisysevent::ReportKnuckleGestureTrackTime(gestureTimeStamps_);
    if (isLastGestureSucceed_) {
        DfxHisysevent::ReportKnuckleGestureFromSuccessToFailTime(drawOFailTimestamp_ - drawOSuccTimestamp_);
    }
    isLastGestureSucceed_ = false;
}

void KeyCommandHandler::ReportRegionGesture()
{
    DfxHisysevent::ReportSmartShotSuccTimes();
    ReportGestureInfo();
}

void KeyCommandHandler::ReportLetterGesture()
{
    DfxHisysevent::ReportKnuckleDrawSSuccessTimes();
    ReportGestureInfo();
}

void KeyCommandHandler::ReportGestureInfo()
{
    DfxHisysevent::ReportKnuckleGestureTrackLength(gestureTrackLength_);
    DfxHisysevent::ReportKnuckleGestureTrackTime(gestureTimeStamps_);
    if (!isLastGestureSucceed_) {
        DfxHisysevent::ReportKnuckleGestureFromFailToSuccessTime(drawOSuccTimestamp_ - drawOFailTimestamp_);
    }
    isLastGestureSucceed_ = true;
}

bool KeyCommandHandler::IsMatchedAbility(std::vector<float> gesturePoints,
    float gestureLastX, float gestureLastY)
{
    if (gesturePoints.size() < POINTER_NUMBER) {
        MMI_HILOGI("The gesturePoints_ is empty");
        return false;
    }
    float gestureFirstX = gesturePoints[0];
    float gestureFirstY = gesturePoints[1];
    float distance = std::min(std::abs(gestureLastX - gestureFirstX), std::abs(gestureLastY - gestureFirstY));
    return distance >= MIN_START_GESTURE;
}
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER

bool KeyCommandHandler::ParseConfig()
{
    const std::string defaultConfig { "/system/etc/multimodalinput/ability_launch_config.json" };
    const char configName[] { "/etc/multimodalinput/ability_launch_config.json" };
    char buf[MAX_PATH_LEN] {};

    char *filePath = ::GetOneCfgFile(configName, buf, sizeof(buf));
    if (filePath == nullptr || filePath[0] == '\0' || strlen(filePath) > MAX_PATH_LEN) {
        MMI_HILOGD("Can not get customization config file");
        return ParseJson(defaultConfig);
    }
    std::string customConfig = filePath;
    MMI_HILOGD("The configuration file path:%{private}s", customConfig.c_str());
    return ParseJson(customConfig) || ParseJson(defaultConfig);
}

bool KeyCommandHandler::ParseExcludeConfig()
{
    const std::string defaultConfig { "/system/etc/multimodalinput/exclude_keys_config.json" };
    const char configName[] { "/etc/multimodalinput/exclude_keys_config.json" };
    char buf[MAX_PATH_LEN] {};

    char *filePath = ::GetOneCfgFile(configName, buf, sizeof(buf));
    if (filePath == nullptr || filePath[0] == '\0' || strlen(filePath) > MAX_PATH_LEN) {
        MMI_HILOGD("Can not get customization exclude_keys_config.json file");
        return ParseExcludeJson(defaultConfig);
    }
    std::string customConfig = filePath;
    MMI_HILOGD("The exclude_keys_config.json file path:%s", customConfig.c_str());
    return ParseExcludeJson(customConfig) || ParseExcludeJson(defaultConfig);
}

void KeyCommandHandler::ParseRepeatKeyMaxCount()
{
    if (repeatKeys_.empty()) {
        maxCount_ = 0;
    }
    int32_t tempCount = 0;
    int32_t tempDelay = 0;
    for (RepeatKey& item : repeatKeys_) {
        if (item.times > tempCount) {
            tempCount = item.times;
        }
        if (item.delay > tempDelay) {
            tempDelay = item.delay;
        }
        if (item.ability.bundleName == WALLET_BUNDLE_NAME) {
            walletLaunchDelayTimes_ = item.delay;
        }
    }
    maxCount_ = tempCount;
    intervalTime_ = tempDelay;
}

bool KeyCommandHandler::CheckSpecialRepeatKey(RepeatKey& item, const std::shared_ptr<KeyEvent> keyEvent)
{
    if (item.keyCode != keyEvent->GetKeyCode()) {
        return false;
    }
    if (item.keyCode != KeyEvent::KEYCODE_VOLUME_DOWN) {
        return false;
    }
    std::string bundleName = item.ability.bundleName;
    std::string matchName = ".camera";
    if (bundleName.find(matchName) == std::string::npos) {
        return false;
    }
    std::string screenStatus = DISPLAY_MONITOR->GetScreenStatus();
    bool isScreenLocked = DISPLAY_MONITOR->GetScreenLocked();
    if (WIN_MGR->JudgeCaramaInFore() &&
        (screenStatus != EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF && isScreenLocked)) {
            return true;
    }
    auto callState = DEVICE_MONITOR->GetCallState();
    if (callState == StateType::CALL_STATUS_ACTIVE || callState == StateType::CALL_STATUS_HOLDING ||
        callState == StateType::CALL_STATUS_INCOMING || callState == StateType::CALL_STATUS_ANSWERED) {
        return true;
    }
    if ((screenStatus == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF || isScreenLocked) &&
        !IsMusicActivate() && (g_distance > 0)) {
        return true;
    }
    MMI_HILOGI("ScreenStatus:%{public}s, isScreenLocked:%{public}d", screenStatus.c_str(), isScreenLocked);
    if (screenStatus == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF || isScreenLocked) {
        return false;
    }
    return true;
}

bool KeyCommandHandler::ParseJson(const std::string &configFile)
{
    CALL_DEBUG_ENTER;
    std::string jsonStr = ReadJsonFile(configFile);
    if (jsonStr.empty()) {
        MMI_HILOGE("Read configFile failed");
        return false;
    }
    JsonParser parser;
    parser.json_ = cJSON_Parse(jsonStr.c_str());
    if (parser.json_ == nullptr) {
        MMI_HILOGE("cJSON_Parse failed");
        return false;
    }
    if (!cJSON_IsObject(parser.json_)) {
        MMI_HILOGE("Parser.json_ is not object");
        return false;
    }

    bool isParseShortKeys = ParseShortcutKeys(parser, shortcutKeys_, businessIds_);
    bool isParseSequences = ParseSequences(parser, sequences_);
    bool isParseTwoFingerGesture = ParseTwoFingerGesture(parser, twoFingerGesture_);
    bool isParseSingleKnuckleGesture = IsParseKnuckleGesture(parser, SINGLE_KNUCKLE_ABILITY, singleKnuckleGesture_);
    bool isParseDoubleKnuckleGesture = IsParseKnuckleGesture(parser, DOUBLE_KNUCKLE_ABILITY, doubleKnuckleGesture_);
    bool isParseMultiFingersTap = ParseMultiFingersTap(parser, TOUCHPAD_TRIP_TAP_ABILITY, threeFingersTap_);
    bool isParseRepeatKeys = ParseRepeatKeys(parser, repeatKeys_, repeatKeyMaxTimes_);
    screenshotSwitch_.statusConfig = SNAPSHOT_KNUCKLE_SWITCH;
    screenshotSwitch_.statusConfigValue = true;
    recordSwitch_.statusConfig = RECORD_KNUCKLE_SWITCH;
    recordSwitch_.statusConfigValue = true;
    if (!isParseShortKeys && !isParseSequences && !isParseTwoFingerGesture && !isParseSingleKnuckleGesture &&
        !isParseDoubleKnuckleGesture && !isParseMultiFingersTap && !isParseRepeatKeys) {
        MMI_HILOGE("Parse configFile failed");
        return false;
    }

    Print();
    PrintSeq();
    return true;
}

bool KeyCommandHandler::ParseExcludeJson(const std::string &configFile)
{
    CALL_DEBUG_ENTER;
    std::string jsonStr = ReadJsonFile(configFile);
    if (jsonStr.empty()) {
        MMI_HILOGE("Read excludeKey configFile failed");
        return false;
    }
    JsonParser parser;
    parser.json_ = cJSON_Parse(jsonStr.c_str());
    if (!cJSON_IsObject(parser.json_)) {
        MMI_HILOGE("Parser.json_ of excludeKey is not object");
        return false;
    }
    bool isParseExcludeKeys = ParseExcludeKeys(parser, excludeKeys_);
    if (!isParseExcludeKeys) {
        MMI_HILOGE("Parse ExcludeKeys configFile failed");
        return false;
    }
    PrintExcludeKeys();
    return true;
}

void KeyCommandHandler::Print()
{
    MMI_HILOGI("ShortcutKey count:%{public}zu", shortcutKeys_.size());
    int32_t row = 0;
    for (const auto &item : shortcutKeys_) {
        MMI_HILOGI("The row:%{public}d", row++);
        auto &shortcutKey = item.second;
        for (const auto &prekey : shortcutKey.preKeys) {
            MMI_HILOGI("The preKey:%d", prekey);
        }
        MMI_HILOGI("The finalKey:%d, keyDownDuration:%{public}d, triggerType:%{public}d,"
                   " bundleName:%{public}s, abilityName:%{public}s", shortcutKey.finalKey,
                   shortcutKey.keyDownDuration, shortcutKey.triggerType,
                   shortcutKey.ability.bundleName.c_str(), shortcutKey.ability.abilityName.c_str());
    }
}

void KeyCommandHandler::PrintExcludeKeys()
{
    size_t keysSize = excludeKeys_.size();
    for (size_t i = 0; i < keysSize; i++) {
        MMI_HILOGD("keyCode:%d, keyAction:%{public}d, delay:%{public}" PRId64,
                   excludeKeys_[i].keyCode, excludeKeys_[i].keyAction, excludeKeys_[i].delay);
    }
}

void KeyCommandHandler::PrintSeq()
{
    MMI_HILOGI("Sequences count:%{public}zu", sequences_.size());
    int32_t row = 0;
    for (const auto &item : sequences_) {
        MMI_HILOGI("The row:%{public}d", row++);
        for (const auto& sequenceKey : item.sequenceKeys) {
            MMI_HILOGI("The keyCode:%d, keyAction:%{public}d, delay:%{public}" PRId64,
                       sequenceKey.keyCode, sequenceKey.keyAction, sequenceKey.delay);
        }
        MMI_HILOGI("Ability bundleName:%{public}s, abilityName:%{public}s",
                   item.ability.bundleName.c_str(), item.ability.abilityName.c_str());
    }
}

bool KeyCommandHandler::IsExcludeKey(const std::shared_ptr<KeyEvent> key)
{
    size_t keysSize = excludeKeys_.size();
    for (size_t i = 0; i < keysSize; i++) {
        if (key->GetKeyCode() == excludeKeys_[i].keyCode) {
            if (key->GetKeyAction() == excludeKeys_[i].keyAction) {
                return true;
            }
        }
    }
    return false;
}

bool KeyCommandHandler::IsEnableCombineKey(const std::shared_ptr<KeyEvent> key)
{
    CHKPF(key);
    if (enableCombineKey_) {
        return true;
    }

    if (!isParseExcludeConfig_) {
        if (!ParseExcludeConfig()) {
            DfxHisysevent::ReportFailHandleKey("IsEnableCombineKey", key->GetKeyCode(),
                DfxHisysevent::KEY_ERROR_CODE::FAILED_PARSE_CONFIG);
            MMI_HILOGE("Parse Exclude configFile failed");
            return false;
        }
        isParseExcludeConfig_ = true;
    }

    if (IsExcludeKey(key)) {
        if (EventLogHelper::IsBetaVersion() && !key->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
            MMI_HILOGD("ExcludekeyCode:%{private}d,ExcludekeyAction:%{public}d",
                key->GetKeyCode(), key->GetKeyAction());
        } else {
            MMI_HILOGD("ExcludekeyCode:%d, ExcludekeyAction:%{public}d", key->GetKeyCode(), key->GetKeyAction());
        }
        auto items = key->GetKeyItems();
        MMI_HILOGI("KeyItemsSize:%{public}zu", items.size());
        if (items.size() != 1) {
            return enableCombineKey_;
        }
        return true;
    }
    if (key->GetKeyCode() == KeyEvent::KEYCODE_L) {
        for (const auto &item : key->GetKeyItems()) {
            int32_t keyCode = item.GetKeyCode();
            if (keyCode != KeyEvent::KEYCODE_L && keyCode != KeyEvent::KEYCODE_META_LEFT &&
                keyCode != KeyEvent::KEYCODE_META_RIGHT) {
                MMI_HILOGI("GetKeyCode:%d", keyCode);
                return enableCombineKey_;
            }
        }
        return true;
    }
    if (key->GetKeyCode() == KeyEvent::KEYCODE_SYSRQ) {
        auto iterms = key->GetKeyItems();
        MMI_HILOGI("Recording response VM");
        return iterms.size() != 1 ? enableCombineKey_ : true;
    }
    return enableCombineKey_;
}

int32_t KeyCommandHandler::EnableCombineKey(bool enable)
{
    enableCombineKey_ = enable;
    MMI_HILOGI("Enable combineKey is successful in keyCommand handler, enable:%{public}d", enable);
    return RET_OK;
}

void KeyCommandHandler::ParseStatusConfigObserver()
{
    CALL_DEBUG_ENTER;
    for (Sequence& item : sequences_) {
        if (item.statusConfig.empty()) {
            continue;
        }
        CreateStatusConfigObserver<Sequence>(item);
    }

    for (auto& item : shortcutKeys_) {
        ShortcutKey &shortcutKey = item.second;
        if (shortcutKey.statusConfig.empty()) {
            continue;
        }
        CreateStatusConfigObserver<ShortcutKey>(shortcutKey);
    }
}

template <class T>
void KeyCommandHandler::CreateStatusConfigObserver(T& item)
{
    CALL_DEBUG_ENTER;
    SettingObserver::UpdateFunc updateFunc = [weak = weak_from_this(), &item](const std::string& key) {
        auto ptr = weak.lock();
        if (ptr == nullptr) {
            return;
        }
        bool statusValue = true;
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetBoolValue(key, statusValue);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return;
        }
        MMI_HILOGI("Config changed key:%s, value:%{public}d", key.c_str(), statusValue);
        item.statusConfigValue = statusValue;
        ptr->OnKunckleSwitchStatusChange(item.statusConfig);
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.statusConfig, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("Register setting observer failed, ret:%{public}d", ret);
        statusObserver = nullptr;
    }
    bool configVlaue = true;
    ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .GetBoolValue(item.statusConfig, configVlaue);
    if (ret != RET_OK) {
        MMI_HILOGE("Get value from setting date fail");
        return;
    }
    MMI_HILOGI("Get value success key:%s, value:%{public}d", item.statusConfig.c_str(), configVlaue);
    item.statusConfigValue = configVlaue;
}

int32_t KeyCommandHandler::RegisterKnuckleSwitchByUserId(int32_t userId)
{
    CALL_DEBUG_ENTER;
    currentUserId_ = userId;
    CreateKnuckleConfigObserver(screenshotSwitch_);
    CreateKnuckleConfigObserver(recordSwitch_);
    return RET_OK;
}

template <class T>
void KeyCommandHandler::CreateKnuckleConfigObserver(T& item)
{
    CALL_DEBUG_ENTER;
    char buf[DEFAULT_BUFFER_LENGTH] {};
    if (sprintf_s(buf, sizeof(buf), SECURE_SETTING_URI_PROXY.c_str(), currentUserId_) < 0) {
        MMI_HILOGE("Failed to format URI");
        return;
    }
    SettingObserver::UpdateFunc updateFunc = [weak = weak_from_this(), &item, buf](const std::string& key) {
        auto ptr = weak.lock();
        if (ptr == nullptr) {
            return;
        }
        bool statusValue = true;
        ErrCode ret = RET_ERR;
        MMI_HILOGI("The statusConfig:%s", item.statusConfig.c_str());
        ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).GetBoolValue(key, statusValue,
            std::string(buf));
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting data fail");
            item.statusConfigValue = true;
            return;
        }
        MMI_HILOGI("Config changed key:%s, value:%{public}d", key.c_str(), statusValue);
        item.statusConfigValue = statusValue;
        ptr->OnKunckleSwitchStatusChange(item.statusConfig);
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.statusConfig, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).RegisterObserver(statusObserver,
        std::string(buf));
    if (ret != ERR_OK) {
        MMI_HILOGE("Register setting observer failed, ret:%{public}d", ret);
        statusObserver = nullptr;
    }
    bool configValue = true;
    ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .GetBoolValue(item.statusConfig, configValue, std::string(buf));
    if (ret != RET_OK) {
        MMI_HILOGE("Get value from setting data fail");
        item.statusConfigValue = true;
        return;
    }
    MMI_HILOGI("Get value success key:%s, value:%{public}d", item.statusConfig.c_str(), configValue);
    item.statusConfigValue = configValue;
}

std::shared_ptr<KeyEvent> KeyCommandHandler::CreateKeyEvent(int32_t keyCode, int32_t keyAction, bool isPressed)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    KeyEvent::KeyItem item;
    item.SetKeyCode(keyCode);
    item.SetPressed(isPressed);
    keyEvent->SetKeyCode(keyCode);
    keyEvent->SetKeyAction(keyAction);
    keyEvent->AddPressedKeyItems(item);
    return keyEvent;
}

bool KeyCommandHandler::PreHandleEvent(const std::shared_ptr<KeyEvent> key)
{
    CHKPF(key);
    if (EventLogHelper::IsBetaVersion() && !key->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
        MMI_HILOGD("KeyEvent occured. keyCode:%{public}d, keyAction:%{public}d",
            key->GetKeyCode(), key->GetKeyAction());
    } else {
        MMI_HILOGD("KeyEvent occured. keyCode:%d, keyAction:%{public}d", key->GetKeyCode(), key->GetKeyAction());
    }
    if (key->GetKeyCode() == KeyEvent::KEYCODE_F1) {
        DfxHisysevent::ReportKeyEvent("screen on");
    }
    if (!IsEnableCombineKey(key)) {
        MMI_HILOGI("Combine key is taken over in key command");
        return false;
    }
    if (!isParseConfig_) {
        if (!ParseConfig()) {
            MMI_HILOGE("Parse configFile failed");
            DfxHisysevent::ReportFailHandleKey("PreHandleEvent", key->GetKeyCode(),
                DfxHisysevent::KEY_ERROR_CODE::FAILED_PARSE_CONFIG);
            return false;
        }
        isParseConfig_ = true;
    }
    if (!isParseLongPressConfig_) {
        if (!ParseLongPressConfig()) {
            MMI_HILOGE("Parse long press configFile failed");
            DfxHisysevent::ReportFailHandleKey("PreHandleEvent", key->GetKeyCode(),
                DfxHisysevent::KEY_ERROR_CODE::FAILED_PARSE_CONFIG);
        }
        isParseLongPressConfig_ = true;
    }
    if (!isParseMaxCount_) {
        ParseRepeatKeyMaxCount();
        isParseMaxCount_ = true;
    }
    if (key->GetKeyCode() == KeyEvent::KEYCODE_VOLUME_DOWN || key->GetKeyCode() == KeyEvent::KEYCODE_VOLUME_UP) {
        lastVolumeDownActionTime_ = key->GetActionTime();
    }
    return true;
}

bool KeyCommandHandler::PreHandleEvent()
{
    CALL_INFO_TRACE;
    if (!isParseConfig_) {
        if (!ParseConfig()) {
            MMI_HILOGE("Parse configFile failed");
            return false;
        }
        isParseConfig_ = true;
    }
    if (!isParseLongPressConfig_) {
        if (!ParseLongPressConfig()) {
            MMI_HILOGE("Parse long press configFile failed");
        }
        isParseLongPressConfig_ = true;
    }
    if (!isParseMaxCount_) {
        ParseRepeatKeyMaxCount();
        isParseMaxCount_ = true;
    }
    return true;
}

bool KeyCommandHandler::HandleEvent(const std::shared_ptr<KeyEvent> key)
{
    CALL_DEBUG_ENTER;
    CHKPF(key);
    if (!PreHandleEvent(key)) {
        return false;
    }

    if (STYLUS_HANDLER->HandleStylusKey(key)) {
        DfxHisysevent::ReportKeyEvent("stylus");
        return true;
    }

    bool shortKeysHandleRet = HandleShortKeys(key);
    if (key->GetKeyCode() == KeyEvent::KEYCODE_POWER && key->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        powerUpTime_ = key->GetActionTime();
    }
    if (key->GetKeyCode() == KeyEvent::KEYCODE_POWER && key->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN) {
        if ((key->GetActionTime() - powerUpTime_) > POWER_ACTION_INTERVAL * FREQUENCY &&
            (key->GetActionTime() - sosLaunchTime_) > SOS_WAIT_TIME * FREQUENCY) {
                MMI_HILOGI("Set isFreezePowerKey as false");
                isFreezePowerKey_ = false;
            }
    }
    if (key->GetKeyCode() == KeyEvent::KEYCODE_POWER && isFreezePowerKey_) {
        MMI_HILOGI("Freeze power key");
        return true;
    }
    bool sequencesHandleRet = HandleSequences(key);
    if (shortKeysHandleRet) {
        launchAbilityCount_ = 0;
        isHandleSequence_ = false;
        return true;
    }
    if (sequencesHandleRet) {
        isHandleSequence_ = true;
        return true;
    }
    if (key->GetKeyCode() == KeyEvent::KEYCODE_POWER) {
        MMI_HILOGI("Handle power key DownStart:%{public}d", isDownStart_);
    }
    if (key->GetKeyCode() != repeatKey_.keyCode && key->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN) {
        MMI_HILOGI("Combination key currentKey:%{public}d, repeatKey:%{public}d",
            key->GetKeyCode(), repeatKey_.keyCode);
        isDownStart_ = false;
    }
    if (!isDownStart_) {
        HandleRepeatKeys(key);
        return false;
    } else {
        if (HandleRepeatKeys(key)) {
            MMI_HILOGI("Handle power key lifting event");
            return true;
        }
    }
    count_ = 0;
    repeatKeyCountMap_.clear();
    isDownStart_ = false;
    return false;
}

void KeyCommandHandler::InitKeyObserver()
{
    if (!isParseStatusConfig_) {
        ParseStatusConfigObserver();
        isParseStatusConfig_ = true;
    }
    if (!isKnuckleSwitchConfig_) {
        CreateKnuckleConfigObserver(screenshotSwitch_);
        CreateKnuckleConfigObserver(recordSwitch_);
        isKnuckleSwitchConfig_ = true;
    }
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
bool KeyCommandHandler::OnHandleEvent(const std::shared_ptr<KeyEvent> key)
{
    CALL_DEBUG_ENTER;
    CHKPF(key);
    HandlePointerVisibleKeys(key);
    if (HandleEvent(key)) {
        return true;
    }

    if (specialKeys_.find(key->GetKeyCode()) != specialKeys_.end()) {
        HandleSpecialKeys(key->GetKeyCode(), key->GetAction());
        return true;
    }

    if (IsSpecialType(key->GetKeyCode(), SpecialType::SUBSCRIBER_BEFORE_DELAY)) {
        auto tmpKey = KeyEvent::Clone(key);
        int32_t timerId = TimerMgr->AddTimer(SPECIAL_KEY_DOWN_DELAY, 1, [this, tmpKey] () {
            MMI_HILOGD("Timer callback");
            auto it = specialTimers_.find(tmpKey->GetKeyCode());
            if (it != specialTimers_.end() && !it->second.empty()) {
                it->second.pop_front();
            }
            auto handler = InputHandler->GetSubscriberHandler();
            CHKPV(handler);
            handler->HandleKeyEvent(tmpKey);
        });
        if (timerId < 0) {
            DfxHisysevent::ReportFailHandleKey("OnHandleEvent", key->GetKeyCode(),
                DfxHisysevent::KEY_ERROR_CODE::FAILED_TIMER);
            MMI_HILOGE("Add timer failed");
            return false;
        }

        auto it = specialTimers_.find(key->GetKeyCode());
        if (it == specialTimers_.end()) {
            std::list<int32_t> timerIds;
            timerIds.push_back(timerId);
            auto it = specialTimers_.emplace(key->GetKeyCode(), timerIds);
            if (!it.second) {
                MMI_HILOGE("Keycode duplicated");
                return false;
            }
        } else {
            it->second.push_back(timerId);
        }
        MMI_HILOGD("Add timer success");
        return true;
    }
    return false;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
bool KeyCommandHandler::OnHandleEvent(const std::shared_ptr<PointerEvent> pointer)
{
    CALL_DEBUG_ENTER;
    CHKPF(pointer);
    STYLUS_HANDLER->SetLastEventState(false);
    if (!isParseConfig_) {
        if (!ParseConfig()) {
            MMI_HILOGE("Parse configFile failed");
            return false;
        }
        isParseConfig_ = true;
    }
    if (!isParseLongPressConfig_) {
        if (!ParseLongPressConfig()) {
            MMI_HILOGE("Parse long press configFile failed");
        }
        isParseLongPressConfig_ = true;
    }
    return HandleMulFingersTap(pointer);
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

bool KeyCommandHandler::HandleRepeatKeys(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (repeatKeys_.empty()) {
        MMI_HILOGD("No sequences configuration data");
        return false;
    }

    bool isLaunched = false;
    bool waitRepeatKey = false;

    for (RepeatKey& item : repeatKeys_) {
        if (CheckSpecialRepeatKey(item, keyEvent)) {
            launchAbilityCount_ = 0;
            MMI_HILOGI("Skip repeatKey");
            return false;
        }
        if (HandleKeyUpCancel(item, keyEvent)) {
            MMI_HILOGI("Cancel repeatKey");
            DfxHisysevent::ReportKeyEvent("cancel");
            return false;
        }
        if (HandleRepeatKeyCount(item, keyEvent)) {
            break;
        }
    }

    for (RepeatKey& item : repeatKeys_) {
        bool isRepeatKey = HandleRepeatKey(item, isLaunched, keyEvent);
        if (isRepeatKey) {
            waitRepeatKey = true;
        }
    }
    MMI_HILOGI("Handle repeat key, isLaunched:%{public}d, waitRepeatKey:%{public}d",
        isLaunched, waitRepeatKey);
    return isLaunched || waitRepeatKey;
}

bool KeyCommandHandler::IsMusicActivate()
{
    return InputScreenCaptureAgent::GetInstance().IsMusicActivate();
}

void KeyCommandHandler::HandleRepeatKeyOwnCount(const RepeatKey &item)
{
    if (item.ability.bundleName == SOS_BUNDLE_NAME) {
        if (downActionTime_ - lastDownActionTime_ < item.delay) {
            repeatKeyCountMap_[item.ability.bundleName]++;
        }
    } else if (downActionTime_ - upActionTime_ < item.delay) {
        repeatKeyCountMap_[item.ability.bundleName]++;
    }
}

bool KeyCommandHandler::HandleRepeatKey(const RepeatKey &item, bool &isLaunched,
    const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (keyEvent->GetKeyCode() != item.keyCode) {
        return false;
    }
    if (!isDownStart_) {
        return false;
    }
    if (keyEvent->GetKeyAction() != KeyEvent::KEY_ACTION_DOWN ||
        (count_ > maxCount_ && keyEvent->GetKeyCode() == KeyEvent::KEYCODE_POWER)) {
        MMI_HILOGI("The isDownStart:%{public}d", isDownStart_);
        if (isDownStart_) {
            HandleSpecialKeys(keyEvent->GetKeyCode(), keyEvent->GetKeyAction());
        }
        return true;
    }
    auto it = repeatKeyCountMap_.find(item.ability.bundleName);
    if (it == repeatKeyCountMap_.end()) {
        lastDownActionTime_ = downActionTime_;
        if (item.ability.bundleName != SOS_BUNDLE_NAME ||
            downActionTime_ - lastVolumeDownActionTime_ > SOS_INTERVAL_TIMES) {
            repeatKeyCountMap_.emplace(item.ability.bundleName, 1);
            return true;
        }
        return false;
    }
    HandleRepeatKeyOwnCount(item);
    lastDownActionTime_ = downActionTime_;
    if (repeatKeyCountMap_[item.ability.bundleName] == item.times) {
        if (!item.statusConfig.empty()) {
            bool statusValue = true;
            auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
                .GetBoolValue(item.statusConfig, statusValue);
            if (ret != RET_OK) {
                MMI_HILOGE("Get value from setting data fail");
                DfxHisysevent::ReportFailHandleKey("HandleRepeatKey", keyEvent->GetKeyCode(),
                    DfxHisysevent::KEY_ERROR_CODE::ERROR_RETURN_VALUE);
                return false;
            }
            if (!statusValue) {
                MMI_HILOGE("Get value from setting data, result is false");
                return false;
            }
        }
        if (repeatKeyMaxTimes_.find(item.keyCode) != repeatKeyMaxTimes_.end()) {
            launchAbilityCount_ = count_;
            if (item.times < repeatKeyMaxTimes_[item.keyCode]) {
                return HandleRepeatKeyAbility(item, isLaunched, keyEvent, false);
            }
            return HandleRepeatKeyAbility(item, isLaunched, keyEvent, true);
        }
    }
    if (count_ > item.times && repeatKeyMaxTimes_.find(item.keyCode) != repeatKeyMaxTimes_.end() &&
        repeatKeyTimerIds_.find(item.ability.bundleName) != repeatKeyTimerIds_.end()) {
        if (count_ < repeatKeyMaxTimes_[item.keyCode] && repeatKeyTimerIds_[item.ability.bundleName] >= 0) {
            TimerMgr->RemoveTimer(repeatKeyTimerIds_[item.ability.bundleName]);
            repeatKeyTimerIds_.erase(item.ability.bundleName);
            return true;
        }
    }
    return true;
}

bool KeyCommandHandler::HandleRepeatKeyAbility(const RepeatKey &item, bool &isLaunched,
    const std::shared_ptr<KeyEvent> keyEvent, bool isMaxTimes)
{
    if (!isMaxTimes) {
        int64_t delaytime = intervalTime_ - (downActionTime_ - upActionTime_);
        int32_t timerId = TimerMgr->AddTimer(
            delaytime / SECONDS_SYSTEM, 1, [this, item, &isLaunched, keyEvent] () {
            LaunchRepeatKeyAbility(item, isLaunched, keyEvent);
            auto it = repeatKeyTimerIds_.find(item.ability.bundleName);
            if (it != repeatKeyTimerIds_.end()) {
                repeatKeyTimerIds_.erase(it);
            }
        });
        if (timerId < 0) {
            DfxHisysevent::ReportFailHandleKey("HandleRepeatKeyAbility", keyEvent->GetKeyCode(),
                DfxHisysevent::KEY_ERROR_CODE::FAILED_TIMER);
            return false;
        }
        if (repeatTimerId_ >= 0) {
            TimerMgr->RemoveTimer(repeatTimerId_);
            repeatTimerId_ = DEFAULT_VALUE;
            isHandleSequence_ = false;
        }
        if (repeatKeyTimerIds_.find(item.ability.bundleName) == repeatKeyTimerIds_.end()) {
            repeatKeyTimerIds_.emplace(item.ability.bundleName, timerId);
            return true;
        }
        repeatKeyTimerIds_[item.ability.bundleName] = timerId;
        return true;
    }
    LaunchRepeatKeyAbility(item, isLaunched, keyEvent);
    return true;
}

void KeyCommandHandler::LaunchRepeatKeyAbility(const RepeatKey &item, bool &isLaunched,
    const std::shared_ptr<KeyEvent> keyEvent)
{
    BytraceAdapter::StartLaunchAbility(KeyCommandType::TYPE_REPEAT_KEY, item.ability.bundleName);
    DfxHisysevent::ReportKeyEvent(item.ability.bundleName);
    LaunchAbility(item.ability);
    BytraceAdapter::StopLaunchAbility();
    repeatKeyCountMap_.clear();
    isLaunched = true;
    auto subscriberHandler = InputHandler->GetSubscriberHandler();
    CHKPV(subscriberHandler);
    auto keyEventCancel = std::make_shared<KeyEvent>(*keyEvent);
    keyEventCancel->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    subscriberHandler->HandleKeyEvent(keyEventCancel);
}

int32_t KeyCommandHandler::SetIsFreezePowerKey(const std::string pageName)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> lock(mutex_);
    if (pageName != "SosCountdown") {
        isFreezePowerKey_ = false;
        return RET_OK;
    }
    isFreezePowerKey_ = true;
    sosLaunchTime_ = OHOS::MMI::GetSysClockTime();
    count_ = 0;
    launchAbilityCount_ = 0;
    repeatKeyCountMap_.clear();
    if (sosDelayTimerId_ >= 0) {
        TimerMgr->RemoveTimer(sosDelayTimerId_);
        sosDelayTimerId_ = DEFAULT_VALUE;
    }
    int32_t timerId = TimerMgr->AddTimer(
        SOS_COUNT_DOWN_TIMES / SECONDS_SYSTEM, 1, [this] () {
        MMI_HILOGW("Timeout, restore the power button");
        isFreezePowerKey_ = false;
    });
    if (timerId < 0) {
        MMI_HILOGE("Add timer failed");
        isFreezePowerKey_ = false;
        return RET_ERR;
    }
    return RET_OK;
}

bool KeyCommandHandler::HandleKeyUpCancel(const RepeatKey &item, const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (keyEvent->GetKeyCode() == item.keyCode && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_CANCEL) {
        isKeyCancel_ = true;
        isDownStart_ = false;
        count_ = 0;
        repeatKeyCountMap_.clear();
        DfxHisysevent::ReportKeyEvent("cancel");
        return true;
    }
    return false;
}

bool KeyCommandHandler::HandleRepeatKeyCount(const RepeatKey &item, const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);

    if (keyEvent->GetKeyCode() == item.keyCode && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        upActionTime_ = keyEvent->GetActionTime();
        repeatKey_.keyCode = item.keyCode;
        repeatKey_.keyAction = keyEvent->GetKeyAction();
        int64_t intervalTime = intervalTime_;
        if (item.keyCode == KeyEvent::KEYCODE_POWER) {
            intervalTime = intervalTime_ - (upActionTime_ - downActionTime_);
            if (walletLaunchDelayTimes_ != 0) {
                intervalTime = walletLaunchDelayTimes_;
            }
        }
        repeatTimerId_ = TimerMgr->AddTimer(intervalTime / SECONDS_SYSTEM, 1, [this] () {
            SendKeyEvent();
            repeatTimerId_ = -1;
        });
        if (repeatTimerId_ < 0) {
            return false;
        }
        return true;
    }

    if (keyEvent->GetKeyCode() == item.keyCode && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN) {
        if (repeatKey_.keyCode != item.keyCode) {
            count_ = 1;
            repeatKey_.keyCode = item.keyCode;
            repeatKey_.keyAction = keyEvent->GetKeyAction();
        } else {
            if (repeatKey_.keyAction == keyEvent->GetKeyAction()) {
                MMI_HILOGD("Repeat key, reset down status");
                count_ = 0;
                isDownStart_ = false;
                repeatKeyCountMap_.clear();
                return true;
            } else {
                repeatKey_.keyAction = keyEvent->GetKeyAction();
                count_++;
                MMI_HILOGD("Repeat count:%{public}d", count_);
            }
        }
        isDownStart_ = true;
        downActionTime_ = keyEvent->GetActionTime();
        if ((downActionTime_ - upActionTime_) < intervalTime_) {
            if (repeatTimerId_ >= 0) {
                TimerMgr->RemoveTimer(repeatTimerId_);
                repeatTimerId_ = -1;
                isHandleSequence_ = false;
            }
        }
        return true;
    }
    return false;
}

void KeyCommandHandler::SendKeyEvent()
{
    CALL_DEBUG_ENTER;
    if (!isHandleSequence_) {
        MMI_HILOGD("Launch ability count:%{public}d count:%{public}d", launchAbilityCount_, count_);
        for (int32_t i = launchAbilityCount_; i < count_; i++) {
            int32_t keycode = repeatKey_.keyCode;
            if (IsSpecialType(keycode, SpecialType::KEY_DOWN_ACTION)) {
                HandleSpecialKeys(keycode, KeyEvent::KEY_ACTION_UP);
            }
            if (count_ == repeatKeyMaxTimes_[keycode] - 1 && keycode == KeyEvent::KEYCODE_POWER) {
                auto keyEventCancel = CreateKeyEvent(keycode, KeyEvent::KEY_ACTION_CANCEL, false);
                CHKPV(keyEventCancel);
                auto handler = InputHandler->GetSubscriberHandler();
                CHKPV(handler);
                handler->HandleKeyEvent(keyEventCancel);
                continue;
            }
            if (i != 0) {
                auto keyEventDown = CreateKeyEvent(keycode, KeyEvent::KEY_ACTION_DOWN, true);
                CHKPV(keyEventDown);
                auto handler = InputHandler->GetSubscriberHandler();
                CHKPV(handler);
                handler->HandleKeyEvent(keyEventDown);
            }

            auto keyEventUp = CreateKeyEvent(keycode, KeyEvent::KEY_ACTION_UP, false);
            CHKPV(keyEventUp);
            auto handler = InputHandler->GetSubscriberHandler();
            CHKPV(handler);
            handler->HandleKeyEvent(keyEventUp);
        }
    }
    count_ = 0;
    repeatKeyCountMap_.clear();
    isDownStart_ = false;
    isHandleSequence_ = false;
    launchAbilityCount_ = 0;
}

bool KeyCommandHandler::HandleShortKeys(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (shortcutKeys_.empty()) {
        MMI_HILOGD("No shortkeys configuration data");
        return false;
    }
    if (IsKeyMatch(lastMatchedKey_, keyEvent)) {
        MMI_HILOGD("The same key is waiting timeout, skip");
        return true;
    }
    if (currentLaunchAbilityKey_.timerId >= 0 && IsKeyMatch(currentLaunchAbilityKey_, keyEvent)) {
        if (EventLogHelper::IsBetaVersion() && !keyEvent->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
            MMI_HILOGD("Repeat, current key %{public}d has launched ability", currentLaunchAbilityKey_.finalKey);
        } else {
            MMI_HILOGD("Repeat, current key %d has launched ability", currentLaunchAbilityKey_.finalKey);
        }
        return true;
    }
    DfxHisysevent::GetComboStartTime();
    if (lastMatchedKey_.timerId >= 0) {
        MMI_HILOGD("Remove timer:%{public}d", lastMatchedKey_.timerId);
        TimerMgr->RemoveTimer(lastMatchedKey_.timerId);
        lastMatchedKey_.timerId = -1;
    }
    ResetLastMatchedKey();
    if (MatchShortcutKeys(keyEvent)) {
        return true;
    }
    return HandleConsumedKeyEvent(keyEvent);
}

bool KeyCommandHandler::MatchShortcutKeys(const std::shared_ptr<KeyEvent> keyEvent)
{
#ifdef SHORTCUT_KEY_RULES_ENABLED
    if ((keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) &&
        KEY_SHORTCUT_MGR->HaveShortcutConsumed(keyEvent)) {
        return false;
    }
#endif // SHORTCUT_KEY_RULES_ENABLED
    bool result = false;
    std::vector<ShortcutKey> upAbilities;

    for (auto &item : shortcutKeys_) {
        result = MatchShortcutKey(keyEvent, item.second, upAbilities) || result;
    }
    if (!upAbilities.empty()) {
        std::sort(upAbilities.begin(), upAbilities.end(),
            [](const ShortcutKey &lShortcutKey, const ShortcutKey &rShortcutKey) -> bool {
            return lShortcutKey.keyDownDuration > rShortcutKey.keyDownDuration;
        });
        ShortcutKey tmpShorteKey = upAbilities.front();
        MMI_HILOGI("Start launch ability immediately");
#ifdef SHORTCUT_KEY_RULES_ENABLED
        KEY_SHORTCUT_MGR->MarkShortcutConsumed(tmpShorteKey);
#endif // SHORTCUT_KEY_RULES_ENABLED
        BytraceAdapter::StartLaunchAbility(KeyCommandType::TYPE_SHORTKEY, tmpShorteKey.ability.bundleName);
        LaunchAbility(tmpShorteKey);
        DfxHisysevent::ReportKeyEvent(tmpShorteKey.ability.bundleName);
        BytraceAdapter::StopLaunchAbility();
    }
    if (result) {
        if (currentLaunchAbilityKey_.finalKey == keyEvent->GetKeyCode()
            && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
            ResetCurrentLaunchAbilityKey();
        }
    }
    return result;
}

bool KeyCommandHandler::MatchShortcutKey(std::shared_ptr<KeyEvent> keyEvent,
    ShortcutKey &shortcutKey, std::vector<ShortcutKey> &upAbilities)
{
    if (!shortcutKey.statusConfigValue) {
        return false;
    }
    if (!IsKeyMatch(shortcutKey, keyEvent)) {
        MMI_HILOGD("Not key matched, next");
        return false;
    }
    int32_t delay = GetKeyDownDurationFromXml(shortcutKey.businessId);
    if (delay >= MIN_SHORT_KEY_DOWN_DURATION && delay <= MAX_SHORT_KEY_DOWN_DURATION) {
        MMI_HILOGD("User defined new short key down duration:%{public}d", delay);
        shortcutKey.keyDownDuration = delay;
    }
    shortcutKey.Print();

    if (shortcutKey.triggerType == KeyEvent::KEY_ACTION_DOWN) {
        return HandleKeyDown(shortcutKey);
    } else if (shortcutKey.triggerType == KeyEvent::KEY_ACTION_UP) {
        bool handleResult = HandleKeyUp(keyEvent, shortcutKey);
        if (handleResult && shortcutKey.keyDownDuration > 0) {
            upAbilities.push_back(shortcutKey);
        }
        return handleResult;
    } else {
        return HandleKeyCancel(shortcutKey);
    }
}

bool KeyCommandHandler::HandleConsumedKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (currentLaunchAbilityKey_.finalKey == keyEvent->GetKeyCode()
        && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        MMI_HILOGI("Handle consumed key event, cancel opration");
        ResetCurrentLaunchAbilityKey();
        repeatKey_.keyCode = -1;
        repeatKey_.keyAction = -1;
        auto keyEventCancel = std::make_shared<KeyEvent>(*keyEvent);
        keyEventCancel->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
        auto inputEventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
        CHKPF(inputEventNormalizeHandler);
        inputEventNormalizeHandler->HandleKeyEvent(keyEventCancel);
        return true;
    }
    return false;
}

bool KeyCommandHandler::IsRepeatKeyEvent(const SequenceKey &sequenceKey)
{
    for (size_t i = keys_.size(); i > 0; --i) {
        if (keys_[i-1].keyCode == sequenceKey.keyCode) {
            if (keys_[i-1].keyAction == sequenceKey.keyAction) {
                MMI_HILOGI("Is repeat key, keyCode:%d", sequenceKey.keyCode);
                return true;
            }
            MMI_HILOGI("Is not repeat key");
            return false;
        }
    }
    return false;
}

bool KeyCommandHandler::IsActiveSequenceRepeating(std::shared_ptr<KeyEvent> keyEvent) const
{
    return (sequenceOccurred_ && !keys_.empty() &&
            (keys_.back().keyCode == keyEvent->GetKeyCode()) &&
            (keys_.back().keyAction == KeyEvent::KEY_ACTION_DOWN) &&
            (keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN));
}

void KeyCommandHandler::MarkActiveSequence(bool active)
{
    sequenceOccurred_ = active;
}

bool KeyCommandHandler::HandleSequences(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    std::string screenStatus = DISPLAY_MONITOR->GetScreenStatus();
    if (screenStatus == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
        if (keyEvent->GetKeyCode() == KeyEvent::KEYCODE_POWER) {
            MMI_HILOGI("The screen is currently off and the power button needs to respond");
            return false;
        }
    }
    if (IsActiveSequenceRepeating(keyEvent)) {
        MMI_HILOGD("Skip repeating key(%{private}d) in active sequence", keyEvent->GetKeyCode());
        return true;
    }
    MarkActiveSequence(false);
    if (matchedSequence_.timerId >= 0 && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        MMI_HILOGI("Screen locked, remove matchedSequence timer:%{public}d", matchedSequence_.timerId);
        TimerMgr->RemoveTimer(matchedSequence_.timerId);
        matchedSequence_.timerId = -1;
    }
    if (sequences_.empty()) {
        MMI_HILOGD("No sequences configuration data");
        return false;
    }

    if (!AddSequenceKey(keyEvent)) {
        MMI_HILOGD("Add new sequence key failed");
        return false;
    }

    if (filterSequences_.empty()) {
        filterSequences_ = sequences_;
    }

    bool isLaunchAbility = false;
    for (auto iter = filterSequences_.begin(); iter != filterSequences_.end();) {
        if (!HandleSequence((*iter), isLaunchAbility)) {
            filterSequences_.erase(iter);
            continue;
        }
        ++iter;
    }

    if (filterSequences_.empty()) {
        MMI_HILOGD("No sequences matched");
        keys_.clear();
        return false;
    }

    if (isLaunchAbility) {
        MarkActiveSequence(true);
        for (const auto& item : keys_) {
            if (IsSpecialType(item.keyCode, SpecialType::KEY_DOWN_ACTION)) {
                HandleSpecialKeys(item.keyCode, item.keyAction);
            }
            auto handler = InputHandler->GetSubscriberHandler();
            CHKPF(handler);
            handler->RemoveSubscriberKeyUpTimer(item.keyCode);
            RemoveSubscribedTimer(item.keyCode);
        }
    }
    return isLaunchAbility;
}

bool KeyCommandHandler::AddSequenceKey(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    SequenceKey sequenceKey;
    sequenceKey.keyCode = keyEvent->GetKeyCode();
    sequenceKey.keyAction = keyEvent->GetKeyAction();
    sequenceKey.actionTime = keyEvent->GetActionTime();
    size_t size = keys_.size();
    if (size > 0) {
        if (keys_[size - 1].actionTime > sequenceKey.actionTime) {
            MMI_HILOGE("The current event time is greater than the last event time");
            ResetSequenceKeys();
            return false;
        }
        if ((sequenceKey.actionTime - keys_[size - 1].actionTime) > MAX_DELAY_TIME) {
            MMI_HILOGD("The delay time is greater than the maximum delay time");
            ResetSequenceKeys();
        } else {
            if (IsRepeatKeyEvent(sequenceKey)) {
                MMI_HILOGD("This is a repeat key event, don't add");
                return false;
            }
            keys_[size - 1].delay = sequenceKey.actionTime - keys_[size - 1].actionTime;
            InterruptTimers();
        }
    }
    if (size > MAX_SEQUENCEKEYS_NUM) {
        DfxHisysevent::ReportFailHandleKey("AddSequenceKey", keyEvent->GetKeyCode(),
            DfxHisysevent::KEY_ERROR_CODE::INVALID_PARAMETER);
        MMI_HILOGD("The save key size more than the max size");
        return false;
    }
    keys_.push_back(sequenceKey);
    return true;
}

bool KeyCommandHandler::HandleScreenLocked(Sequence& sequence, bool &isLaunchAbility)
{
    sequence.timerId = TimerMgr->AddTimer(LONG_ABILITY_START_DELAY, 1, [this, &sequence] () {
        MMI_HILOGI("Timer callback");
        BytraceAdapter::StartLaunchAbility(KeyCommandType::TYPE_SEQUENCE, sequence.ability.bundleName);
        DfxHisysevent::ReportKeyEvent(sequence.ability.bundleName);
        LaunchAbility(sequence);
        sequence.timerId = -1;
        BytraceAdapter::StopLaunchAbility();
    });
    if (sequence.timerId < 0) {
        MMI_HILOGE("Add Timer failed");
        return false;
    }
    MMI_HILOGI("Add timer success");
    matchedSequence_ = sequence;
    isLaunchAbility = true;
    return true;
}

bool KeyCommandHandler::HandleNormalSequence(Sequence& sequence, bool &isLaunchAbility)
{
    if (sequence.abilityStartDelay == 0) {
        MMI_HILOGI("Start launch ability immediately");
        BytraceAdapter::StartLaunchAbility(KeyCommandType::TYPE_SEQUENCE, sequence.ability.bundleName);
        LaunchAbility(sequence);
        DfxHisysevent::ReportKeyEvent(sequence.ability.bundleName);
        BytraceAdapter::StopLaunchAbility();
        isLaunchAbility = true;
        return true;
    }
    sequence.timerId = TimerMgr->AddTimer(sequence.abilityStartDelay, 1, [this, &sequence] () {
        MMI_HILOGI("Timer callback");
        BytraceAdapter::StartLaunchAbility(KeyCommandType::TYPE_SEQUENCE, sequence.ability.bundleName);
        LaunchAbility(sequence);
        DfxHisysevent::ReportKeyEvent(sequence.ability.bundleName);
        sequence.timerId = -1;
        BytraceAdapter::StopLaunchAbility();
    });
    if (sequence.timerId < 0) {
        MMI_HILOGE("Add Timer failed");
        DfxHisysevent::ReportFailLaunchAbility(sequence.ability.bundleName,
            DfxHisysevent::KEY_ERROR_CODE::FAILED_TIMER);
        return false;
    }
    MMI_HILOGI("Add timer success");
    isLaunchAbility = true;
    return true;
}

bool KeyCommandHandler::HandleMatchedSequence(Sequence& sequence, bool &isLaunchAbility)
{
    std::string screenStatus = DISPLAY_MONITOR->GetScreenStatus();
    bool isScreenLocked = DISPLAY_MONITOR->GetScreenLocked();
    MMI_HILOGI("The screenStatus:%{public}s, isScreenLocked:%{public}d", screenStatus.c_str(), isScreenLocked);
    std::string bundleName = sequence.ability.bundleName;
    std::string matchName = ".screenshot";
    if (bundleName.find(matchName) != std::string::npos) {
        bundleName = bundleName.substr(bundleName.size() - matchName.size());
    }
    if (screenStatus == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
        if (bundleName == matchName) {
            MMI_HILOGI("Screen off, screenshot invalid");
            return false;
        }
    } else {
        if (bundleName == matchName && isScreenLocked) {
            MMI_HILOGI("Screen locked, screenshot delay 2000 milisecond");
            return HandleScreenLocked(sequence, isLaunchAbility);
        }
    }
    return HandleNormalSequence(sequence, isLaunchAbility);
}

bool KeyCommandHandler::HandleSequence(Sequence &sequence, bool &isLaunchAbility)
{
    CALL_DEBUG_ENTER;
    size_t keysSize = keys_.size();
    size_t sequenceKeysSize = sequence.sequenceKeys.size();
    if (!sequence.statusConfigValue) {
        return false;
    }
    if (keysSize > sequenceKeysSize) {
        MMI_HILOGI("The save sequence not matching ability sequence");
        return false;
    }
    for (size_t i = 0; i < keysSize; ++i) {
        if (keys_[i] != sequence.sequenceKeys[i]) {
            MMI_HILOGD("The keyCode or keyAction not matching");
            return false;
        }
        int64_t delay = sequence.sequenceKeys[i].delay;
        if (((i + 1) != keysSize) && (delay != 0) && (keys_[i].delay >= delay)) {
            MMI_HILOGD("Delay is not matching");
            return false;
        }
    }
    if (keysSize == sequenceKeysSize) {
        std::ostringstream oss;
        oss << sequence;
        MMI_HILOGI("SequenceKey matched:%{public}s", oss.str().c_str());
        return HandleMatchedSequence(sequence, isLaunchAbility);
    }
    return true;
}

bool KeyCommandHandler::HandleMulFingersTap(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_TRIPTAP) {
        MMI_HILOGI("The touchpad trip tap will launch ability");
        BytraceAdapter::StartLaunchAbility(KeyCommandType::TYPE_MULTI_FINGERS, threeFingersTap_.ability.bundleName);
        LaunchAbility(threeFingersTap_.ability, NO_DELAY);
        BytraceAdapter::StopLaunchAbility();
        return true;
    }
    return false;
}

bool KeyCommandHandler::IsKeyMatch(const ShortcutKey &shortcutKey, const std::shared_ptr<KeyEvent> &key)
{
    CALL_DEBUG_ENTER;
    CHKPF(key);
    if ((key->GetKeyCode() != shortcutKey.finalKey) || (shortcutKey.triggerType != key->GetKeyAction())) {
        DfxHisysevent::ReportFailHandleKey("IsKeyMatch", key->GetKeyCode(),
            DfxHisysevent::KEY_ERROR_CODE::INVALID_PARAMETER);
        return false;
    }
    if ((shortcutKey.preKeys.size() + 1) != key->GetKeyItems().size()) {
        return false;
    }
    for (const auto &item : key->GetKeyItems()) {
        int32_t keyCode = item.GetKeyCode();
        if (SkipFinalKey(keyCode, key)) {
            continue;
        }
        if (shortcutKey.preKeys.find(keyCode) == shortcutKey.preKeys.end()) {
            return false;
        }
    }
    MMI_HILOGD("Leave, key matched");
    return true;
}

bool KeyCommandHandler::SkipFinalKey(const int32_t keyCode, const std::shared_ptr<KeyEvent> &key)
{
    CHKPF(key);
    return keyCode == key->GetKeyCode();
}

bool KeyCommandHandler::HandleKeyDown(ShortcutKey &shortcutKey)
{
    CALL_DEBUG_ENTER;
    if (shortcutKey.keyDownDuration == 0) {
        MMI_HILOGI("Start launch ability immediately");
#ifdef SHORTCUT_KEY_RULES_ENABLED
        KEY_SHORTCUT_MGR->MarkShortcutConsumed(shortcutKey);
#endif // SHORTCUT_KEY_RULES_ENABLED
        BytraceAdapter::StartLaunchAbility(KeyCommandType::TYPE_SHORTKEY, shortcutKey.ability.bundleName);
        LaunchAbility(shortcutKey);
        DfxHisysevent::ReportKeyEvent(shortcutKey.ability.bundleName);
        BytraceAdapter::StopLaunchAbility();
        return true;
    }
    shortcutKey.timerId = TimerMgr->AddTimer(shortcutKey.keyDownDuration, 1, [this, &shortcutKey] () {
        MMI_HILOGI("Timer callback");
#ifdef SHORTCUT_KEY_RULES_ENABLED
        KEY_SHORTCUT_MGR->MarkShortcutConsumed(shortcutKey);
#endif // SHORTCUT_KEY_RULES_ENABLED
        currentLaunchAbilityKey_ = shortcutKey;
        shortcutKey.timerId = -1;
        BytraceAdapter::StartLaunchAbility(KeyCommandType::TYPE_SHORTKEY, shortcutKey.ability.bundleName);
        LaunchAbility(shortcutKey);
        DfxHisysevent::ReportKeyEvent(shortcutKey.ability.bundleName);
        BytraceAdapter::StopLaunchAbility();
    });
    if (shortcutKey.timerId < 0) {
        MMI_HILOGE("Add Timer failed");
        DfxHisysevent::ReportFailLaunchAbility(shortcutKey.ability.bundleName,
            DfxHisysevent::KEY_ERROR_CODE::FAILED_TIMER);
        return false;
    }
    MMI_HILOGI("Add timer success");
    lastMatchedKey_ = shortcutKey;
    auto handler = InputHandler->GetSubscriberHandler();
    CHKPF(handler);
    if (handler->IsKeyEventSubscribed(shortcutKey.finalKey, shortcutKey.triggerType)) {
        MMI_HILOGI("Current shortcutKey %d is subSubcribed", shortcutKey.finalKey);
        return false;
    }
    return true;
}

int32_t KeyCommandHandler::GetKeyDownDurationFromXml(const std::string &businessId)
{
    CALL_DEBUG_ENTER;
    return PREFERENCES_MGR->GetShortKeyDuration(businessId);
}

bool KeyCommandHandler::HandleKeyUp(const std::shared_ptr<KeyEvent> &keyEvent, const ShortcutKey &shortcutKey)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (shortcutKey.keyDownDuration == 0) {
        MMI_HILOGI("Start launch ability immediately");
        BytraceAdapter::StartLaunchAbility(KeyCommandType::TYPE_SHORTKEY, shortcutKey.ability.bundleName);
        LaunchAbility(shortcutKey);
        DfxHisysevent::ReportKeyEvent(shortcutKey.ability.bundleName);
        BytraceAdapter::StopLaunchAbility();
        return true;
    }
    std::optional<KeyEvent::KeyItem> keyItem = keyEvent->GetKeyItem();
    if (!keyItem) {
        MMI_HILOGE("The keyItem is nullopt");
        return false;
    }
    auto upTime = keyEvent->GetActionTime();
    auto downTime = keyItem->GetDownTime();
    MMI_HILOGI("The upTime:%{public}" PRId64 ",downTime:%{public}" PRId64 ",keyDownDuration:%{public}d",
        upTime, downTime, shortcutKey.keyDownDuration);

    if (upTime - downTime <= static_cast<int64_t>(shortcutKey.keyDownDuration) * FREQUENCY) {
        MMI_HILOGI("Skip, upTime - downTime <= duration");
        return false;
    }
    return true;
}

bool KeyCommandHandler::HandleKeyCancel(ShortcutKey &shortcutKey)
{
    CALL_DEBUG_ENTER;
    if (shortcutKey.timerId < 0) {
        DfxHisysevent::ReportFailHandleKey("HandleKeyCancel", shortcutKey.finalKey,
            DfxHisysevent::KEY_ERROR_CODE::INVALID_PARAMETER);
        MMI_HILOGE("Skip, timerid less than 0");
    }
    auto timerId = shortcutKey.timerId;
    shortcutKey.timerId = -1;
    TimerMgr->RemoveTimer(timerId);
    MMI_HILOGI("The timerId:%{public}d", timerId);
    return false;
}

void KeyCommandHandler::LaunchAbility(const Ability &ability, int64_t delay)
{
    CALL_DEBUG_ENTER;
    if (ability.bundleName.empty()) {
        MMI_HILOGW("BundleName is empty");
        return;
    }
    AAFwk::Want want;
    want.SetElementName(ability.deviceId, ability.bundleName, ability.abilityName);
    want.SetAction(ability.action);
    want.SetUri(ability.uri);
    want.SetType(ability.type);
    for (const auto &entity : ability.entities) {
        want.AddEntity(entity);
    }
    for (const auto &item : ability.params) {
        want.SetParam(item.first, item.second);
    }
    DfxHisysevent::CalcComboStartTimes(delay);
    DfxHisysevent::ReportComboStartTimes();
    MMI_HILOGW("Start launch ability, bundleName:%{public}s", ability.bundleName.c_str());
    auto begin = std::chrono::high_resolution_clock::now();
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    auto durationMS = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - begin).count();
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
    DfxHisysevent::ReportApiCallTimes(ApiDurationStatistics::Api::ABILITY_MGR_CLIENT_START_ABILITY, durationMS);
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
    if (err != ERR_OK) {
        MMI_HILOGE("LaunchAbility failed, bundleName:%{public}s, err:%{public}d", ability.bundleName.c_str(), err);
        return;
    }
    int32_t state = NapProcess::GetInstance()->GetNapClientPid();
    if (state == REMOVE_OBSERVER) {
        MMI_HILOGW("nap client status:%{public}d", state);
        return;
    }
    OHOS::MMI::NapProcess::NapStatusData napData;
    napData.pid = -1;
    napData.uid = -1;
    napData.bundleName = ability.bundleName;
    int32_t syncState = ACTIVE_EVENT;
    NapProcess::GetInstance()->AddMmiSubscribedEventData(napData, syncState);
    NapProcess::GetInstance()->NotifyBundleName(napData, syncState);
    MMI_HILOGW("End launch ability, bundleName:%{public}s", ability.bundleName.c_str());
    return;
}

void KeyCommandHandler::LaunchAbility(const Ability &ability)
{
    CALL_DEBUG_ENTER;
    AAFwk::Want want;
    want.SetElementName(ability.deviceId, ability.bundleName, ability.abilityName);
    want.SetAction(ability.action);
    want.SetUri(ability.uri);
    want.SetType(ability.uri);
    for (const auto &entity : ability.entities) {
        want.AddEntity(entity);
    }
    for (const auto &item : ability.params) {
        want.SetParam(item.first, item.second);
    }

    MMI_HILOGW("Start launch ability, bundleName:%{public}s", ability.bundleName.c_str());
    if (ability.abilityType == EXTENSION_ABILITY) {
        auto begin = std::chrono::high_resolution_clock::now();
        ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartExtensionAbility(want, nullptr);
        auto durationMS = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - begin).count();
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
        DfxHisysevent::ReportApiCallTimes(ApiDurationStatistics::Api::ABILITY_MGR_START_EXT_ABILITY, durationMS);
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
        if (err != ERR_OK) {
            MMI_HILOGE("LaunchAbility failed, bundleName:%{public}s, err:%{public}d", ability.bundleName.c_str(), err);
        }
    } else {
        auto begin = std::chrono::high_resolution_clock::now();
        ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
        auto durationMS = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - begin).count();
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
        DfxHisysevent::ReportApiCallTimes(ApiDurationStatistics::Api::ABILITY_MGR_CLIENT_START_ABILITY, durationMS);
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
        if (err != ERR_OK) {
            MMI_HILOGE("LaunchAbility failed, bundleName:%{public}s, err:%{public}d", ability.bundleName.c_str(), err);
        }
        if (err == ERR_OK && ability.bundleName == SOS_BUNDLE_NAME) {
            if (isDownStart_) {
                isDownStart_ = false;
            }
            isFreezePowerKey_ = true;
            sosLaunchTime_ = OHOS::MMI::GetSysClockTime();
            count_ = 0;
            launchAbilityCount_ = 0;
            repeatKeyCountMap_.clear();
            repeatKey_.keyCode = -1;
            repeatKey_.keyAction = -1;
            sosDelayTimerId_ = TimerMgr->AddTimer(SOS_DELAY_TIMES / SECONDS_SYSTEM, 1, [this] () {
                isFreezePowerKey_ = false;
                sosDelayTimerId_ = -1;
                MMI_HILOGW("Timeout, restore the power button");
            });
            if (sosDelayTimerId_ < 0) {
                isFreezePowerKey_ = false;
                MMI_HILOGE("Add timer failed");
            }
        }
    }
    MMI_HILOGW("End launch ability, bundleName:%{public}s", ability.bundleName.c_str());
}

void KeyCommandHandler::LaunchAbility(const ShortcutKey &key)
{
    CALL_INFO_TRACE;
    LaunchAbility(key.ability, lastMatchedKey_.keyDownDuration);
    ResetLastMatchedKey();
}

void KeyCommandHandler::LaunchAbility(const Sequence &sequence)
{
    CALL_INFO_TRACE;
    LaunchAbility(sequence.ability, sequence.abilityStartDelay);
}

void ShortcutKey::Print() const
{
    for (const auto &prekey: preKeys) {
        MMI_HILOGI("Eventkey matched, preKey:%d", prekey);
    }
    MMI_HILOGI("Eventkey matched, finalKey:%d, bundleName:%{public}s",
        finalKey, ability.bundleName.c_str());
}

void KeyCommandHandler::RemoveSubscribedTimer(int32_t keyCode)
{
    CALL_DEBUG_ENTER;
    auto iter = specialTimers_.find(keyCode);
    if (iter != specialTimers_.end()) {
        for (auto& item : iter->second) {
            TimerMgr->RemoveTimer(item);
        }
        specialTimers_.erase(keyCode);
        MMI_HILOGI("Remove timer success");
    }
}

void KeyCommandHandler::HandleSpecialKeys(int32_t keyCode, int32_t keyAction)
{
    CALL_INFO_TRACE;
    auto iter = specialKeys_.find(keyCode);
    if (keyAction == KeyEvent::KEY_ACTION_UP) {
        if (iter != specialKeys_.end()) {
            specialKeys_.erase(iter);
            return;
        }
    }

    if (keyAction == KeyEvent::KEY_ACTION_DOWN) {
        if (iter == specialKeys_.end()) {
            auto it = specialKeys_.emplace(keyCode, keyAction);
            if (!it.second) {
                MMI_HILOGD("KeyCode duplicated");
                return;
            }
        }
    }
}

void KeyCommandHandler::InterruptTimers()
{
    for (Sequence& item : filterSequences_) {
        if (item.timerId >= 0) {
            MMI_HILOGD("The key sequence change, close the timer");
            TimerMgr->RemoveTimer(item.timerId);
            item.timerId = -1;
        }
    }
}

void KeyCommandHandler::HandlePointerVisibleKeys(const std::shared_ptr<KeyEvent> &keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    if (keyEvent->GetKeyCode() == KeyEvent::KEYCODE_F9 && lastKeyEventCode_ == KeyEvent::KEYCODE_CTRL_LEFT) {
        MMI_HILOGI("Force make pointer visible");
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
        IPointerDrawingManager::GetInstance()->ForceClearPointerVisiableStatus();
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    }
    lastKeyEventCode_ = keyEvent->GetKeyCode();
}


int32_t KeyCommandHandler::UpdateSettingsXml(const std::string &businessId, int32_t delay)
{
    CALL_DEBUG_ENTER;
    if (businessId.empty() || businessIds_.empty()) {
        MMI_HILOGE("The business id or business ids is empty");
        return PARAMETER_ERROR;
    }
    if (std::find(businessIds_.begin(), businessIds_.end(), businessId) == businessIds_.end()) {
        MMI_HILOGE("%{public}s not in the config file", businessId.c_str());
        return PARAMETER_ERROR;
    }
    if (delay < MIN_SHORT_KEY_DOWN_DURATION || delay > MAX_SHORT_KEY_DOWN_DURATION) {
        MMI_HILOGE("Delay is not in valid range");
        return PARAMETER_ERROR;
    }
    return PREFERENCES_MGR->SetShortKeyDuration(businessId, delay);
}

KnuckleGesture KeyCommandHandler::GetSingleKnuckleGesture() const
{
    return singleKnuckleGesture_;
}

KnuckleGesture KeyCommandHandler::GetDoubleKnuckleGesture() const
{
    return doubleKnuckleGesture_;
}

void KeyCommandHandler::SetKnuckleDoubleTapDistance(float distance)
{
    CALL_DEBUG_ENTER;
    if (distance <= std::numeric_limits<float>::epsilon()) {
        MMI_HILOGE("Invalid distance:%{public}f", distance);
        return;
    }
    downToPrevDownDistanceConfig_ = distance;
}

bool KeyCommandHandler::CheckInputMethodArea(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(touchEvent);
    int32_t id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    int32_t targetWindowId = item.GetTargetWindowId();
    int32_t targetDisplayId = touchEvent->GetTargetDisplayId();
    auto window = WIN_MGR->GetWindowAndDisplayInfo(targetWindowId, targetDisplayId);
    if (!window || (window->windowType != WINDOW_INPUT_METHOD_TYPE && window->windowType != WINDOW_SCREENSHOT_TYPE)) {
            return false;
    }
    return true;
}

void KeyCommandHandler::Dump(int32_t fd, const std::vector<std::string> &args)
{
    static const std::unordered_map<int32_t, std::string> actionMap = { {0, "UNKNOWN"},
        {1, "CANCEL"}, {2, "DOWN"}, {3, "UP"} };
    CALL_DEBUG_ENTER;
    mprintf(fd, "----------------------------- ShortcutKey information ----------------------------\t");
    mprintf(fd, "ShortcutKey: count = %zu", shortcutKeys_.size());
    for (const auto &item : shortcutKeys_) {
        auto &shortcutKey = item.second;
        for (const auto &prekey : shortcutKey.preKeys) {
            mprintf(fd, "PreKey:%d", prekey);
        }
        mprintf(fd,
            "BusinessId: %s | StatusConfig: %s | StatusConfigValue: %s "
            "| FinalKey: %d | keyDownDuration: %d | TriggerType: %d | BundleName: %s | AbilityName: %s "
            "| Action: %s \t", shortcutKey.businessId.c_str(), shortcutKey.statusConfig.c_str(),
            shortcutKey.statusConfigValue ? "true" : "false", shortcutKey.finalKey, shortcutKey.keyDownDuration,
            shortcutKey.triggerType, shortcutKey.ability.bundleName.c_str(), shortcutKey.ability.abilityName.c_str(),
            shortcutKey.ability.action.c_str());
    }
    mprintf(fd, "-------------------------- Sequence information ----------------------------------\t");
    mprintf(fd, "Sequence: count = %zu", sequences_.size());
    for (const auto &item : sequences_) {
        for (const auto& sequenceKey : item.sequenceKeys) {
            mprintf(fd, "keyCode: %d | keyAction: %s",
                sequenceKey.keyCode, ConvertKeyActionToString(sequenceKey.keyAction).c_str());
        }
        mprintf(fd, "BundleName: %s | AbilityName: %s | Action: %s ",
            item.ability.bundleName.c_str(), item.ability.abilityName.c_str(), item.ability.action.c_str());
    }
    mprintf(fd, "-------------------------- ExcludeKey information --------------------------------\t");
    mprintf(fd, "ExcludeKey: count = %zu", excludeKeys_.size());
    for (const auto &item : excludeKeys_) {
        mprintf(fd, "keyCode: %d | keyAction: %s", item.keyCode, ConvertKeyActionToString(item.keyAction).c_str());
    }
    mprintf(fd, "-------------------------- RepeatKey information ---------------------------------\t");
    mprintf(fd, "RepeatKey: count = %zu", repeatKeys_.size());
    for (const auto &item : repeatKeys_) {
        mprintf(fd,
            "KeyCode: %d | KeyAction: %s | Times: %d"
            "| StatusConfig: %s | StatusConfigValue: %s | BundleName: %s | AbilityName: %s"
            "| Action:%s \t", item.keyCode, ConvertKeyActionToString(item.keyAction).c_str(), item.times,
            item.statusConfig.c_str(), item.statusConfigValue ? "true" : "false",
            item.ability.bundleName.c_str(), item.ability.abilityName.c_str(), item.ability.action.c_str());
    }
    PrintGestureInfo(fd);
}

void KeyCommandHandler::PrintGestureInfo(int32_t fd)
{
    mprintf(fd, "-------------------------- TouchPad Two Fingers Gesture --------------------------\t");
    mprintf(fd,
        "GestureActive: %s | GestureBundleName: %s | GestureAbilityName: %s"
        "| GestureAction: %s \t", twoFingerGesture_.active ? "true" : "false",
        twoFingerGesture_.ability.bundleName.c_str(), twoFingerGesture_.ability.abilityName.c_str(),
        twoFingerGesture_.ability.action.c_str());
    mprintf(fd, "-------------------------- TouchPad Three Fingers Tap Gesture --------------------\t");
    mprintf(fd,
        "TapBundleName: %s | TapAbilityName: %s"
        "| TapAction: %s \t", threeFingersTap_.ability.bundleName.c_str(),
        threeFingersTap_.ability.abilityName.c_str(), threeFingersTap_.ability.action.c_str());
    mprintf(fd, "-------------------------- Knuckle Single Finger Gesture -------------------------\t");
    mprintf(fd,
        "GestureState: %s | GestureBundleName: %s | GestureAbilityName: %s"
        "| GestureAction: %s \t", singleKnuckleGesture_.state ? "true" : "false",
        singleKnuckleGesture_.ability.bundleName.c_str(), singleKnuckleGesture_.ability.abilityName.c_str(),
        singleKnuckleGesture_.ability.action.c_str());
    mprintf(fd, "-------------------------- Knuckle Two Fingers Gesture ---------------------------\t");
    mprintf(fd,
        "GestureState: %s | GestureBundleName: %s | GestureAbilityName: %s"
        "| GestureAction:%s \t", doubleKnuckleGesture_.state ? "true" : "false",
        doubleKnuckleGesture_.ability.bundleName.c_str(), doubleKnuckleGesture_.ability.abilityName.c_str(),
        doubleKnuckleGesture_.ability.action.c_str());
}
std::string KeyCommandHandler::ConvertKeyActionToString(int32_t keyAction)
{
    static const std::unordered_map<int32_t, std::string> actionMap = {
        {0, "UNKNOWN"},
        {1, "CANCEL"},
        {2, "DOWN"},
        {3, "UP"}
    };
    auto it = actionMap.find(keyAction);
    if (it != actionMap.end()) {
        return it->second;
    } else {
        return "UNKNOWN_ACTION";
    }
}
std::ostream& operator<<(std::ostream& os, const Sequence& seq)
{
    os << "keys: [";
    for (const SequenceKey &singleKey: seq.sequenceKeys) {
        os << "(kc:" << singleKey.keyCode << ",ka:" << singleKey.keyAction << ",d:" << singleKey.delay << "),";
    }
    os << "]: " << seq.ability.bundleName << ":" << seq.ability.abilityName;
    return os;
}

void KeyCommandHandler::CheckAndUpdateTappingCountAtDown(std::shared_ptr<PointerEvent> touchEvent)
{
    CHKPV(touchEvent);
    int64_t currentDownTime = touchEvent->GetActionTime();
    int64_t downIntervalTime = currentDownTime - lastDownTime_;
    lastDownTime_ = currentDownTime;
    if (downIntervalTime <= 0 || downIntervalTime >= TAP_DOWN_INTERVAL_MILLIS) {
        tappingCount_ = 1;
        return;
    }
    tappingCount_++;
    int64_t timeDiffToPrevKnuckleUpTime = currentDownTime - previousUpTime_;
    if (timeDiffToPrevKnuckleUpTime <= DOUBLE_CLICK_INTERVAL_TIME_SLOW) {
        if (tappingCount_ == MAX_TAP_COUNT) {
            DfxHisysevent::ReportFailIfOneSuccTwoFail(touchEvent);
        }
        if (tappingCount_ > MAX_TAP_COUNT) {
            DfxHisysevent::ReportFailIfKnockTooFast();
        }
    }
}

bool KeyCommandHandler::TouchPadKnuckleDoubleClickHandle(std::shared_ptr<KeyEvent> event)
{
    CHKPF(event);
    auto actionType = event->GetKeyAction();
    if (actionType == KNUCKLE_1F_DOUBLE_CLICK) {
        TouchPadKnuckleDoubleClickProcess(PC_PRO_SCREENSHOT_BUNDLE_NAME,
            PC_PRO_SCREENSHOT_ABILITY_NAME, "single_knuckle");
        return true;
    }
    if (actionType == KNUCKLE_2F_DOUBLE_CLICK) {
        TouchPadKnuckleDoubleClickProcess(PC_PRO_SCREENRECORDER_BUNDLE_NAME,
            PC_PRO_SCREENRECORDER_ABILITY_NAME, "double_knuckle");
        return true;
    }
    return false;
}

void KeyCommandHandler::TouchPadKnuckleDoubleClickProcess(const std::string bundleName,
    const std::string abilityName, const std::string action)
{
    std::string screenStatus = DISPLAY_MONITOR->GetScreenStatus();
    bool isScreenLocked = DISPLAY_MONITOR->GetScreenLocked();
    if (screenStatus == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF || isScreenLocked) {
        MMI_HILOGI("The current screen is not in the unlocked state with the screen on");
        return;
    }
    Ability ability;
    ability.bundleName = bundleName;
    ability.abilityName = abilityName;
    ability.params.emplace(std::make_pair("trigger_type", action));
    LaunchAbility(ability, NO_DELAY);
}

bool KeyCommandHandler::ParseLongPressConfig()
{
    std::string configPath = "/system/variant/phone/base/etc/multimodalinput/universal_drag_app_whitelist.json";
    return ParseLongPressJson(configPath);
}

bool KeyCommandHandler::ParseLongPressJson(const std::string &configFile)
{
    CALL_DEBUG_ENTER;
    std::string jsonStr = ReadJsonFile(configFile);
    if (jsonStr.empty()) {
        MMI_HILOGE("Read configFile failed");
        return false;
    }
    JsonParser parser;
    parser.json_ = cJSON_Parse(jsonStr.c_str());
    if (!cJSON_IsObject(parser.json_)) {
        MMI_HILOGE("Parser.json_ is not object");
        return false;
    }

    cJSON* item = nullptr;
    cJSON* enable = nullptr;
    cJSON* status = nullptr;
    cJSON_ArrayForEach(item, parser.json_) {
        if (!cJSON_IsObject(item)) {
            continue;
        }
        enable = cJSON_GetObjectItem(item, KEY_ENABLE);
        status = cJSON_GetObjectItem(item, KEY_STATUS);
        if (enable == NULL || status == NULL) {
            continue;
        }
        if (enable->valueint == 1) {
            appWhiteList_.insert(item->string);
        }
    }
    return true;
}

bool KeyCommandHandler::CheckBundleName(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    if (!isParseLongPressConfig_) {
        MMI_HILOGE("Parse configFile failed");
        return false;
    }
    int32_t windowPid = WIN_MGR->GetWindowPid(touchEvent->GetTargetWindowId());
    if (windowPid == RET_ERR) {
        MMI_HILOGE("Get window pid failed");
        return false;
    }

    std::string bundleName;
    if (LONG_PRESS_EVENT_HANDLER->GetBundleName(bundleName, windowPid) == RET_ERR) {
        MMI_HILOGE("Failed to get bundle name, pid %{public}d", windowPid);
        return false;
    }
    if (appWhiteList_.find(bundleName) == appWhiteList_.end()) {
        MMI_HILOGE("The app does not support long-press drag., bundle name:%{public}s", bundleName.c_str());
        return false;
    }
    return true;
}

void KeyCommandHandler::OnKunckleSwitchStatusChange(const std::string switchName)
{
#ifdef OHOS_BUILD_ENABLE_ANCO
    if (switchName != SNAPSHOT_KNUCKLE_SWITCH && switchName != RECORD_KNUCKLE_SWITCH) {
        return;
    }
    bool isKnuckleEnable = !SkipKnuckleDetect();
    int32_t ret = WIN_MGR->SyncKnuckleStatus(isKnuckleEnable);
    if (ret != RET_OK) {
        MMI_HILOGE("sync knuckle status error., ret:%{public}d", ret);
    }
#endif // OHOS_BUILD_ENABLE_ANCO
}

bool KeyCommandHandler::MenuClickHandle(std::shared_ptr<KeyEvent> event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    auto keycode = event->GetKeyCode();
    if (keycode != KeyEvent::KEYCODE_MENU) {
        return false;
    }
    auto actionType = event->GetKeyAction();
    if ((actionType == KeyEvent::KEY_ACTION_DOWN) && (!existMenuDown_)) {
        lastMenuDownTime_ = OHOS::MMI::GetSysClockTime();
        existMenuDown_ = true;
        tmpkeyEvent_ = KeyEvent::Clone(event);
        return true;
    } else if ((actionType == KeyEvent::KEY_ACTION_UP) && existMenuDown_) {
        auto time = OHOS::MMI::GetSysClockTime();
        auto duration = (time - lastMenuDownTime_);
        lastMenuDownTime_ = 0;
        existMenuDown_ = false;
        if (duration >= (MENU_KEY_DOWN_DELAY*TIME_CONVERSION_UNIT)) {
            MMI_HILOGD("Key menu long press, send bundlname to TV");
            tmpkeyEvent_.reset();
            MenuClickProcess(TV_MENU_BUNDLE_NAME, TV_MENU_ABILITY_NAME, "key_menu_longpress");
            return true;
        } else {
            MMI_HILOGD("Key menu short press.");
            if (tmpkeyEvent_) {
                SendSaveEvent(tmpkeyEvent_);
            }
            return false;
        }
    } else {
        return false;
    }
}

void KeyCommandHandler::SendSaveEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    if (OnHandleEvent(keyEvent)) {
        if (DISPLAY_MONITOR->GetScreenStatus() == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
            auto monitorHandler = InputHandler->GetMonitorHandler();
            CHKPV(monitorHandler);
            keyEvent->SetFourceMonitorFlag(true);
#ifndef OHOS_BUILD_EMULATOR
            monitorHandler->OnHandleEvent(keyEvent);
#endif // OHOS_BUILD_EMULATOR
            keyEvent->SetFourceMonitorFlag(false);
        }
        MMI_HILOGD("The keyEvent start launch an ability, keyCode:%{private}d", keyEvent->GetKeyCode());
        BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::KEY_LAUNCH_EVENT);
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandleKeyEvent(keyEvent);
}

void KeyCommandHandler::MenuClickProcess(const std::string bundleName,
                                         const std::string abilityName, const std::string action)
{
    CALL_DEBUG_ENTER;
    std::string screenStatus = DISPLAY_MONITOR->GetScreenStatus();
    bool isScreenLocked = DISPLAY_MONITOR->GetScreenLocked();
    if (screenStatus == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF || isScreenLocked) {
        MMI_HILOGE("The current screen is not in the unlocked state with the screen on");
        return;
    }
    Ability ability;
    ability.bundleName = bundleName;
    ability.abilityName = abilityName;
    ability.params.emplace(std::make_pair("trigger_type", action));
    LaunchAbility(ability, NO_DELAY);
}

void KeyCommandHandler::RegisterProximitySensor()
{
    CALL_INFO_TRACE;
    g_user.callback = SensorDataCallbackImpl;
    int32_t ret = SubscribeSensor(SENSOR_TYPE_ID_PROXIMITY, &g_user);
    if (ret != 0) {
        MMI_HILOGE("Failed to SubscribeSensor: %{public}d ret:%{public}d", SENSOR_TYPE_ID_PROXIMITY, ret);
        return;
    }
    ret = SetBatch(SENSOR_TYPE_ID_PROXIMITY, &g_user, SENSOR_SAMPLING_INTERVAL, SENSOR_REPORT_INTERVAL);
    if (ret != 0) {
        MMI_HILOGE("Failed to SetBatch: %{public}d ret:%{public}d", SENSOR_TYPE_ID_PROXIMITY, ret);
        return;
    }
    ret = ActivateSensor(SENSOR_TYPE_ID_PROXIMITY, &g_user);
    if (ret != 0) {
        MMI_HILOGE("Failed to ActivateSensor: %{public}d ret:%{public}d", SENSOR_TYPE_ID_PROXIMITY, ret);
    }
}

int32_t KeyCommandHandler::SetKnuckleSwitch(bool knuckleSwitch)
{
    gameForbidFingerKnuckle_ = !knuckleSwitch;
    MMI_HILOGI("SetKnuckleSwitch is successful in keyCommand handler, knuckleSwitch:%{public}d", knuckleSwitch);
    return RET_OK;
}

int32_t KeyCommandHandler::CheckTwoFingerGesture(int32_t pid)
{
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    int64_t milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    int64_t timeOut = milliseconds - twoFingerGesture_.startTime;
    if (twoFingerGesture_.touchEvent == nullptr) {
        MMI_HILOGE("twoFingerGesture_.touchEvent == nullptr");
        return RET_ERR;
    }
    if (timeOut > SCREEN_TIME_OUT) {
        MMI_HILOGE("Double finger press timeout");
        return RET_ERR;
    }

    if ((twoFingerGesture_.windowId < 0) || (twoFingerGesture_.touchEvent->GetTargetWindowId() !=
        twoFingerGesture_.windowId)) {
        MMI_HILOGE("Window changefocusWindowId:%{public}d, twoFingerGesture_.focusWindowId:%{public}d",
            twoFingerGesture_.touchEvent->GetTargetWindowId(), twoFingerGesture_.windowId);
        return RET_ERR;
    }

    if (twoFingerGesture_.windowPid != pid) {
        MMI_HILOGE("twoFingerGesture_.windowPid:%{public}d, pid:%{public}d", twoFingerGesture_.windowPid, pid);
        return RET_ERR;
    }

    if (!twoFingerGesture_.longPressFlag) {
        MMI_HILOGE("The long press state is not set");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t KeyCommandHandler::LaunchAiScreenAbility(int32_t pid)
{
    if (CheckTwoFingerGesture(pid) != RET_OK) {
        twoFingerGesture_.startTime = 0;
        twoFingerGesture_.longPressFlag = false;
        twoFingerGesture_.windowId = -1;
        twoFingerGesture_.windowPid = -1;
        return RET_ERR;
    }

    MMI_HILOGE("Start launch ai screen ability immediately");
    BytraceAdapter::StartLaunchAbility(KeyCommandType::TYPE_MULTI_FINGERS, twoFingerGesture_.ability.bundleName);
    LaunchAbility(twoFingerGesture_.ability, twoFingerGesture_.abilityStartDelay);
    BytraceAdapter::StopLaunchAbility();

    twoFingerGesture_.startTime = 0;
    twoFingerGesture_.longPressFlag = false;
    twoFingerGesture_.windowId = -1;
    twoFingerGesture_.windowPid = -1;
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
