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

#include "event_statistic.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventStatistic"

namespace OHOS {
namespace MMI {
namespace {
const char* EVENT_FILE_NAME = "/data/service/el1/public/multimodalinput/multimodal_event.dmp";
const char* EVENT_FILE_NAME_HISTORY = "/data/service/el1/public/multimodalinput/multimodal_event_history.dmp";
constexpr int32_t FILE_MAX_SIZE = 100 * 1024 * 1024;
constexpr int32_t EVENT_OUT_SIZE = 30;
constexpr int32_t FUNC_EXE_OK = 0;
constexpr int32_t STRING_WIDTH = 3;
constexpr int32_t POINTER_RECORD_MAX_SIZE = 100;
}

std::queue<std::string> EventStatistic::eventQueue_;
std::list<std::string> EventStatistic::dumperEventList_;
std::mutex EventStatistic::queueMutex_;
std::condition_variable EventStatistic::queueCondition_;
std::deque<EventStatistic::PointerEventRecord> EventStatistic::pointerRecordDeque_;
std::mutex EventStatistic::dequeMutex_;
bool EventStatistic::writeFileEnabled_ = false;
static const std::unordered_map<int32_t, std::string> pointerActionMap = {
    { PointerEvent::POINTER_ACTION_CANCEL, "cancel" },
    { PointerEvent::POINTER_ACTION_DOWN, "down" },
    { PointerEvent::POINTER_ACTION_MOVE, "move" },
    { PointerEvent::POINTER_ACTION_UP, "up" },
    { PointerEvent::POINTER_ACTION_AXIS_BEGIN, "axis-begin" },
    { PointerEvent::POINTER_ACTION_AXIS_UPDATE, "axis-update" },
    { PointerEvent::POINTER_ACTION_AXIS_END, "axis-end" },
    { PointerEvent::POINTER_ACTION_BUTTON_DOWN, "button-down" },
    { PointerEvent::POINTER_ACTION_BUTTON_UP, "button-up" },
    { PointerEvent::POINTER_ACTION_ENTER_WINDOW, "enter-window" },
    { PointerEvent::POINTER_ACTION_LEAVE_WINDOW, "leave-window" },
    { PointerEvent::POINTER_ACTION_PULL_DOWN, "pull-down" },
    { PointerEvent::POINTER_ACTION_PULL_MOVE, "pull-move" },
    { PointerEvent::POINTER_ACTION_PULL_UP, "pull-up" },
    { PointerEvent::POINTER_ACTION_PULL_IN_WINDOW, "pull-in-window" },
    { PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW, "pull-out-window" },
    { PointerEvent::POINTER_ACTION_SWIPE_BEGIN, "swipe-begin" },
    { PointerEvent::POINTER_ACTION_SWIPE_UPDATE, "swipe-update" },
    { PointerEvent::POINTER_ACTION_SWIPE_END, "swipe-end" },
    { PointerEvent::POINTER_ACTION_ROTATE_BEGIN, "rotate-begin" },
    { PointerEvent::POINTER_ACTION_ROTATE_UPDATE, "rotate-update" },
    { PointerEvent::POINTER_ACTION_ROTATE_END, "rotate-end" },
    { PointerEvent::POINTER_ACTION_TRIPTAP, "touchpad-triptap" },
    { PointerEvent::POINTER_ACTION_QUADTAP, "quadtap" },
    { PointerEvent::POINTER_ACTION_HOVER_MOVE, "hover-move" },
    { PointerEvent::POINTER_ACTION_HOVER_ENTER, "hover-enter" },
    { PointerEvent::POINTER_ACTION_HOVER_EXIT, "hover-exit" },
    { PointerEvent::POINTER_ACTION_FINGERPRINT_DOWN, "fingerprint-down" },
    { PointerEvent::POINTER_ACTION_FINGERPRINT_UP, "fingerprint-up" },
    { PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE, "fingerprint-slide" },
    { PointerEvent::POINTER_ACTION_FINGERPRINT_RETOUCH, "fingerprint-retouch" },
    { PointerEvent::POINTER_ACTION_FINGERPRINT_CLICK, "fingerprint-click" },
    { PointerEvent::POINTER_ACTION_FINGERPRINT_HOLD, "fingerprint-hold" },
    { PointerEvent::POINTER_ACTION_FINGERPRINT_TOUCH, "fingerprint-touch" },
    { PointerEvent::TOUCH_ACTION_SWIPE_DOWN, "touch-swipe-down" },
    { PointerEvent::TOUCH_ACTION_SWIPE_UP, "touch-swipe-up" },
    { PointerEvent::TOUCH_ACTION_SWIPE_LEFT, "touch-swipe-left" },
    { PointerEvent::TOUCH_ACTION_SWIPE_RIGHT, "touch-swipe-right" },
    { PointerEvent::TOUCH_ACTION_PINCH_OPENED, "touch-pinch-open" },
    { PointerEvent::TOUCH_ACTION_PINCH_CLOSEED, "touch-pinch-close" },
    { PointerEvent::TOUCH_ACTION_GESTURE_END, "touch-gesture-end" },
    { PointerEvent::POINTER_ACTION_PROXIMITY_IN, "pen-proximity-in" },
    { PointerEvent::POINTER_ACTION_PROXIMITY_OUT, "pen-proximity-out" },
};
static const std::unordered_map<int32_t, std::string> keyActionMap = {
    { KeyEvent::KEY_ACTION_UNKNOWN, "key_action_unknown" },
    { KeyEvent::KEY_ACTION_CANCEL, "key_action_cancel" },
    { KeyEvent::KEY_ACTION_DOWN, "key_action_down" },
    { KeyEvent::KEY_ACTION_UP, "key_action_up" },
};

std::string EventStatistic::ConvertInputEventToStr(const std::shared_ptr<InputEvent> eventPtr)
{
    auto nowTime = std::chrono::system_clock::now();
    std::time_t timeT = std::chrono::system_clock::to_time_t(nowTime);
    auto milsecsCount = std::chrono::duration_cast<std::chrono::milliseconds>(nowTime.time_since_epoch()).count();
    std::string handleTime = ConvertTimeToStr(static_cast<int64_t>(timeT));
    int32_t milsec = milsecsCount % 1000;
    std::stringstream strStream;
    strStream << std::left << std::setw(STRING_WIDTH) << milsec;
    std::string milsecStr(strStream.str());
    handleTime += "." + milsecStr;
    std::string eventStr = "{";
    eventStr += handleTime;
    eventStr += ",eventType:";
    eventStr += ConvertEventTypeToString(eventPtr->GetEventType());
    eventStr += ",actionTime:" + std::to_string(eventPtr->GetActionTime());
    eventStr += ",deviceId:" + std::to_string(eventPtr->GetDeviceId());
    eventStr += ",sourceType:";
    eventStr += ConvertSourceTypeToString(eventPtr->GetSourceType());
    return eventStr;
}

std::string EventStatistic::ConvertTimeToStr(int64_t timestamp)
{
    std::string timeStr = std::to_string(timestamp);
    std::time_t timeT = timestamp;
    std::tm tmInfo;
    localtime_r(&timeT, &tmInfo);
    char buffer[32] = {0};
    if (std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tmInfo) > 0) {
        timeStr = buffer;
    }
    return timeStr;
}

void EventStatistic::PushPointerEvent(std::shared_ptr<PointerEvent> eventPtr)
{
    CHKPV(eventPtr);
    PushPoniterRecord(eventPtr);
    int32_t pointerAction = eventPtr->GetPointerAction();
    if (pointerAction == PointerEvent::POINTER_ACTION_MOVE || pointerAction == PointerEvent::POINTER_ACTION_PULL_MOVE ||
        pointerAction == PointerEvent::POINTER_ACTION_HOVER_MOVE ||
        pointerAction == PointerEvent::POINTER_ACTION_AXIS_UPDATE ||
        pointerAction == PointerEvent::POINTER_ACTION_SWIPE_UPDATE ||
        pointerAction == PointerEvent::POINTER_ACTION_ROTATE_UPDATE) {
        MMI_HILOGD("PointEvent is filtered");
        return;
    }
    std::string eventStr = ConvertInputEventToStr(eventPtr);
    eventStr += ",pointerId:" + std::to_string(eventPtr->GetPointerId());
    eventStr += ",pointerAction:";
    eventStr += ConvertPointerActionToString(eventPtr);
    eventStr += ",buttonId:" + std::to_string(eventPtr->GetButtonId()) + ",pointers:[";
    size_t pointerSize = 0;
    std::list<PointerEvent::PointerItem> pointerItems = eventPtr->GetAllPointerItems();
    for (auto it = pointerItems.begin(); it != pointerItems.end(); it++) {
        std::string displayX = "***";
        std::string displayY = "***";
        pointerSize++;
        if (!eventPtr->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
            displayX = std::to_string((*it).GetDisplayX());
            displayY = std::to_string((*it).GetDisplayY());
        }
        eventStr += "{";
        eventStr += "displayX:" + displayX;
        eventStr += ",displayY:" + displayY;
        eventStr += ",pressure:" + std::to_string((*it).GetPressure());
        eventStr += "}";
        if (pointerSize != pointerItems.size()) {
            eventStr += ",";
        }
    }
    eventStr += "],pressedButtons:[";
    size_t buttonsSize = 0;
    std::set<int32_t> pressedButtons = eventPtr->GetPressedButtons();
    for (auto it = pressedButtons.begin(); it != pressedButtons.end(); it++) {
        buttonsSize++;
        eventStr += std::to_string(*it);
        if (buttonsSize != pressedButtons.size()) {
            eventStr += ",";
        }
    }
    eventStr += "]";
    eventStr += "}";
    PushEventStr(eventStr);
}

void EventStatistic::PushKeyEvent(std::shared_ptr<KeyEvent> eventPtr)
{
    CHKPV(eventPtr);
    std::string eventStr = ConvertInputEventToStr(eventPtr);
    std::string keyCode = "***";
    if (!eventPtr->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
        keyCode = std::to_string(eventPtr->GetKeyCode());
    }
    eventStr += ",keyCode:" + keyCode;
    eventStr += ",keyAction:";
    eventStr += ConvertKeyActionToString(eventPtr->GetKeyAction());
    auto keyItems = eventPtr->GetKeyItems();
    eventStr += ",keyItems:[";
    for (size_t i = 0; i < keyItems.size(); i++) {
        std::string keyItemCode = "***";
        int32_t pressed = keyItems[i].IsPressed() ? 1 : 0;
        if (!eventPtr->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
            keyItemCode = std::to_string(keyItems[i].GetKeyCode());
        }
        eventStr += "{pressed:" + std::to_string(pressed);
        eventStr += ",deviceId:" + std::to_string(keyItems[i].GetDeviceId());
        eventStr += ",keyCode:" + keyItemCode;
        eventStr += ",downTime:" + std::to_string(keyItems[i].GetDownTime());
        eventStr += ",unicode:" + std::to_string(keyItems[i].GetUnicode()) + "}";
        if (i != keyItems.size() - 1) {
            eventStr += ",";
        }
    }
    eventStr += "]";
    eventStr += "}";
    PushEventStr(eventStr);
}

void EventStatistic::PushSwitchEvent(std::shared_ptr<SwitchEvent> eventPtr)
{
    CHKPV(eventPtr);
    std::string eventStr = ConvertInputEventToStr(eventPtr);
    eventStr += ",switchValue:" + std::to_string(eventPtr->GetSwitchValue());
    eventStr += ",switchType:";
    eventStr += ConvertSwitchTypeToString(eventPtr->GetSwitchType());
    eventStr += "}";
    PushEventStr(eventStr);
}

void EventStatistic::PushEventStr(std::string eventStr)
{
    std::lock_guard<std::mutex> lock(queueMutex_);
    dumperEventList_.push_back(eventStr);
    if (dumperEventList_.size() > EVENT_OUT_SIZE) {
        dumperEventList_.pop_front();
    }
    if (writeFileEnabled_) {
        eventQueue_.push(eventStr);
        queueCondition_.notify_all();
    }
}

void EventStatistic::PushPointerRecord(std::shared_ptr<PointerEvent> eventPtr)
{
    std::list<PointerEvent::PointerItem> pointerItems = eventPtr->GetAllPointerItems();
    std::vector<double> pressures;
    std::vector<double> tiltXs;
    std::vector<double> tiltYs;
    for (auto it = pointerItems.begin(); it != pointerItems.end(); ++it) {
        pressures.push_back(it->GetPressure());
        tiltXs.push_back(it->GetTiltX());
        tiltYs.push_back(it->GetTiltY());
    }
    pointerRecordDeque_.emplace_back(eventPtr->GetActionTime(),
        eventPtr->GetSourceType(),
        eventPtr->HasFlag(InputEvent::EVENT_FLAG_SIMULATE),
        pressures,
        tiltXs,
        tiltYs);
    if (pointerRecordDeque_.size() > POINTER_RECORD_MAX_SIZE) {
        pointerRecordDeque_.pop_front();
    }
}

int32_t EventStatistic::QueryPointerRecord(int32_t count, std::vector<std::shared_ptr<PointerEvent>> &pointerList)
{
    if (count <= 0 || pointerRecordDeque_.empty()) {
        MMI_HILOGD("Return pointerList is empty");
        return RET_OK;
    }
    count = std::min(count, static_cast<int32_t>(pointerRecordDeque_.size()));
    for (auto it = pointerRecordDeque_.end() - count; it != pointerRecordDeque_.end(); ++it) {
        auto pointerEvent = PointerEvent::Create();
        pointerEvent->SetActionTime(it->actionTime);
        pointerEvent->SetSourceType(it->sourceType);
        if (it->isInject) {
            pointerEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);
        }
        for (auto pressuresIt = it->pressures.begin(), tiltXsIt = it->tiltXs.begin(), tiltYsIt = it->tiltYs.begin();
             pressuresIt != it->pressures.end() && tiltXsIt != it->tiltXs.end() && tiltYsIt != it->tiltYs.end();
             ++pressuresIt, ++tiltXsIt, ++tiltYsIt) {
            PointerEvent::PointerItem pointerItem;
            pointerItem.SetPressure(*pressuresIt);
            pointerItem.SetTiltX(*tiltXsIt);
            pointerItem.SetTiltY(*tiltYsIt);
            pointerEvent->AddPointerItem(pointerItem);
        }
        pointerList.push_back(pointerEvent);
    }
    return RET_OK;
}

std::string EventStatistic::PopEvent()
{
    std::unique_lock<std::mutex> lock(queueMutex_);
    if (eventQueue_.empty()) {
        queueCondition_.wait(lock, []() { return !eventQueue_.empty(); });
    }
    std::string eventStr = eventQueue_.front();
    eventQueue_.pop();
    return eventStr;
}

void EventStatistic::WriteEventFile()
{
    while (writeFileEnabled_) {
        std::string eventStr = PopEvent();
        struct stat statbuf;
        int32_t fileSize = 0;
        if (stat(EVENT_FILE_NAME, &statbuf) == FUNC_EXE_OK) {
            fileSize = static_cast<int32_t>(statbuf.st_size);
        }
        if (fileSize >= FILE_MAX_SIZE) {
            if (access(EVENT_FILE_NAME_HISTORY, F_OK) == FUNC_EXE_OK &&
                remove(EVENT_FILE_NAME_HISTORY) != FUNC_EXE_OK) {
                MMI_HILOGE("Remove history file failed");
            }
            if (rename(EVENT_FILE_NAME, EVENT_FILE_NAME_HISTORY) != FUNC_EXE_OK) {
                MMI_HILOGE("Rename file failed");
            }
        }
        std::ofstream file(EVENT_FILE_NAME, std::ios::app);
        if (file.is_open()) {
            file << eventStr << std::endl;
            file.close();
        } else {
            MMI_HILOGE("Open file failed");
        }
    }
}

void EventStatistic::Dump(int32_t fd, const std::vector<std::string> &args)
{
    std::lock_guard<std::mutex> lock(queueMutex_);
    for (auto it = dumperEventList_.begin(); it != dumperEventList_.end(); ++it) {
        mprintf(fd, (*it).c_str());
    }
}

const char* EventStatistic::ConvertEventTypeToString(int32_t eventType)
{
    switch (eventType) {
        case InputEvent::EVENT_TYPE_BASE: {
            return "base";
        }
        case InputEvent::EVENT_TYPE_KEY: {
            return "key";
        }
        case InputEvent::EVENT_TYPE_POINTER: {
            return "pointer";
        }
        case InputEvent::EVENT_TYPE_AXIS: {
            return "axis";
        }
        case InputEvent::EVENT_TYPE_FINGERPRINT: {
            return "fingerprint";
        }
        default: {
            MMI_HILOGW("Unknown EventType");
            return "unknown";
        }
    }
}
 
const char* EventStatistic::ConvertSourceTypeToString(int32_t sourceType)
{
    switch (sourceType) {
        case InputEvent::SOURCE_TYPE_MOUSE: {
            return "mouse";
        }
        case InputEvent::SOURCE_TYPE_TOUCHSCREEN: {
            return "touch-screen";
        }
        case InputEvent::SOURCE_TYPE_TOUCHPAD: {
            return "touch-pad";
        }
        case InputEvent::SOURCE_TYPE_JOYSTICK: {
            return "joystick";
        }
        case InputEvent::SOURCE_TYPE_FINGERPRINT: {
            return "fingerprint";
        }
        case InputEvent::SOURCE_TYPE_CROWN: {
            return "crown";
        }
        default: {
            MMI_HILOGW("Unknown SourceType");
            return "unknown";
        }
    }
}
 
const char* EventStatistic::ConvertPointerActionToString(std::shared_ptr<PointerEvent> eventPtr)
{
    int32_t pointerAction = eventPtr->GetPointerAction();
    int32_t axes = eventPtr->GetAxes();
    if (pointerAction == PointerEvent::POINTER_ACTION_AXIS_BEGIN) {
        if (PointerEvent::HasAxis(axes, PointerEvent::AXIS_TYPE_SCROLL_VERTICAL) ||
            PointerEvent::HasAxis(axes, PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)) {
            return "axis-begin";
        } else if (PointerEvent::HasAxis(axes, PointerEvent::AXIS_TYPE_PINCH)) {
            return "pinch-begin";
        }
    } else if (pointerAction == PointerEvent::POINTER_ACTION_AXIS_UPDATE) {
        if (PointerEvent::HasAxis(axes, PointerEvent::AXIS_TYPE_SCROLL_VERTICAL) ||
            PointerEvent::HasAxis(axes, PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)) {
            return "axis-update";
        } else if (PointerEvent::HasAxis(axes, PointerEvent::AXIS_TYPE_PINCH)) {
            return "pinch-update";
        }
    } else if (pointerAction == PointerEvent::POINTER_ACTION_AXIS_END) {
        if (PointerEvent::HasAxis(axes, PointerEvent::AXIS_TYPE_SCROLL_VERTICAL) ||
            PointerEvent::HasAxis(axes, PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)) {
            return "axis-end";
        } else if (PointerEvent::HasAxis(axes, PointerEvent::AXIS_TYPE_PINCH)) {
            return "pinch-end";
        }
    }
    auto it = pointerActionMap.find(pointerAction);
    if (it != pointerActionMap.end()) {
        return it->second.c_str();
    }
    return "unknown";
}
 
const char* EventStatistic::ConvertKeyActionToString(int32_t keyAction)
{
    auto it = keyActionMap.find(keyAction);
    if (it != keyActionMap.end()) {
        return it->second.c_str();
    }
    return "unknown";
}
 
const char* EventStatistic::ConvertSwitchTypeToString(int32_t switchType)
{
    switch (switchType) {
        case SwitchEvent::SWITCH_DEFAULT: {
            return "switch_default";
        }
        case SwitchEvent::SWITCH_LID: {
            return "switch_lid";
        }
        case SwitchEvent::SWITCH_TABLET: {
            return "switch_tablet";
        }
        case SwitchEvent::SWITCH_PRIVACY: {
            return "switch_privacy";
        }
        default: {
            MMI_HILOGW("Unknown SwitchType");
            return "unknown";
        }
    }
}
} // namespace MMI
} // namespace OHOS