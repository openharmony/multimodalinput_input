/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "register_event.h"
#include <cmath>
#include "input-event-codes.h"
#include "system_event_handler.h"

namespace OHOS {
namespace MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "RegisterEvent" };
    }
struct GetModeCode {
    int32_t keystate;
    uint32_t keyCode;
    int32_t modCode;
};
struct GetTaskCode {
    int32_t signCode;
    int32_t bitCode;
};
struct EventHandle {
    uint32_t keyCode;
    int32_t taskCode;
    MmiMessageId handler; // MmiMessageId
};

RegisterEvent::RegisterEvent()
{
    gestureInfo_.enabled = false;
    key_ = {};
}

RegisterEvent::~RegisterEvent()
{
}

void RegisterEvent::OnEventKeyGetSign(const EventKeyboard& key, MmiMessageId& msg, EventKeyboard& prevKey)
{
    CHK((key.state == 0) || (key.state == BIT1), PARAM_INPUT_INVALID);
    int32_t temp = modTask_;
    GetModeCode getModeCode[] = {
        {RELEASE, KEY_LEFTMETA, BIT0},
        {RELEASE, KEY_LEFTCTRL, BIT1},
        {RELEASE, KEY_RIGHTCTRL, BIT2},
        {RELEASE, KEY_LEFTALT, BIT3},
        {RELEASE, KEY_RIGHTALT, BIT4},
        {RELEASE, KEY_LEFTSHIFT, BIT5},
        {RELEASE, KEY_RIGHTSHIFT, BIT6},
        {PRESS, KEY_LEFTMETA, BIT0},
        {PRESS, KEY_LEFTCTRL, BIT1},
        {PRESS, KEY_RIGHTCTRL, BIT2},
        {PRESS, KEY_LEFTALT, BIT3},
        {PRESS, KEY_RIGHTALT, BIT4},
        {PRESS, KEY_LEFTSHIFT, BIT5},
        {PRESS, KEY_RIGHTSHIFT, BIT6},
    };
    GetTaskCode taskCode[] = {
        {GetBitNum(BIT0), BIT0},
        {GetBitNum(BIT1) + GetBitNum(BIT2), BIT1},
        {GetBitNum(BIT3) + GetBitNum(BIT4), BIT2},
        {GetBitNum(BIT6) + GetBitNum(BIT5), BIT3},
    };
    int32_t ret = memcpy_s(&prevKey, sizeof(prevKey), &key, sizeof(key));
    CHK(ret == EOK, MEMCPY_SEC_FUN_FAIL);
    for (auto it : getModeCode) {
        if ((it.keystate == key.state) && (it.keyCode == key.key)) {
            if (key.state == KEY_STATE_RELEASED) {
                modMask_ = BitSetZero(modMask_, it.modCode);
            } else {
                modMask_ = BitSetOne(modMask_, it.modCode);
                ret = memcpy_s(&key_, sizeof(key_), &key, sizeof(key));
                CHK(ret == EOK, MEMCPY_SEC_FUN_FAIL);
            }
        }
    }
    for (auto it : taskCode) {
        if (modMask_ & it.signCode) {
            modTask_ = BitSetOne(modTask_, it.bitCode);
        } else {
            modTask_ = BitSetZero(modTask_, it.bitCode);
        }
    }
    if (temp != modTask_) {
        return;
    }
    if (key.state == KEY_STATE_PRESSED) {
        OnEventKeyJudge(key, msg, prevKey);
    }
}

bool RegisterEvent::OnGetRepeatKetState(const uint32_t keyCode, MmiMessageId& msgId)
{
    EventHandle taskCode[] = {
        {KEY_SCREENRECORD, BIT4, MmiMessageId::ON_STOP_SCREEN_RECORD},
        {KEY_VIDEO, BIT5, MmiMessageId::ON_STOP_SCREEN_RECORD}
    };
    for (auto it : taskCode) {
        if ((it.keyCode == keyCode) && (baseKey_ & GetBitNum(it.taskCode))) {
            baseKey_ = BitSetZero(baseKey_, it.taskCode);
            msgId = it.handler;
        } else if ((it.keyCode == keyCode) && (!(baseKey_ & GetBitNum(it.taskCode)))) {
            baseKey_ = BitSetOne(baseKey_, it.taskCode);
        }
    }
    return true;
}

int32_t RegisterEvent::SetPrevKeyValue(EventKeyboard& prevKey)
{
    prevKey.deviceType = key_.deviceType;
    prevKey.eventType = key_.eventType;
    prevKey.deviceId = key_.deviceId;
    int32_t ret = memcpy_s(prevKey.deviceName, sizeof(prevKey.deviceName), key_.deviceName,
                   sizeof(key_.deviceName));
    CHKR(ret == EOK, MEMCPY_SEC_FUN_FAIL, RET_ERR);
    ret = memcpy_s(prevKey.physical, sizeof(prevKey.physical), key_.physical,
                   sizeof(key_.physical));
    CHKR(ret == EOK, MEMCPY_SEC_FUN_FAIL, RET_ERR);
    return RET_OK;
}

int32_t RegisterEvent::OnEventKeyJudge(const EventKeyboard& key, MmiMessageId& msgId, EventKeyboard& prevKey)
{
    EventHandle eventHandle[] = {
        {KEY_SEARCH, 0, MmiMessageId::ON_SEARCH}, {KEY_PAUSE, 0, MmiMessageId::ON_PAUSE},
        {KEY_PLAY, 0, MmiMessageId::ON_PLAY}, {KEY_CHANNELUP, 0, MmiMessageId::ON_PREVIOUS},
        {KEY_CHANNELDOWN, 0, MmiMessageId::ON_NEXT}, {KEY_VOLUMEUP, 0, MmiMessageId::ON_PREVIOUS},
        {KEY_VOLUMEDOWN, 0, MmiMessageId::ON_NEXT}, {KEY_MENU, 0, MmiMessageId::ON_SHOW_MENU},
        {KEY_ASSISTANT, 0, MmiMessageId::ON_LAUNCH_VOICE_ASSISTANT}, {KEY_F11, 0, MmiMessageId::ON_SCREEN_SHOT},
        {KEY_S, (GetBitNum(BIT0) + GetBitNum(BIT3)), MmiMessageId::ON_SCREEN_SHOT},
        {KEY_S, GetBitNum(BIT0), MmiMessageId::ON_SEARCH}, {KEY_D, GetBitNum(BIT0), MmiMessageId::ON_GOTO_DESKTOP},
        {KEY_H, GetBitNum(BIT0), MmiMessageId::ON_GOTO_DESKTOP}, {KEY_TAB, GetBitNum(BIT2), MmiMessageId::ON_RECENT},
        {KEY_TAB, GetBitNum(BIT0), MmiMessageId::ON_RECENT},
        {KEY_N, GetBitNum(BIT0), MmiMessageId::ON_SHOW_NOTIFICATION},
        {KEY_L, GetBitNum(BIT0), MmiMessageId::ON_LOCK_SCREEN}, {KEY_F, GetBitNum(BIT1), MmiMessageId::ON_SEARCH},
        {KEY_F4, GetBitNum(BIT2), MmiMessageId::ON_CLOSE_PAGE}, {KEY_F4, 0, MmiMessageId::ON_MUTE},
        {KEY_W, GetBitNum(BIT1), MmiMessageId::ON_CLOSE_PAGE}, {KEY_PAGEUP, 0, MmiMessageId::ON_PREVIOUS},
        {KEY_PAGEDOWN, 0, MmiMessageId::ON_NEXT}, {KEY_R, GetBitNum(BIT1), MmiMessageId::ON_REFRESH},
        {KEY_F5, 0, MmiMessageId::ON_REFRESH}, {KEY_Z, GetBitNum(BIT1), MmiMessageId::ON_UNDO},
        {KEY_X, GetBitNum(BIT1), MmiMessageId::ON_CUT}, {KEY_C, GetBitNum(BIT1), MmiMessageId::ON_COPY},
        {KEY_V, GetBitNum(BIT1), MmiMessageId::ON_PASTE}, {KEY_F10, GetBitNum(BIT3), MmiMessageId::ON_SHOW_MENU},
        {KEY_F10, GetBitNum(BIT0) + GetBitNum(BIT3), MmiMessageId::ON_SHOW_MENU},
        {KEY_MENU, 0, MmiMessageId::ON_SHOW_MENU}, {KEY_VIDEO, 0, MmiMessageId::ON_START_SCREEN_RECORD},
        {KEY_VIDEO, 0, MmiMessageId::ON_STOP_SCREEN_RECORD}, {KEY_DOWN, 0, MmiMessageId::ON_NEXT},
        {KEY_P, GetBitNum(BIT1), MmiMessageId::ON_PRINT}, {KEY_UP, 0, MmiMessageId::ON_PREVIOUS},
        {KEY_LEFT, 0, MmiMessageId::ON_PREVIOUS}, {KEY_VOICECOMMAND, 0, MmiMessageId::ON_LAUNCH_VOICE_ASSISTANT},
        {KEY_COMPOSE, 0, MmiMessageId::ON_SHOW_MENU}, {KEY_RIGHT, 0, MmiMessageId::ON_NEXT},
        {KEY_HOMEPAGE, 0, MmiMessageId::ON_GOTO_DESKTOP}, {KEY_POWER, 0, MmiMessageId::ON_LOCK_SCREEN},
        {KEY_SEARCH, 0, MmiMessageId::ON_SEARCH}, {KEY_MULTITASK, 0, MmiMessageId::ON_SEARCH},
        {KEY_SCREENSHOT, 0, MmiMessageId::ON_SCREEN_SHOT}, {KEY_SCREENRECORD, 0, MmiMessageId::ON_START_SCREEN_RECORD},
        {KEY_SCREENRECORD, 0, MmiMessageId::ON_STOP_SCREEN_RECORD}, {KEY_RECENT, 0, MmiMessageId::ON_RECENT},
        {KEY_NOTIFICATION, 0, MmiMessageId::ON_SHOW_NOTIFICATION},
    };
    for (auto it : eventHandle) {
        if ((key.key == it.keyCode) && (modTask_ == it.taskCode)) {
            msgId = it.handler;
            if (it.taskCode != 0) {
                int32_t ret = SetPrevKeyValue(prevKey);
                CHKR(ret == RET_ERR, MEMCPY_SEC_FUN_FAIL, RET_ERR);
            }
            if ((key.key == KEY_VIDEO) || (key.key == KEY_SCREENRECORD)) {
                OnGetRepeatKetState(key.key, msgId);
            }
            return RET_OK;
        }
    }
    return RET_OK;
}

int32_t RegisterEvent::GetBitNum(const int32_t bitCode) const
{
    CHKF(bitCode >= 0, PARAM_INPUT_INVALID);
    return BIT1 << bitCode;
}

int32_t RegisterEvent::BitSetZero(const int32_t signCode, const int32_t bitCode) const
{
    CHKF(bitCode >= 0, PARAM_INPUT_INVALID);
    CHKF(signCode >= 0, PARAM_INPUT_INVALID);
    return signCode & ~(BIT1 << bitCode);
}

int32_t RegisterEvent::BitSetOne(const int32_t signCode, const int32_t bitCode) const
{
    CHKF(bitCode >= 0, PARAM_INPUT_INVALID);
    CHKF(signCode >= 0, PARAM_INPUT_INVALID);
    return signCode | (BIT1 << bitCode);
}

void RegisterEvent::TouchInfoBegin(const uint64_t time, const double x, const double y, TouchInfo& touchinfo)
{
    CHK(time > 0, PARAM_INPUT_INVALID);
    touchinfo.beginTime = time;
    touchinfo.beginX = x;
    touchinfo.beginY = y;
}

void RegisterEvent::TouchInfoEnd(const uint64_t time, const double x, const double y, TouchInfo& touchinfo)
{
    CHK(time > 0, PARAM_INPUT_INVALID);
    touchinfo.endTime = time;
    touchinfo.endX = x;
    touchinfo.endY = y;
}

int32_t RegisterEvent::OnEventPointButton(const int32_t buttonCode, const uint64_t timeNow,
                                          const BUTTON_STATE stateValue, MmiMessageId& msgId)
{
    CHKF(buttonCode >= 0, PARAM_INPUT_INVALID);
    CHKF(timeNow > 0, PARAM_INPUT_INVALID);
    CHKF(stateValue == 0 || stateValue == BIT1, PARAM_INPUT_INVALID);
    if (buttonCode == BTN_MIDDLE && stateValue == BUTTON_STATE_PRESSED) {
        if (timeCount_ == 0) {
            timeCount_ = timeNow;
        } else {
            if (timeNow - timeCount_ <= INTERVALTIME) {
                msgId = MmiMessageId::ON_RECENT;
                timeCount_ = timeNow;
            } else {
                timeCount_ = timeNow;
            }
        }
    }
    if (buttonCode == BTN_MIDDLE && stateValue == BUTTON_STATE_RELEASED) {
        if (timeCount_ == 0) {
            return RET_OK;
        } else {
            if (timeNow - timeCount_ >= (INTERVALTIME / BIT2)) {
                msgId = MmiMessageId::ON_GOTO_DESKTOP;
                timeCount_ = 0;
            } else {
                msgId = MmiMessageId::ON_BACK;
            }
        }
    }
    if (buttonCode == BTN_RIGHT && stateValue == BUTTON_STATE_PRESSED) {
        msgId = MmiMessageId::ON_SHOW_MENU;
    }
    return RET_OK;
}

int32_t RegisterEvent::OnEventPointAxis(const EventPointer& point, MmiMessageId& msgId)
{
    if (point.axis == POINTER_AXIS_SCROLL_VERTICAL && point.delta.y < 0) {
        msgId = MmiMessageId::ON_PREVIOUS;
    }
    if (point.axis == POINTER_AXIS_SCROLL_VERTICAL && point.delta.y > 0) {
        msgId = MmiMessageId::ON_NEXT;
    }
    return RET_OK;
}

void RegisterEvent::OnEventGestureGetSign(const EventGesture& gesture, MmiMessageId& msgId)
{
    CHK(gesture.time > 0, PARAM_INPUT_INVALID);
    CHK(gesture.fingerCount > 0, PARAM_INPUT_INVALID);
    CHK(gesture.eventType > 0, PARAM_INPUT_INVALID);
    switch (gesture.eventType) {
        case LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN: {
            OnEventGestureBeginGetSign(gesture);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_SWIPE_END: {
            OnEventGestureEndGetSign(gesture, msgId);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE: {
            OnEventGestureUpdateGetSign(gesture, msgId);
            break;
        }
        default: {
            break;
        }
    }
}

void RegisterEvent::OnEventTouchGetSign(const EventTouch& touch, MmiMessageId& msgId)
{
    CHK(touch.time > 0, PARAM_INPUT_INVALID);
    CHK(touch.seatSlot >= 0, PARAM_INPUT_INVALID);
    CHK(touch.eventType >= 0, PARAM_INPUT_INVALID);
    switch (touch.eventType) {
        case LIBINPUT_EVENT_TOUCH_DOWN:
            OnEventTouchDownGetSign(touch);
            break;
        case LIBINPUT_EVENT_TOUCH_UP:
            OnEventTouchUpGetSign(touch, msgId);
            break;
        case LIBINPUT_EVENT_TOUCH_MOTION:
            OnEventTouchMotionGetSign(touch, msgId);
            break;
        default:
            break;
    }
    SysEveHdl->OnSystemEventHandler(msgId);
}

int32_t RegisterEvent::OnEventGestureBeginGetSign(const EventGesture& gesture)
{
    CHKF(gesture.time > 0, PARAM_INPUT_INVALID);
    CHKF(gesture.fingerCount > 0, PARAM_INPUT_INVALID);
    gestureInfo_.enabled = true;
    gestureInfo_.beginTime = gesture.time;
    gestureInfo_.endTime = gesture.time;
    gestureInfo_.delta.x = gesture.delta.x;
    gestureInfo_.delta.y = gesture.delta.y;
    gestureInfo_.deltaUnaccel.x = gesture.deltaUnaccel.x;
    gestureInfo_.deltaUnaccel.y = gesture.deltaUnaccel.y;
    gestureInfo_.cancelled = gesture.cancelled;
    gestureInfo_.fingerCount = gesture.fingerCount;
    return RET_OK;
}

int32_t RegisterEvent::OnEventGestureUpdateGetSign(const EventGesture& gesture, MmiMessageId& msgId)
{
    CHKF(gesture.time >= gestureInfo_.beginTime, OHOS::PARAM_INPUT_INVALID);
    CHKF(gesture.fingerCount > 0, OHOS::PARAM_INPUT_INVALID);
    if (!gestureInfo_.enabled || gestureInfo_.fingerCount != gesture.fingerCount) {
        return RET_OK;
    }
    gestureInfo_.endTime = gesture.time;
    gestureInfo_.cancelled = gesture.cancelled;
    gestureInfo_.delta.x += gesture.delta.x;
    gestureInfo_.delta.y += gesture.delta.y;
    gestureInfo_.deltaUnaccel.x += gesture.deltaUnaccel.x;
    gestureInfo_.deltaUnaccel.y += gesture.deltaUnaccel.y;
    if (fabs(gestureInfo_.deltaUnaccel.x) >= fabs(gestureInfo_.deltaUnaccel.y)) {
        if (gestureInfo_.deltaUnaccel.x > MOVEDISTANCE && gestureInfo_.endTime - gestureInfo_.beginTime < PRESSTIME) {
            msgId = MmiMessageId::ON_BACK;
            gestureInfo_ = {};
            gestureInfo_.enabled = false;
        }
        if (gestureInfo_.deltaUnaccel.x < 0 && fabs(gestureInfo_.deltaUnaccel.x) > MOVEDISTANCE &&
            gestureInfo_.endTime - gestureInfo_.beginTime < PRESSTIME) {
            msgId = MmiMessageId::ON_NEXT;
            gestureInfo_ = {};
            gestureInfo_.enabled = false;
        }
    } else {
        if (gestureInfo_.deltaUnaccel.y < 0 && fabs(gestureInfo_.deltaUnaccel.y) > MOVEDISTANCE &&
            gestureInfo_.endTime - gestureInfo_.beginTime < PRESSTIME) {
            msgId = MmiMessageId::ON_GOTO_DESKTOP;
            gestureInfo_ = {};
            gestureInfo_.enabled = false;
        }
        if (gestureInfo_.deltaUnaccel.y > MOVEDISTANCE && gestureInfo_.endTime - gestureInfo_.beginTime < PRESSTIME) {
            msgId = MmiMessageId::ON_PREVIOUS;
            gestureInfo_ = {};
            gestureInfo_.enabled = false;
        }
    }
    return RET_OK;
}

int32_t RegisterEvent::OnEventGestureEndGetSign(const EventGesture& gesture, MmiMessageId& msgId)
{
    CHKF(gesture.time > 0, OHOS::PARAM_INPUT_INVALID);
    CHKF(gesture.fingerCount > 0, OHOS::PARAM_INPUT_INVALID);
    if (!gestureInfo_.enabled) {
        return RET_OK;
    }
    if (fabs(gestureInfo_.deltaUnaccel.x) < fabs(gestureInfo_.deltaUnaccel.y) &&
        gestureInfo_.deltaUnaccel.y > MOVEDISTANCE && gestureInfo_.endTime - gestureInfo_.beginTime >= PRESSTIME) {
            msgId = MmiMessageId::ON_RECENT;
    }
    gestureInfo_ = {};
    gestureInfo_.enabled = false;
    return RET_OK;
}

int32_t RegisterEvent::OnEventTouchDownGetSign(const EventTouch& touch)
{
    CHKF(touch.time > 0, PARAM_INPUT_INVALID);
    CHKF(touch.seatSlot >= 0, PARAM_INPUT_INVALID);
    TouchInfo touchDownInfo = {};
    TouchInfoBegin(touch.time, touch.point.x, touch.point.y, touchDownInfo);
    TouchInfoEnd(touch.time, touch.point.x, touch.point.y, touchDownInfo);
    touchDownInfo.deviceId = touch.deviceId;
    touchDownInfo.eventType = touch.eventType;
    touchDownInfo.pressure = touch.pressure;
    touchDownInfo.area = touch.area;
    touchDownInfo.slot = touch.slot;
    touchDownInfo.seatSlot = touch.seatSlot;
    touchInfos_.insert(std::map<std::pair<uint32_t, int32_t>,
        TouchInfo>::value_type(std::make_pair(touch.deviceId, touch.seatSlot), touchDownInfo));
    if (GetTouchInfoSizeByDeviceId(touchDownInfo.deviceId) > MAXFINGER) {
        DeleteTouchInfoByDeviceId(touchDownInfo.deviceId);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t RegisterEvent::OnEventOneFingerHandlerGetSign(MmiMessageId& msgId, TouchInfo& touchUpInfo)
{
    if (((touchUpInfo.beginX >= MINX) && (touchUpInfo.beginX < MINX + REGION) &&
        (touchUpInfo.endX - touchUpInfo.beginX > MOVEXDISTANCE)) ||
        ((touchUpInfo.beginX <= MAXX) && (touchUpInfo.beginX > MAXX - REGION) &&
        (touchUpInfo.beginX - touchUpInfo.endX > MOVEXDISTANCE))) {
        msgId = MmiMessageId::ON_BACK;
        return RET_OK;
    }

    if ((touchUpInfo.beginY <= MAXY) && (touchUpInfo.beginY > MAXY - REGION) && (touchUpInfo.beginX != MINX) &&
        (touchUpInfo.beginX != MAXX) && (touchUpInfo.beginY - touchUpInfo.endY > MOVEDISTANCE) &&
        (touchUpInfo.endTime - touchUpInfo.beginTime <= PRESSTIME)) {
        msgId = MmiMessageId::ON_GOTO_DESKTOP;
        return RET_OK;
    }
    return RET_OK;
}

int32_t RegisterEvent::OnEventThreeFingerHandlerGetSign(MmiMessageId& msgId, TouchInfo& touchUpInfo)
{
    int32_t touchState = 1;
    for (auto temp : touchInfos_) {
        if ((temp.second.deviceId == touchUpInfo.deviceId) &&
            ((temp.second.endY - temp.second.beginY < MOVEDISTANCE) || (temp.second.beginY == MINY))) {
            touchState = RELEASE;
            break;
        }
    }
    if ((touchUpInfo.endY - touchUpInfo.beginY < MOVEDISTANCE) || (touchUpInfo.beginY == MINY)) {
        touchState = RELEASE;
    }
    if (touchState) {
        msgId = MmiMessageId::ON_SCREEN_SHOT;
    }
    return RET_OK;
}

int32_t RegisterEvent::OnEventTouchUpGetSign(const EventTouch& touch, MmiMessageId& msgId)
{
    CHKF(touch.time > 0, PARAM_INPUT_INVALID);
    CHKF(touch.seatSlot >= 0, PARAM_INPUT_INVALID);
    TouchInfo touchUpInfo = {};
    auto iter = touchInfos_.find(std::make_pair(touch.deviceId, touch.seatSlot));
    if (iter != touchInfos_.end()) {
        touchUpInfo = iter->second;
        touchInfos_.erase(iter);
    } else {
        return RET_ERR;
    }

    if ((GetTouchInfoSizeByDeviceId(touchUpInfo.deviceId) + 1) == THREEFINGER) {
        return OnEventThreeFingerHandlerGetSign(msgId, touchUpInfo);
    }
    if ((GetTouchInfoSizeByDeviceId(touchUpInfo.deviceId) + 1) == ONEFINGER) {
        return OnEventOneFingerHandlerGetSign(msgId, touchUpInfo);
    }
    return RET_OK;
}

int32_t RegisterEvent::OnEventTouchMotionGetSign(const EventTouch& touch, MmiMessageId& msgId)
{
    CHKF(touch.time > 0, PARAM_INPUT_INVALID);
    CHKF(touch.seatSlot >= 0, PARAM_INPUT_INVALID);
    auto iter = touchInfos_.find(std::make_pair(touch.deviceId, touch.seatSlot));
    if (iter != touchInfos_.end()) {
        iter->second.endX = touch.point.x;
        iter->second.endY = touch.point.y;
        iter->second.endTime = touch.time;
        iter->second.eventType = touch.eventType;
        iter->second.pressure = touch.pressure;
        iter->second.area = touch.area;
        iter->second.seatSlot = touch.seatSlot;
        iter->second.slot = touch.slot;
    } else {
        return RET_ERR;
    }

    if (GetTouchInfoSizeByDeviceId(touch.deviceId) == ONEFINGER) {
        if ((iter->second.beginY >= MINY) && (iter->second.beginY < MINY + REGION) && (iter->second.beginX != MINX) &&
            (iter->second.beginX != MAXX) && (iter->second.endY - iter->second.beginY > MOVEDISTANCE)) {
            msgId = MmiMessageId::ON_SHOW_NOTIFICATION;
            return RET_OK;
        }
        if ((iter->second.beginY <= MAXY) && (iter->second.beginY > MAXY - REGION) && (iter->second.beginX != MINX) &&
            (iter->second.beginX != MAXX) && (iter->second.beginY - iter->second.endY > MOVEDISTANCE) &&
            (iter->second.endTime - iter->second.beginTime > PRESSTIME)) {
            msgId = MmiMessageId::ON_RECENT;
            return RET_OK;
        }
    }
    return RET_OK;
}

int32_t RegisterEvent::GetTouchInfo(const std::pair<uint32_t, int32_t> key, EventTouch& touch)
{
    auto iter = touchInfos_.find(key);
    CHKF(iter != touchInfos_.end(), TOUCH_ID_NO_FIND);
    if (iter != touchInfos_.end()) {
        touch.point.x = iter->second.endX;
        touch.point.y = iter->second.endY;
        touch.time = iter->second.endTime;
        touch.seatSlot = iter->second.seatSlot;
        touch.slot = iter->second.slot;
        touch.eventType = iter->second.eventType;
        touch.pressure = iter->second.pressure;
        touch.area = iter->second.area;
        touch.deviceId = iter->second.deviceId;
        return RET_OK;
    } else {
        return RET_ERR;
    }
}

void RegisterEvent::GetTouchIds(std::vector<std::pair<uint32_t, int32_t>>& touchIds, const uint32_t deviceId)
{
    auto iter = touchInfos_.begin();
    while (iter != touchInfos_.end()) {
        if (iter->second.deviceId == deviceId) {
            touchIds.push_back(iter->first);
        }
        iter++;
    }
}

int32_t RegisterEvent::GetTouchInfoSizeByDeviceId(uint32_t deviceId)
{
    int32_t count = 0;
    for (auto iter = touchInfos_.begin(); iter != touchInfos_.end(); iter++) {
        if (iter->second.deviceId == deviceId) {
            count++;
        }
    }
    return count;
}

void RegisterEvent::DeleteTouchInfoByDeviceId(uint32_t deviceId)
{
    auto it = touchInfos_.begin();
    while (it != touchInfos_.end()) {
        if (it->second.deviceId == deviceId) {
            it = touchInfos_.erase(it);
        } else {
            it++;
        }
    }
}
}
}
