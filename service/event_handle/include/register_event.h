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
#ifndef REGISTER_EVENT_H
#define REGISTER_EVENT_H

#include <map>
#include <vector>
#include "singleton.h"
#include "hos_key_event.h"
#include "libinput.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
struct TouchInfo {
    uint32_t deviceId;
    double pressure;
    double area;
    double beginX;
    double beginY;
    double endX;
    double endY;
    uint64_t beginTime;
    uint64_t endTime;
    int32_t eventType;
    int32_t slot;
    int32_t seatSlot;
};
struct GestureInfo {
    int32_t fingerCount;
    int32_t cancelled;
    NormalizedCoords delta;
    NormalizedCoords deltaUnaccel;
    uint64_t beginTime;
    uint64_t endTime;
    bool enabled;
};

class RegisterEvent : public DelayedSingleton<RegisterEvent> {
public:
    RegisterEvent();
    ~RegisterEvent();
    /*
    * Method:    OnEventKeyGetSign
    * FullName:  RegisterEvent::OnEventKeyGetSign
    * Access:    public
    * Returns:   void
    * Qualifier: 判断键盘事件是否为功能键（ctrl,alt,shift,logo）
    */
    void OnEventKeyGetSign(const EventKeyboard& key, MmiMessageId& msg, EventKeyboard& prevKey);
    int32_t OnEventPointButton(const int32_t buttonCode, const uint64_t timeNow,
        const BUTTON_STATE stateValue, MmiMessageId& msgId);
    int32_t OnEventPointAxis(const EventPointer& point, MmiMessageId& msgId);
    /*
    * Method:    OnEventTouchGetSign
    * FullName:  RegisterEvent::OnEventTouchGetSign
    * Access:    public
    * Returns:   bool
    * Qualifier: 判断触屏事件的高级事件
    */
    void OnEventTouchGetSign(const EventTouch& touch, MmiMessageId& msgId);
    void OnEventGestureGetSign(const EventGesture& gesture, MmiMessageId& msgId);
    void GetTouchInfo(const std::pair<uint32_t, int32_t> key, EventTouch& touch);
    void GetTouchIds(std::vector<std::pair<uint32_t, int32_t>>& touchIds, const uint32_t deviceId);
    int32_t GetTouchInfoSizeByDeviceId(const uint32_t deviceId);
protected:
    int32_t OnEventGestureEndGetSign(const EventGesture& gesture, MmiMessageId& msgId);
    int32_t OnEventGestureUpdateGetSign(const EventGesture& gesture, MmiMessageId& msgId);
    int32_t OnEventGestureBeginGetSign(const EventGesture& gesture);
    int32_t OnEventOneFingerHandlerGetSign(const TouchInfo& touchUpInfo, MmiMessageId& msgId);
    int32_t OnEventThreeFingerHandlerGetSign(const TouchInfo& touchUpInfo, MmiMessageId& msgId);
    int32_t OnEventTouchDownGetSign(const EventTouch& touch);
    int32_t OnEventTouchMotionGetSign(const EventTouch& touch, MmiMessageId& msgId);
    int32_t OnEventTouchUpGetSign(const EventTouch& touch, MmiMessageId& msgId);
    bool OnGetRepeatKetState(const uint32_t keyCode, MmiMessageId& msgId);
    int32_t SetPrevKeyValue(EventKeyboard& prevKey);
    int32_t OnEventKeyJudge(const EventKeyboard& key, MmiMessageId& msgId, EventKeyboard& prevKey);
    /*
    * Method:    GetBitNum
    * FullName:  RegisterEvent::GetBitNum
    * Access:    protected
    * Returns:   int32_t
    * Qualifier: 得到对应标志位的数值
    */
    int32_t GetBitNum(const int32_t bitCode) const;
    /*
    * Method:    BitSetZero
    * FullName:  RegisterEvent::BitSetZero
    * Access:    protected
    * Returns:   int32_t
    * Qualifier: 对应标志位置0
    */
    int32_t BitSetZero(const int32_t signCode, const int32_t bitCode) const;
    /*
    * Method:    BitSetOne
    * FullName:  RegisterEvent::BitSetOne
    * Access:    protected
    * Returns:   int32_t
    * Qualifier: 对应标志位置1
    */
    int32_t BitSetOne(const int32_t signCode, const int32_t bitCode) const;
    void TouchInfoBegin(const uint64_t time, const double x, const double y, TouchInfo& touchinfo);
    void TouchInfoEnd(const uint64_t time, const double x, const double y, TouchInfo& touchinfo);
    void DeleteTouchInfoByDeviceId(uint32_t deviceId);

protected:
    EventKeyboard key_ = {};
    int32_t modMask_ = 0;
    int32_t modTask_ = 0;
    uint64_t timeCount_ = 0;
    int32_t baseKey_ = 0;
    std::map<std::pair<uint32_t, int32_t>, TouchInfo> touchInfos_ = {};
    GestureInfo gestureInfo_ = {};

    static const int32_t KEY_MULTITASK = 0x280; /* virtual multitask key */
    static const int32_t KEY_SCREENSHOT = 0x281; /* remote SCREENSHOT key */
    static const int32_t KEY_SCREENRECORD = 0x282; /* remote SCREENRECORD key */
    static const int32_t KEY_RECENT = 0x283; /* remote switch windows key */
    static const int32_t KEY_NOTIFICATION = 0x284; /* remote NOTIFICATION key */
    static const uint64_t INTERVALTIME = 1000000;
    static const uint64_t PRESSTIME = 6000000;  // 6s
    static const int32_t MAXFINGER = 5;
    static const int32_t MOVEDISTANCE = 100;
    static const int32_t MOVETABLEPAD = 500;
    static const int32_t MOVEXDISTANCE = 50;
    static const int32_t MAXY = 1000;
    static const int32_t MAXX = 500;
    static const int32_t MINY = 0;
    static const int32_t MINX = 0;
    static const int32_t REGION = 50;
    static const int32_t ONEFINGER = 1;
    static const int32_t THREEFINGER = 3;
    static const int32_t PRESS = 1;
    static const int32_t RELEASE = 0;
    static const int32_t BIT0 = 0;
    static const int32_t BIT1 = 1;
    static const int32_t BIT2 = 2;
    static const int32_t BIT3 = 3;
    static const int32_t BIT4 = 4;
    static const int32_t BIT5 = 5;
    static const int32_t BIT6 = 6;
};
}
}
#define MMIRegEvent OHOS::MMI::RegisterEvent::GetInstance()
#endif // REGISTER_EVENT_H