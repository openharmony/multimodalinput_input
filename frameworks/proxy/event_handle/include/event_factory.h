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

#ifndef OHOS_EVENTS_FACTORY_H
#define OHOS_EVENTS_FACTORY_H
#include "multimodal_event.h"

namespace OHOS {
enum EventType {
    EVENT_MULTIMODAL = 0,    // 多模消息基类
    EVENT_KEY = 1,           // 按键消息
    EVENT_KEYBOARD = 2,      // 键盘消息
    EVENT_ROCKER = 3,        // 摇杆消息
    EVENT_REMOTECONTROL = 4, // 远程控制消息
    EVENT_JOYSTICK = 5,      // 手柄消息
    EVENT_MOUSE = 6,         // 鼠标消息
    EVENT_TRACKBOLL = 7,     // 轨迹球消息
    EVENT_MANIPULATION = 8,  // 操纵消息
    EVENT_TOUCH = 9,         // 触屏消息
    EVENT_TOUCHPAD = 10,     // Pad触屏消息
    EVENT_STYLUS = 11,       // 电子笔消息
    EVENT_ROTATION = 12,     // 旋转消息
    EVENT_SPEECH = 13,       // 语音消息
    EVENT_BUILTINKEY = 14,   // 内置消息
    EVENT_COMPOSITE = 15,    // 组合消息
    EVENT_DEVICE = 16,       // 设备消息
};

class EventFactory {
public:
    static MultimodalEventPtr CreateEvent(int32_t eventType);
};
}
#endif
