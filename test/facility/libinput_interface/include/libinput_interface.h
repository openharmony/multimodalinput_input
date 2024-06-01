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
 
#ifndef LIBINPUT_INTERFACE_H
#define LIBINPUT_INTERFACE_H

#include <memory>
#include <string>

#include "libinput.h"

struct udev_device {
    uint32_t tags;
};

struct libinput_device {
    struct udev_device udevDev;
    unsigned int busType;
    unsigned int version;
    unsigned int product;
    unsigned int vendor;
    std::string name;
};

struct libinput_event {
    uint64_t time;
    enum libinput_event_type type;
    libinput_device dev;
};

struct libinput_event_pointer {
    struct libinput_event base;
    enum libinput_button_state buttonState;
};

struct libinput_event_keyboard {
    struct libinput_event base;
    uint32_t key;
    enum libinput_key_state keyState;
};

struct libinput_event_tablet_tool {
    struct libinput_event base;
};

struct libinput_event_touch {
    struct libinput_event base;
    int32_t seatSlot;
    int32_t longAxis;
    int32_t shortAxis;
    int32_t toolType;
    double x;
    double y;
    double pressure;
    double toolX;
    double toolY;
    double toolWidth;
    double toolHeight;
};

struct device_coords {
    int32_t x;
    int32_t y;
};

constexpr uint32_t N_GESTURE_DEVICE_COORDS { 5 };

struct libinput_event_gesture {
    struct libinput_event base;
    double scale;
    double angle;
    struct device_coords coords[N_GESTURE_DEVICE_COORDS];
};

namespace OHOS {
namespace MMI {

class LibinputInterface {
public:
    LibinputInterface();
    virtual ~LibinputInterface() = default;

    virtual enum libinput_event_type GetEventType(struct libinput_event *event) = 0;
    virtual struct libinput_event_gesture* GetGestureEvent(struct libinput_event *event) = 0;
    virtual uint32_t GestureEventGetTime(struct libinput_event_gesture *event) = 0;
    virtual int GestureEventGetFingerCount(struct libinput_event_gesture *event) = 0;
    virtual int GestureEventGetDevCoordsX(struct libinput_event_gesture *event, uint32_t idx) = 0;
    virtual int GestureEventGetDevCoordsY(struct libinput_event_gesture *event, uint32_t idx) = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // LIBINPUT_INTERFACE_H