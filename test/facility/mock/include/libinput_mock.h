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

#ifndef LIBINPUT_MOCK_H
#define LIBINPUT_MOCK_H

#include <gmock/gmock.h>

#include "libinput_interface.h"

namespace OHOS {
namespace MMI {
class LibinputInterfaceMock : public LibinputInterface {
public:
    LibinputInterfaceMock() = default;
    virtual ~LibinputInterfaceMock() = default;

    MOCK_METHOD(enum libinput_event_type, GetEventType, (struct libinput_event *));
    MOCK_METHOD(struct libinput_device *, GetDevice, (struct libinput_event *));
    MOCK_METHOD(uint64_t, GetSensorTime, (struct libinput_event *));
    MOCK_METHOD(struct libinput_event_touch *, GetTouchEvent, (struct libinput_event *));
    MOCK_METHOD(struct libinput_event_tablet_tool *, GetTabletToolEvent, (struct libinput_event *));
    MOCK_METHOD(struct libinput_event_gesture *, GetGestureEvent, (struct libinput_event *));
    MOCK_METHOD(struct libinput_tablet_tool *, TabletToolGetTool, (struct libinput_event_tablet_tool *));
    MOCK_METHOD(enum libinput_tablet_tool_tip_state, TabletToolGetTipState, (struct libinput_event_tablet_tool *));
    MOCK_METHOD(enum libinput_tablet_tool_type, TabletToolGetType, (struct libinput_tablet_tool *));
    MOCK_METHOD(enum libinput_pointer_axis_source, GetAxisSource, (struct libinput_event_pointer *));
    MOCK_METHOD(struct libinput_event_pointer*, LibinputGetPointerEvent, (struct libinput_event *));
    MOCK_METHOD(int32_t, TabletToolGetToolType, (struct libinput_event_tablet_tool *));
    MOCK_METHOD(double, TabletToolGetTiltX, (struct libinput_event_tablet_tool *));
    MOCK_METHOD(double, TabletToolGetTiltY, (struct libinput_event_tablet_tool *));
    MOCK_METHOD(uint64_t, TabletToolGetTimeUsec, (struct libinput_event_tablet_tool *));
    MOCK_METHOD(double, TabletToolGetPressure, (struct libinput_event_tablet_tool *));
    MOCK_METHOD(uint64_t, TouchEventGetTime, (struct libinput_event_touch *));
    MOCK_METHOD(int32_t, TouchEventGetSeatSlot, (struct libinput_event_touch *));
    MOCK_METHOD(double, TouchEventGetPressure, (struct libinput_event_touch *));
    MOCK_METHOD(int32_t, TouchEventGetContactLongAxis, (struct libinput_event_touch *));
    MOCK_METHOD(int32_t, TouchEventGetContactShortAxis, (struct libinput_event_touch *));
    MOCK_METHOD(int32_t, TouchEventGetToolType, (struct libinput_event_touch *));
    MOCK_METHOD(int, TouchEventGetBtnToolTypeDown, (struct libinput_device *, int32_t));
    MOCK_METHOD(uint32_t, GestureEventGetTime, (struct libinput_event_gesture *));
    MOCK_METHOD(int, GestureEventGetFingerCount, (struct libinput_event_gesture *));
    MOCK_METHOD(int, GestureEventGetDevCoordsX, (struct libinput_event_gesture *, uint32_t));
    MOCK_METHOD(int, GestureEventGetDevCoordsY, (struct libinput_event_gesture *, uint32_t));
    MOCK_METHOD(uint32_t, PointerEventGetFingerCount, (struct libinput_event_pointer *));
    MOCK_METHOD(double, PointerGetDxUnaccelerated, (struct libinput_event_pointer *));
    MOCK_METHOD(double, PointerGetDyUnaccelerated, (struct libinput_event_pointer *));
    MOCK_METHOD(uint32_t, PointerGetButton, (struct libinput_event_pointer *));
    MOCK_METHOD(int, PointerHasAxis, (struct libinput_event_pointer *,  enum libinput_pointer_axis));
    MOCK_METHOD(double, PointerGetAxisValue, (struct libinput_event_pointer *,  enum libinput_pointer_axis));
    MOCK_METHOD(struct libinput_event_touch *, GetTouchpadEvent, (struct libinput_event *));
    MOCK_METHOD(int32_t, TouchpadGetTool, (struct libinput_event_touch *));
    MOCK_METHOD(char*, DeviceGetName, (struct libinput_device *));
    MOCK_METHOD(struct libinput_event_keyboard*, LibinputEventGetKeyboardEvent, (struct libinput_event *));
    MOCK_METHOD(uint32_t, LibinputEventKeyboardGetKey, (struct libinput_event_keyboard *));
    MOCK_METHOD(enum libinput_key_state, LibinputEventKeyboardGetKeyState, (struct libinput_event_keyboard *));
};
} // namespace MMI
} // namespace OHOS
#endif // LIBINPUT_MOCK_H
