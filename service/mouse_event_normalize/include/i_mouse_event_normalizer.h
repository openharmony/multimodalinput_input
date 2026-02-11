/*
* Copyright (c) 2026 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License") = 0;
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

#ifndef I_MOUSE_EVENT_NORMALIZE_H
#define I_MOUSE_EVENT_NORMALIZE_H

#include <functional>
#include <memory>
#include <shared_mutex>

#include "component_manager.h"
#include "device_observer.h"
#include "key_event.h"
#include "pointer_event.h"

struct libinput_event;

extern "C" {
    struct Offset {
        double dx;
        double dy;
    };

    int32_t HandleMotionAccelerateMouse(const Offset* offset, bool mode, double* abs_x, double* abs_y,
        int32_t speed, int32_t deviceType);
    int32_t HandleMotionAccelerateTouchpad(const Offset* offset, bool mode, double* abs_x, double* abs_y,
        int32_t speed, int32_t deviceType);
    int32_t HandleAxisAccelerateTouchpad(bool mode, double* abs_axis, int32_t deviceType);
    int32_t HandleMotionDynamicAccelerateMouse(const Offset* offset, bool mode, double* abs_x, double* abs_y,
        int32_t speed, uint64_t delta_time, double display_ppi, double factor);
    int32_t HandleMotionDynamicAccelerateTouchpad(const Offset* offset, bool mode, double* abs_x, double* abs_y,
        int32_t speed, double display_size, double touchpad_size, double touchpad_ppi, int32_t frequency);
}

namespace OHOS {
namespace MMI {
class IMouseEventNormalize {
public:
    IMouseEventNormalize() = default;
    virtual ~IMouseEventNormalize() = default;

    virtual void OnDeviceAdded(int32_t deviceId) = 0;
    virtual void OnDeviceRemoved(int32_t deviceId) = 0;
    virtual bool HasMouse() = 0;
    virtual int32_t OnEvent(struct libinput_event *event) = 0;
    virtual std::shared_ptr<PointerEvent> GetPointerEvent() = 0;
    virtual std::shared_ptr<PointerEvent> GetPointerEvent(int32_t deviceId) = 0;
    virtual void Dump(int32_t fd, const std::vector<std::string> &args) = 0;
    virtual int32_t NormalizeRotateEvent(struct libinput_event *event, int32_t type, double angle) = 0;
    virtual bool CheckAndPackageAxisEvent(libinput_event* event) = 0;
#ifdef OHOS_BUILD_MOUSE_REPORTING_RATE
    virtual bool CheckFilterMouseEvent(struct libinput_event *event) = 0;
#endif // OHOS_BUILD_MOUSE_REPORTING_RATE
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    virtual bool NormalizeMoveMouse(int32_t offsetX, int32_t offsetY) = 0;
    virtual void OnDisplayLost(int32_t displayId) = 0;
    virtual int32_t GetDisplayId() const = 0;
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
    virtual int32_t SetPointerLocation(int32_t x, int32_t y, int32_t displayId = -1) = 0;
    virtual int32_t GetPointerLocation(int32_t &displayId, double &displayX, double &displayY) = 0;
    virtual int32_t SetMouseAccelerateMotionSwitch(int32_t deviceId, bool enable) = 0;
    // MouseDeviceState Interface
    virtual int32_t GetMouseCoordsX() const = 0;
    virtual int32_t GetMouseCoordsY() const = 0;
    virtual void SetMouseCoords(int32_t x, int32_t y) = 0;
    virtual bool IsLeftBtnPressed() = 0;
    virtual void GetPressedButtons(std::vector<int32_t>& pressedButtons) = 0;
    virtual void MouseBtnStateCounts(uint32_t btnCode, const BUTTON_STATE btnState) = 0;
    virtual int32_t LibinputChangeToPointer(const uint32_t keyValue) = 0;
    virtual int32_t SetScrollSwitchSetterPid(int32_t pid) = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // I_MOUSE_EVENT_NORMALIZE_H