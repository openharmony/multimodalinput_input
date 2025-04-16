/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef MOUSE_TRANSFORM_PROCESSOR_H
#define MOUSE_TRANSFORM_PROCESSOR_H

#include "libinput.h"

#include "aggregator.h"
#include "timer_manager.h"
#include "pointer_event.h"
#include "touchpad_control_display_gain.h"
#include "window_info.h"

namespace OHOS {

extern "C" {
    struct Offset {
        double dx;
        double dy;
    };
    enum class DeviceType {
        DEVICE_UNKOWN = 0,
        DEVICE_PC = 1,
        DEVICE_SOFT_PC_PRO = 2,
        DEVICE_HARD_PC_PRO = 3,
        DEVICE_TABLET = 4,
        DEVICE_FOLD_PC = 5,
        DEVICE_M_PC = 6,
        DEVICE_FOLD_PC_VIRT = 7,
        DEVICE_M_TABLET = 8,
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

namespace MMI {
struct AccelerateCurve {
    std::vector<int32_t> speeds;
    std::vector<double> slopes;
    std::vector<double> diffNums;
};
class MouseTransformProcessor final : public std::enable_shared_from_this<MouseTransformProcessor> {
    struct Movement {
        double dx;
        double dy;
    };

public:
    enum class RightClickType {
        TP_RIGHT_BUTTON = 1,
        TP_LEFT_BUTTON = 2,
        TP_TWO_FINGER_TAP = 3,
        TP_TWO_FINGER_TAP_OR_RIGHT_BUTTON = 4,
        TP_TWO_FINGER_TAP_OR_LEFT_BUTTON = 5,
    };

    enum class PointerDataSource {
        MOUSE = 1,
        TOUCHPAD = 2,
    };

#ifdef OHOS_BUILD_MOUSE_REPORTING_RATE
    struct FilterInsertionPoint {
        double filterX{ 0.0 };
        double filterY{ 0.0 };
        uint64_t filterPrePointTime{ 0 };
        uint64_t filterDeltaTime{ 0 };
        bool filterFlag{ false };
        static constexpr int32_t FILTER_THRESHOLD_US = 800; // <=1ms
    };
#endif // OHOS_BUILD_MOUSE_REPORTING_RATE

public:
    DISALLOW_COPY_AND_MOVE(MouseTransformProcessor);
    explicit MouseTransformProcessor(int32_t deviceId);
    ~MouseTransformProcessor() = default;
    std::shared_ptr<PointerEvent> GetPointerEvent() const;
    int32_t Normalize(struct libinput_event *event);
    int32_t NormalizeRotateEvent(struct libinput_event *event, int32_t type, double angle);
    void Dump(int32_t fd, const std::vector<std::string> &args);
    bool CheckAndPackageAxisEvent();
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    bool NormalizeMoveMouse(int32_t offsetX, int32_t offsetY);
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
#ifdef OHOS_BUILD_MOUSE_REPORTING_RATE
    void HandleFilterMouseEvent(Offset* offset);
    bool CheckFilterMouseEvent(struct libinput_event *event);
#endif // OHOS_BUILD_MOUSE_REPORTING_RATE

private:
    int32_t HandleMotionInner(struct libinput_event_pointer* data, struct libinput_event *event);
    int32_t HandleButtonInner(struct libinput_event_pointer* data, struct libinput_event *event);
    int32_t HandleAxisInner(struct libinput_event_pointer* data);
    int32_t HandleAxisBeginEndInner(struct libinput_event *event);
    int32_t HandleScrollFingerInner(struct libinput_event *event);
    void HandleAxisPostInner(PointerEvent::PointerItem &pointerItem);
    bool HandlePostInner(struct libinput_event_pointer* data, PointerEvent::PointerItem &pointerItem);
    void HandleTouchPadAxisState(libinput_pointer_axis_source source, int32_t& direction, bool& tpScrollSwitch);
    void HandleTouchPadButton(enum libinput_button_state state, int32_t type);
    int32_t UpdateMouseMoveLocation(const DisplayInfo* displayInfo, Offset &offset,
        double &abs_x, double &abs_y, int32_t deviceType);
    int32_t UpdateTouchpadMoveLocation(const DisplayInfo* displayInfo, struct libinput_event* event,
        Offset &offset, double &abs_x, double &abs_y, int32_t deviceType);
#ifndef OHOS_BUILD_ENABLE_WATCH
    void HandleTouchpadRightButton(struct libinput_event_pointer* data, const int32_t evenType, uint32_t &button);
    void HandleTouchpadLeftButton(struct libinput_event_pointer* data, const int32_t evenType, uint32_t &button);
    void HandleTouchpadTwoFingerButton(struct libinput_event_pointer* data, const int32_t evenType, uint32_t &button);
    void HandleTouchpadTwoFingerButtonOrRightButton(struct libinput_event_pointer* data,
        const int32_t evenType, uint32_t &button);
    void HandleTouchpadTwoFingerButtonOrLeftButton(struct libinput_event_pointer* data,
        const int32_t evenType, uint32_t &button);
    void TransTouchpadRightButton(struct libinput_event_pointer* data, const int32_t type, uint32_t &button);
    double HandleAxisAccelateTouchPad(double axisValue);
#endif // OHOS_BUILD_ENABLE_WATCH
    void CalculateOffset(const DisplayInfo* displayInfo, Offset &offset);
    void HandleReportMouseResponseTime(std::string &connectType, std::map<long long, int32_t> &curMap);
    void CalculateMouseResponseTimeProbability(struct libinput_event *event);
    std::map<std::string, std::map<long long, int32_t>> mouseResponseMap = {};
    std::map<std::string, std::chrono::time_point<std::chrono::steady_clock>> mouseMap = {};
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    void HandleMotionMoveMouse(int32_t offsetX, int32_t offsetY);
    void HandlePostMoveMouse(PointerEvent::PointerItem &pointerItem);
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
    int32_t HandleButtonValueInner(struct libinput_event_pointer* data, uint32_t& button, int32_t type);
    DeviceType CheckDeviceType(int32_t width, int32_t height);
    void DeletePressedButton(uint32_t originButton);
    void DumpInner();
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    static void GetVirtualTouchpadTapSwitch(bool &switchFlag);
    static void GetVirtualTouchpadRightClickType(int32_t &type);
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
    static int32_t PutConfigDataToDatabase(std::string &key, bool value);
    static void GetConfigDataFromDatabase(std::string &key, bool &value);
    static int32_t PutConfigDataToDatabase(std::string &key, int32_t value);
    static void GetConfigDataFromDatabase(std::string &key, int32_t &value);

public:
    static void OnDisplayLost(int32_t displayId);
    static int32_t GetDisplayId();
    static int32_t SetMousePrimaryButton(int32_t primaryButton);
    static int32_t GetMousePrimaryButton();
    static int32_t SetMouseScrollRows(int32_t rows);
    static int32_t GetMouseScrollRows();
    static int32_t SetPointerSpeed(int32_t speed);
    static int32_t GetPointerSpeed();
    static int32_t SetPointerLocation(int32_t x, int32_t y, int32_t displayId);
    static int32_t SetTouchpadScrollSwitch(int32_t pid, bool switchFlag);
    static void GetTouchpadScrollSwitch(bool &switchFlag);
    static int32_t SetTouchpadScrollDirection(bool state);
    static void GetTouchpadScrollDirection(bool &state);
    static int32_t SetTouchpadTapSwitch(bool switchFlag);
    static void GetTouchpadTapSwitch(bool &switchFlag);
    static int32_t SetTouchpadRightClickType(int32_t type);
    static void GetTouchpadRightClickType(int32_t &type);
    static int32_t SetTouchpadPointerSpeed(int32_t speed);
    static void GetTouchpadPointerSpeed(int32_t &speed);
    static void GetTouchpadCDG(TouchpadCDG &touchpadCDG);
    static void UpdateTouchpadCDG(double touchpadPPi, double touchpadSize, int32_t frequency);
    static int32_t GetTouchpadSpeed();

private:
    static DeviceType deviceTypeGlobal_;
    static int32_t globalPointerSpeed_;
    static int32_t scrollSwitchPid_;
    std::shared_ptr<PointerEvent> pointerEvent_ { nullptr };
    int32_t timerId_ { -1 };
    int32_t buttonId_ { -1 };
    uint32_t pressedButton_ { 0 };
    bool isPressed_ { false };
    int32_t deviceId_ { -1 };
    bool isAxisBegin_ { false };
    Movement unaccelerated_ {};
    std::map<int32_t, int32_t> buttonMapping_;
    static TouchpadCDG touchpadOption_;
    Aggregator aggregator_ {
            [](int32_t intervalMs, int32_t repeatCount, std::function<void()> callback) -> int32_t {
                return TimerMgr->AddTimer(intervalMs, repeatCount, std::move(callback));
            },
            [](int32_t timerId) -> int32_t
            {
                return TimerMgr->ResetTimer(timerId);
            }
    };
#ifdef OHOS_BUILD_MOUSE_REPORTING_RATE
    struct FilterInsertionPoint filterInsertionPoint_;
#endif // OHOS_BUILD_MOUSE_REPORTING_RATE
};
} // namespace MMI
} // namespace OHOS
#endif // MOUSE_TRANSFORM_PROCESSOR_H