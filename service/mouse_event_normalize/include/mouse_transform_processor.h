/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "aggregator.h"
#include "device_type_definition.h"
#include "i_input_service_context.h"
#include "libinput.h"
#include "timer_manager.h"
#include "pointer_event.h"
#include "old_display_info.h"
#include "i_mouse_event_normalizer.h"

#include <preferences_value.h>

namespace OHOS {
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
    explicit MouseTransformProcessor(IInputServiceContext *env, int32_t deviceId);
    ~MouseTransformProcessor();
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
    int32_t SetMouseAccelerateMotionSwitch(bool enable);
    void OnDeviceRemoved();

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
    int32_t UpdateMouseMoveLocation(const OLD::DisplayInfo* displayInfo, Offset &offset,
        double &abs_x, double &abs_y, int32_t deviceType);
    int32_t UpdateTouchpadMoveLocation(const OLD::DisplayInfo* displayInfo, struct libinput_event* event,
        Offset &offset, double &abs_x, double &abs_y, int32_t deviceType);
#ifndef OHOS_BUILD_ENABLE_WATCH
    void HandleTouchpadRightButton(struct libinput_event_pointer* data, const int32_t eventType, uint32_t &button);
    void HandleTouchpadLeftButton(struct libinput_event_pointer* data, const int32_t eventType, uint32_t &button);
    void HandleTouchpadTwoFingerButton(struct libinput_event_pointer* data, const int32_t eventType, uint32_t &button);
    void HandleTouchpadTwoFingerButtonOrRightButton(struct libinput_event_pointer* data,
        const int32_t eventType, uint32_t &button);
    void HandleTouchpadTwoFingerButtonOrLeftButton(struct libinput_event_pointer* data,
        const int32_t eventType, uint32_t &button);
    void TransTouchpadRightButton(struct libinput_event_pointer* data, const int32_t type, uint32_t &button);
#endif // OHOS_BUILD_ENABLE_WATCH
#ifdef OHOS_BUILD_ENABLE_TOUCHPAD
    double HandleAxisAccelateTouchPad(int32_t userId, double axisValue);
#endif // OHOS_BUILD_ENABLE_TOUCHPAD
    void CalculateOffset(const OLD::DisplayInfo* displayInfo, Offset &offset);
    Direction GetDisplayDirection(const OLD::DisplayInfo *displayInfo);
    double CalculateProportion(long long key, long &total, std::map<long long, int32_t> &curMap);
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
    void SetPointerEventRightButtonSource(const int32_t eventType, uint32_t button);
    void SetMouseScrollAxisValue(libinput_pointer_axis_source source, double &axisValue);
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    static bool IsEventFromVirtualSource(struct libinput_event* event);
    static void GetVirtualTouchpadTapSwitch(bool &switchFlag);
    static void GetVirtualTouchpadRightClickType(int32_t &type);
    static int32_t GetVirtualTouchpadPrimaryButton();
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

public:
    static void OnDisplayLost(IInputServiceContext &env, int32_t displayId);
    static int32_t GetDisplayId(IInputServiceContext &env);
    static int32_t SetPointerLocation(IInputServiceContext &env, int32_t x, int32_t y, int32_t displayId);
    static int32_t GetPointerLocation(IInputServiceContext &env, int32_t &displayId,
        double &displayX, double &displayY);
    static void SetScrollSwitchSetterPid(int32_t pid);
    std::shared_ptr<IInputEventHandler> GetEventNormalizeHandler() const;
    std::shared_ptr<IInputEventHandler> GetDispatchHandler() const;
    std::shared_ptr<ITimerManager> GetTimerManager() const;
    std::shared_ptr<IInputWindowsManager> GetInputWindowsManager() const;
    std::shared_ptr<IInputDeviceManager> GetDeviceManager() const;
    std::shared_ptr<IPreferenceManager> GetPreferenceManager() const;
    std::shared_ptr<ISettingManager> GetSettingManager() const;

private:
    IInputServiceContext *env_ { nullptr };
    static std::atomic_int32_t globalPointerSpeed_;
    static std::atomic_int32_t globalScrollSwitchPid_;
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    static std::atomic_bool isVirtualDeviceEvent_;
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
    std::shared_ptr<PointerEvent> pointerEvent_ { nullptr };
    int32_t timerId_ { -1 };
    int32_t buttonId_ { -1 };
    uint32_t pressedButton_ { 0 };
    bool isPressed_ { false };
    int32_t deviceId_ { -1 };
    bool isAxisBegin_ { false };
    Movement unaccelerated_ {};
    std::map<int32_t, int32_t> buttonMapping_;
    Aggregator aggregator_ {
            [this](int32_t intervalMs, int32_t repeatCount, std::function<void()> callback) -> int32_t {
                return env_->GetTimerManager()->AddTimer(intervalMs, repeatCount, std::move(callback));
            },
            [this](int32_t timerId) -> int32_t
            {
                return env_->GetTimerManager()->ResetTimer(timerId);
            },
            [this](int32_t timerId) -> int32_t
            {
                return env_->GetTimerManager()->RemoveTimer(timerId);
            }
    };
    bool enableMouseAleaccelerateBool_ { true };
#ifdef OHOS_BUILD_MOUSE_REPORTING_RATE
    struct FilterInsertionPoint filterInsertionPoint_;
#endif // OHOS_BUILD_MOUSE_REPORTING_RATE
};
} // namespace MMI
} // namespace OHOS
#endif // MOUSE_TRANSFORM_PROCESSOR_H