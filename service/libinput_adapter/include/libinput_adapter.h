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
 
#ifndef LIBINPUT_ADAPTER_H
#define LIBINPUT_ADAPTER_H

#include "hotplug_detector.h"
#include "libinput.h"

namespace OHOS {
namespace MMI {
typedef std::function<void(void *event, int64_t frameTime)> FunInputEvent;
typedef std::function<int32_t(double screenX,
                              double screenY,
                              int touchId,
                              int32_t eventType,
                              double touchPressure,
                              int32_t longAxis,
                              int32_t shortAxis)> HandleTouchPoint;
typedef std::function<void(const std::string &keyName)> HardwareKeyEventDetected;
typedef std::function<int32_t()> GetKeyboardActivationState;
typedef std::function<bool()> IsFloatingKeyboard;
typedef std::function<bool()> IsVKeyboardShown;
typedef std::function<int32_t(libinput_event_touch *touch, int32_t& delayMs, std::vector<libinput_event*>& events)> GetLibinputEventForVKeyboard;
typedef std::function<int32_t(libinput_event_touch *touch, std::vector<libinput_event*>& events)> GetLibinputEventForVTrackpad;

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
enum VTPSwipeStateType {
    SWIPE_BEGIN = 1,
    SWIPE_UPDATE = 2,
    SWIPE_END = 3,
};
enum VKeyboardMessageType {
    VNoMessage = -1,
    VKeyPressed = 0,
    VCombinationKeyPressed = 1,
    VStartLongPressControl = 16,
    VStopLongPressControl = 17,
    VSwitchLayout = 18,
};
enum VKeyboardEventType {
    NoKeyboardEvent = -1,
    NormalKeyboardEvent = 0,
    HideCursor = 1,
    UpdateCaps = 2,
    StopLongpress = 3
};

enum VTrackpadEventType {
    NoTrackpadEvent = -1,
    NormalTrackpadEvent = 0,
    PinchBegin = 1,
    PinchUpdate = 2,
    PinchEnd = 3
};
enum class VTPStateMachineMessageType : int32_t {
    UNKNOWN = 0,
    POINTER_MOVE = 1,
    LEFT_CLICK_DOWN = 2,
    LEFT_CLICK_UP = 3,
    RIGHT_CLICK_DOWN = 4,
    RIGHT_CLICK_UP = 5,
    SCROLL_BEGIN = 6,
    SCROLL_UPDATE = 7,
    SCROLL_END = 8,
    PINCH_BEGIN = 9,
    PINCH_UPDATE = 10,
    PINCH_END = 11,
    PAN_BEGIN = 12,
    PAN_UPDATE = 13,
    PAN_END = 14,
    ROT_BEGIN = 15,
    ROT_UPDATE = 16,
    ROT_END = 17,
    LEFT_TOUCH_DOWN = 18,
    LEFT_TOUCH_UP = 19,
    TWO_FINGER_TAP = 20,
    LEFT_TOUCH_UP_CANCEL = 21,
    SWIPE_BEGIN = 22,
    SWIPE_UPDATE = 23,
    SWIPE_END = 24,
    SWIPE_FOUR_BEGIN = 25,
    SWIPE_FOUR_UPDATE = 26,
    SWIPE_FOUR_END = 27,
};

enum class VKeyboardActivation : int32_t {
    INACTIVE = 0,
    ACTIVATED = 1,
    TOUCH_CANCEL = 2,
    TOUCH_DROP = 3,
    EIGHT_FINGERS_UP = 4,
};
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
class LibinputAdapter final {
public:
    static int32_t DeviceLedUpdate(struct libinput_device *device, int32_t funcKey, bool isEnable);
    LibinputAdapter() = default;
    DISALLOW_COPY_AND_MOVE(LibinputAdapter);
    ~LibinputAdapter() = default;
    bool Init(FunInputEvent funInputEvent);
    void EventDispatch(int32_t fd);
    void Stop();
    void ProcessPendingEvents();
    void ReloadDevice();
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    static void SetBootCompleted();
    void RegisterBootStatusReceiver();
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

    auto GetInputFds() const
    {
        return std::array{fd_, hotplugDetector_.GetFd()};
    }
	
    void InitVKeyboard(HandleTouchPoint handleTouchPoint,
        HardwareKeyEventDetected hardwareKeyEventDetected,
        GetKeyboardActivationState getKeyboardActivationState,
        IsFloatingKeyboard isFloatingKeyboard,
        IsVKeyboardShown isVKeyboardShown,
		GetLibinputEventForVKeyboard getLibinputEventForVKeyboard,
        GetLibinputEventForVTrackpad getLibinputEventForVTrackpad
        );

private:
    void MultiKeyboardSetLedState(bool oldCapsLockState);
    void MultiKeyboardSetFuncState(libinput_event* event);
    void OnEventHandler();
    void OnDeviceAdded(std::string path);
    void OnDeviceRemoved(std::string path);
    void InitRightButtonAreaConfig();
	//test
    void InjectKeyEvent(libinput_event_touch* touch, int32_t keyCode, libinput_key_state state, int64_t frameTime);
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    void HandleVFullKeyboardMessages(
        libinput_event *event, int64_t frameTime, libinput_event_type eventType, libinput_event_touch *touch);
    bool IsVKeyboardActivationDropEvent(libinput_event_touch* touch, libinput_event_type eventType);
    void InjectEventForTwoFingerOnTouchpad(libinput_event_touch* touch,
        libinput_event_type eventType, int64_t frameTime);
    void InjectEventForCastWindow(libinput_event_touch* touch);
    bool IsCursorInCastWindow();
    int32_t ConvertToTouchEventType(libinput_event_type eventType);
    void HandleHWKeyEventForVKeyboard(libinput_event* event);
    void ShowMouseCursor();
    void HideMouseCursorTemporary();
    double GetAccumulatedPressure(int touchId, int32_t eventType, double touchPressure);
    bool SkipTouchMove(int touchId, int32_t eventType); // compress touch move events in consecutive two frame
    void DelayInjectKeyEventCallback();
    bool CreateVKeyboardDelayTimer(libinput_event *event, int32_t delayMs, libinput_event *keyEvent);
    void StartVKeyboardDelayTimer(int32_t delayMs);
    bool GetIsCaptureMode();
    void UpdateBootFlag();
    VTPSwipeStateType vtpSwipeState_ = VTPSwipeStateType::SWIPE_END;

    libinput_event *vkbDelayedEvent_ = nullptr;
	libinput_event *vkbDelayedKeyEvent_ = nullptr;
    int32_t vkbDelayedKeyCode_ = 0;
    std::chrono::system_clock::time_point vtpSingleTapDownTime;
    const double vtpSingleTapThreshold = 0.18; // s
    // set as true once subscriber succeeded.
    std::atomic_bool hasInitSubscriber_ { false };
    static std::atomic_bool isBootCompleted_;
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
    int32_t fd_ { -1 };
    libinput *input_ { nullptr };

    FunInputEvent funInputEvent_;
    HandleTouchPoint handleTouchPoint_ { nullptr };
    HardwareKeyEventDetected hardwareKeyEventDetected_ { nullptr };
    GetKeyboardActivationState getKeyboardActivationState_ { nullptr };
    IsFloatingKeyboard isFloatingKeyboard_ { nullptr };
    IsVKeyboardShown isVKeyboardShown_ { nullptr };
	GetLibinputEventForVKeyboard getLibinputEventForVKeyboard_ { nullptr };
    GetLibinputEventForVTrackpad getLibinputEventForVTrackpad_ { nullptr };
    int32_t deviceId;
    std::unordered_map<int32_t, std::pair<double, double>> touchPoints_;
    static std::unordered_map<std::string, int32_t> keyCodes_;
    std::unordered_map<int32_t, double> touchPointPressureCache_;

    HotplugDetector hotplugDetector_;
    std::unordered_map<std::string, libinput_device*> devices_;
};
} // namespace MMI
} // namespace OHOS
#endif // S_INPUT_H
