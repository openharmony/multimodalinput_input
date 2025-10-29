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

#include <shared_mutex>

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
typedef std::function<int32_t(libinput_event_touch *touch, int32_t& delayMs,
                              std::vector<libinput_event*>& events)> GetLibinputEventForVKeyboard;
typedef std::function<int32_t(libinput_event_touch *touch,
                              std::vector<libinput_event*>& events)> GetLibinputEventForVTrackpad;
typedef std::function<void()> ResetVTrackpadState;
typedef std::function<void()> StopVTrackpadTimer;
typedef std::function<bool(double x, double y)> IsInsideFullKbd;
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
enum VKeyboardEventType {
    NoKeyboardEvent = -1,
    NormalKeyboardEvent = 0,
    HideCursor = 1,
    UpdateCaps = 2,
    StopLongPress = 3
};

enum VTrackpadEventType {
    NoTrackpadEvent = -1,
    NormalTrackpadEvent = 0,
    PinchBegin = 1,
    PinchUpdate = 2,
    PinchEnd = 3,
    SingleTap = 4,
    DoubleTap = 5,
    RemoveTimer = 6,
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
    ~LibinputAdapter();
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
        GetLibinputEventForVTrackpad getLibinputEventForVTrackpad,
        ResetVTrackpadState resetVTrackpadState,
        StopVTrackpadTimer stopVTrackpadTimer,
        IsInsideFullKbd isInsideFullKbd
        );

private:
    void MultiKeyboardSetLedState(bool newCapsLockState);
    void MultiKeyboardSetFuncState(libinput_event* event);
    void OnEventHandler();
    void OnDeviceAdded(std::string path);
    void OnDeviceRemoved(std::string path);
    void InitRightButtonAreaConfig();
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    void ProcessTouchEventAsVKeyboardEvent(libinput_event *event, libinput_event_type eventType, int64_t frameTime);
    void MapTouchToVKeyboardCoordinates(
        libinput_event_touch *touch, int32_t touchId, double &x, double &y, bool &isInsideSpecialWindow);
    bool IsPhoneTouchThpEventOnFullKbd(libinput_event_touch *touch, libinput_event_type eventType, double x, double y);
    void HandleVFullKeyboardMessages(
        libinput_event *event, int64_t frameTime, libinput_event_type eventType, libinput_event_touch *touch);
    void HandleVKeyboardMessage(VKeyboardEventType eventType, std::vector<libinput_event*> &keyboardEvents,
                                int64_t frameTime);
    void HandleVTrackpadMessage(VTrackpadEventType eventType, std::vector<libinput_event*> &events,
                                int64_t frameTime, libinput_event_touch *touch,
                                libinput_event *event, bool& delayvtpDestroy);
    bool IsVKeyboardActivationDropEvent(libinput_event_touch* touch, libinput_event_type eventType);
    void InjectEventForTwoFingerOnTouchpad(libinput_event_touch* touch,
        libinput_event_type eventType, int64_t frameTime);
    void InjectEventForCastWindow(libinput_event_touch* touch);
    bool IsCursorInCastWindow();
    int32_t ConvertToTouchEventType(libinput_event_type eventType);
    void HandleHWKeyEventForVKeyboard(libinput_event* event);
    void HideMouseCursorTemporary();
    double GetAccumulatedPressure(int32_t touchId, int32_t eventType, double touchPressure);
    void DelayInjectKeyEventCallback();
    bool CreateVKeyboardDelayTimer(int32_t delayMs, libinput_event *keyEvent);
    void StartVKeyboardDelayTimer(int32_t delayMs);
    bool GetIsCaptureMode();
    void SafeDestroyVKeyboardDelayedEvent();
    libinput_event_touch* SafeGetVTrackPadTouchEvent();
    void SafeDestroyVTrackPadDelayedEvent();
    void DelayInjectReleaseCallback();
    void DelayInjectPressReleaseCallback();
    void UpdateBootFlag();

    libinput_event *vkbDelayedKeyEvent_ = nullptr;
    libinput_event *vtpDelayedEvent_ = nullptr;
    std::mutex vtrDelayedMutex_;
    int32_t vkbTimerId_ { -1 };
    int32_t vtpTimerId_ { -1 };
    
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
    ResetVTrackpadState resetVTrackpadState_ { nullptr };
    StopVTrackpadTimer stopVTrackpadTimer_ { nullptr };
    IsInsideFullKbd isInsideFullKbd_ { nullptr };
    int32_t deviceId_;
    std::unordered_map<int32_t, std::pair<double, double>> touchPoints_;
    static std::unordered_map<std::string, int32_t> keyCodes_;
    std::unordered_map<int32_t, double> touchPointPressureCache_;

    HotplugDetector hotplugDetector_;
    std::unordered_map<std::string, libinput_device*> devices_;
};
} // namespace MMI
} // namespace OHOS
#endif // S_INPUT_H
