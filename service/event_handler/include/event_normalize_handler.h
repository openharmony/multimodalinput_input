/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef EVENT_NORMALIZE_HANDLER_H
#define EVENT_NORMALIZE_HANDLER_H

#include "i_input_event_handler.h"
#include "key_event_normalize.h"
#include "plugin_stage.h"

namespace OHOS {
namespace MMI {
class EventNormalizeHandler : public IInputEventHandler {
public:
    EventNormalizeHandler() = default;
    ~EventNormalizeHandler() = default;
    void HandleEvent(libinput_event* event, int64_t frameTime);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
    int32_t GetCurrentHandleKeyCode()
    {
        return currentHandleKeyCode_;
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_SWITCH
    void HandleSwitchEvent(const std::shared_ptr<SwitchEvent> switchEvent) override;
#endif // OHOS_BUILD_ENABLE_SWITCH
    int32_t AddHandleTimer(int32_t timeout = 300);
#ifdef OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
    int32_t SetMoveEventFilters(bool flag);
#endif // OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
    void BypassChainAndDispatchDirectly(std::shared_ptr<PointerEvent> pointerEvent);

private:
    int32_t OnEventDeviceAdded(libinput_event *event);
    int32_t OnEventDeviceRemoved(libinput_event *event);
    int32_t HandleKeyboardEvent(libinput_event* event);
    void Repeat(const std::shared_ptr<KeyEvent> keyEvent);
    bool HandleTouchPadTripleTapEvent(std::shared_ptr<PointerEvent> pointerEvent);
#ifndef OHOS_BUILD_ENABLE_WATCH
    int32_t HandleTouchPadEvent(libinput_event* event);
    int32_t HandleTouchPadAction(libinput_event* event);
    int32_t HandleGestureEvent(libinput_event* event);
    int32_t HandleTableToolEvent(libinput_event* event);
#endif // OHOS_BUILD_ENABLE_WATCH
    int32_t HandleMouseEvent(libinput_event* event);
    int32_t HandleTouchEvent(libinput_event* event, int64_t frameTime);
    int32_t HandleSwitchInputEvent(libinput_event* event);
#ifdef OHOS_BUILD_ENABLE_JOYSTICK
    int32_t HandleJoystickButtonEvent(libinput_event *event);
    int32_t HandleJoystickAxisEvent(libinput_event *event);
#endif // OHOS_BUILD_ENABLE_JOYSTICK
    void HandlePalmEvent(libinput_event* event, std::shared_ptr<PointerEvent> pointerEvent);
    bool JudgeIfSwipeInward(std::shared_ptr<PointerEvent> pointerEvent,
        enum libinput_event_type type, libinput_event* event);
    void SwipeInwardProcess(std::shared_ptr<PointerEvent> pointerEvent, libinput_event* event);
    void SwipeInwardButtonJudge(std::shared_ptr<PointerEvent> pointerEvent);
    void SwipeInwardSpeedJudge(std::shared_ptr<PointerEvent> pointerEvent);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void UpdateKeyEventHandlerChain(const std::shared_ptr<KeyEvent> keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
    bool HandleTouchEventWithFlag(const std::shared_ptr<PointerEvent> pointerEvent);
    double CalcTouchOffset(const std::shared_ptr<PointerEvent> touchMoveEvent);
#endif // OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
    int32_t SetOriginPointerId(std::shared_ptr<PointerEvent> pointerEvent);
    void PointerEventSetPressedKeys(std::shared_ptr<PointerEvent> pointerEvent);
    bool TouchPadKnuckleDoubleClickHandle(libinput_event* event);
    bool HandleTouchPadEdgeSwipe(libinput_event* event);
    int32_t GetToolType(libinput_event* event);

private:
    int32_t timerId_ { -1 };
    bool isShield_ { false };
    std::set<int32_t> buttonIds_ {};
    int32_t currentHandleKeyCode_ { -1 };
    double currentPointDownPosX_ { 0.0 };
    int64_t currentPointDownTime_ { 0 };
#ifdef OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
    bool moveEventFilterFlag_ { false };
    std::list<PointerEvent::PointerItem> lastTouchDownItems_;
#endif // OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
#ifdef OHOS_BUILD_ENABLE_POINTER
    static int32_t tpRegisterTryCount_;
#endif // OHOS_BUILD_ENABLE_POINTER
    void ResetTouchUpEvent(std::shared_ptr<PointerEvent> pointerEvent, struct libinput_event *event);
    bool ProcessNullEvent(libinput_event *event, int64_t frameTime);
#ifdef OHOS_BUILD_ENABLE_SWITCH
    void RestoreTouchPadStatus();
#endif // OHOS_BUILD_ENABLE_SWITCH
    void TerminateAxis(libinput_event* event);
    void CancelTwoFingerAxis(libinput_event* event);
    bool IsAccessibilityEventWithZOrder(std::shared_ptr<PointerEvent> pointerEvent);
};
} // namespace MMI
} // namespace OHOS
#endif // EVENT_NORMALIZE_HANDLER_H