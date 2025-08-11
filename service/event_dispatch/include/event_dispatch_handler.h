/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef EVENT_DISPATCH_HANDLER_H
#define EVENT_DISPATCH_HANDLER_H

#include "i_input_event_handler.h"
#include "key_event_value_transformation.h"
#include "uds_server.h"
#include "window_info.h"

namespace OHOS {
namespace MMI {
class EventDispatchHandler final : public IInputEventHandler {
    struct DinputSimulateEvent {
        uint32_t type { PointerEvent::SOURCE_TYPE_UNKNOWN };
        uint32_t code { PointerEvent::BUTTON_NONE };
        int32_t value { PointerEvent::POINTER_ACTION_UNKNOWN };
    };
public:
    EventDispatchHandler() = default;
    DISALLOW_COPY_AND_MOVE(EventDispatchHandler);
    ~EventDispatchHandler() override = default;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t DispatchKeyEventPid(UDSServer& udsServer, std::shared_ptr<KeyEvent> key);
    int32_t DispatchKeyEvent(int32_t fd, UDSServer& udsServer, std::shared_ptr<KeyEvent> key);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    void HandlePointerEventInner(const std::shared_ptr<PointerEvent> point);
    void NotifyPointerEventToRS(int32_t pointAction, const std::string& programName, uint32_t pid, int32_t pointCnt);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    std::chrono::time_point<std::chrono::high_resolution_clock> LasteventBeginTime_ =
    std::chrono::high_resolution_clock::now();
    void SendWindowStateError(int32_t pid, int32_t windowId);
private:
    void DispatchPointerEventInner(std::shared_ptr<PointerEvent> point, int32_t fd);
    void HandleMultiWindowPointerEvent(std::shared_ptr<PointerEvent> point,
        PointerEvent::PointerItem pointerItem);
    bool ReissueEvent(std::shared_ptr<PointerEvent> &point, int32_t windowId, std::optional<WindowInfo> &windowInfo);
    std::shared_ptr<WindowInfo> SearchCancelList(int32_t pointerId, int32_t windowId);
    bool SearchWindow(std::vector<std::shared_ptr<WindowInfo>> &windowList, std::shared_ptr<WindowInfo> targetWindow);
    int32_t GetClientFd(int32_t pid, std::shared_ptr<PointerEvent> point);
    void UpdateDisplayXY(const std::shared_ptr<PointerEvent> &point);
    void AddFlagToEsc(const std::shared_ptr<KeyEvent> keyEvent);
    void ResetDisplayXY(const std::shared_ptr<PointerEvent> &point);
#ifdef OHOS_BUILD_ENABLE_POINTER
    void EnsureMouseEventCycle(std::shared_ptr<PointerEvent> event);
    void CleanMouseEventCycle(std::shared_ptr<PointerEvent> event);
#endif // OHOS_BUILD_ENABLE_POINTER

    int32_t eventTime_ { 0 };
    int32_t currentTime_ { 0 };
    bool enableMark_ { true };
    bool escToBackFlag_ { false };
    struct {
        double x {};
        double y {};
        bool fixed { false };
    } currentXY_;
    struct {
        int32_t pid { -1 };
        int32_t windowId { -1 };
        int64_t startTime { -1 };
    } windowStateErrorInfo_;
    std::map<int32_t, std::vector<std::shared_ptr<WindowInfo>>> cancelEventList_;
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    void FilterInvalidPointerItem(const std::shared_ptr<PointerEvent> pointEvent, int32_t fd);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    bool AcquireEnableMark(std::shared_ptr<PointerEvent> event);
};
} // namespace MMI
} // namespace OHOS
#endif // EVENT_DISPATCH_HANDLER_H
