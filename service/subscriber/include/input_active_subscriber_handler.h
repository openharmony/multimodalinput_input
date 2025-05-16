/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef INPUT_ACTIVE_SUBSCRIBER_HANDLER_H
#define INPUT_ACTIVE_SUBSCRIBER_HANDLER_H

#include <mutex>
#include "i_input_event_handler.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
class InputActiveSubscriberHandler final : public IInputEventHandler {
public:
    InputActiveSubscriberHandler() = default;
    DISALLOW_COPY_AND_MOVE(InputActiveSubscriberHandler);
    ~InputActiveSubscriberHandler() = default;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
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
    int32_t SubscribeInputActive(SessionPtr sess, int32_t subscribeId, int64_t interval);
    int32_t UnsubscribeInputActive(SessionPtr sess, int32_t subscribeId);
    void Dump(int32_t fd, const std::vector<std::string> &args);
private:
    enum EventType : uint32_t {
        EVENTTYPE_INVALID = 0,
        EVENTTYPE_KEY,
        EVENTTYPE_POINTER,
    };
    struct Subscriber {
        Subscriber(int32_t id, SessionPtr sess, int64_t interval) : id_(id), sess_(sess), interval_(interval) {}
        int32_t id_ { -1 };
        SessionPtr sess_ { nullptr };
        int32_t timerId_ { INVALID_TIMERID };
        int64_t interval_ { 0 };
        EventType lastEventType_ { EVENTTYPE_INVALID };
        int64_t sendEventLastTime_ { 0 };
        std::shared_ptr<KeyEvent> keyEvent_ { nullptr };
        std::shared_ptr<PointerEvent> pointerEvent_ { nullptr };
    };

    void InsertSubscriber(std::shared_ptr<Subscriber> subscriber);
    void OnSubscribeInputActive(const std::shared_ptr<KeyEvent> keyEvent);
    void OnSubscribeInputActive(const std::shared_ptr<PointerEvent> pointerEvent);
    void NotifySubscriber(const std::shared_ptr<KeyEvent> keyEvent, const std::shared_ptr<Subscriber> subscriber);
    void NotifySubscriber(
        const std::shared_ptr<PointerEvent> pointerEvent, const std::shared_ptr<Subscriber> subscriber);
    void OnSessionDelete(SessionPtr sess);
    bool InitSessionDeleteCallback();
    bool IsImmediateNotifySubscriber(std::shared_ptr<Subscriber> subscriber, int64_t eventTime);
    void StartIntervalTimer(std::shared_ptr<Subscriber> subscriber, int64_t eventTime);
    void CleanSubscribeInfo(std::shared_ptr<Subscriber> subscriber, int64_t eventTime);
private:
    std::list<std::shared_ptr<Subscriber>> subscribers_;
    std::atomic_bool callbackInitialized_ { false };
    static constexpr int32_t INVALID_TIMERID = -1;
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_ACTIVE_SUBSCRIBER_HANDLER_H