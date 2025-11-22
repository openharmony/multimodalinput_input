/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SWITCH_SUBSCRIBER_HANDLER_H
#define SWITCH_SUBSCRIBER_HANDLER_H

#include <atomic>
#include <unordered_map>
#include "i_input_event_handler.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
class SwitchSubscriberHandler final : public IInputEventHandler {
public:
    SwitchSubscriberHandler() = default;
    DISALLOW_COPY_AND_MOVE(SwitchSubscriberHandler);
    ~SwitchSubscriberHandler() = default;
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
    bool PublishTabletEvent(const std::shared_ptr<SwitchEvent> switchEvent);
    bool PublishLidEvent(const std::shared_ptr<SwitchEvent> switchEvent);
    void DumpTabletStandState(int32_t fd, const std::vector<std::string> &args);
    void DumpLidState(int32_t fd, const std::vector<std::string> &args);
#endif // OHOS_BUILD_ENABLE_SWITCH
    int32_t SubscribeSwitchEvent(SessionPtr sess, int32_t subscribeId, int32_t switchType);
    int32_t UnsubscribeSwitchEvent(SessionPtr sess, int32_t subscribeId);
    void Dump(int32_t fd, const std::vector<std::string> &args);
    bool UpdateSwitchState(const std::shared_ptr<SwitchEvent> switchEvent);
    int32_t QuerySwitchStatus(int32_t switchType, int32_t& state);
private:
    struct Subscriber {
        Subscriber(int32_t id, SessionPtr sess, int32_t switchType)
            : id_(id), sess_(sess), switchType_(switchType), timerId_(-1) {}
        int32_t id_ { -1 };
        SessionPtr sess_ { nullptr };
        int32_t switchType_ { -1 };
        int32_t timerId_ { -1 };
        std::shared_ptr<SwitchEvent> switchEvent_ { nullptr };
    };
    void InsertSubScriber(std::shared_ptr<Subscriber> subs);

private:
    bool OnSubscribeSwitchEvent(std::shared_ptr<SwitchEvent> keyEvent);
    void NotifySubscriber(std::shared_ptr<SwitchEvent> keyEvent,
        const std::shared_ptr<Subscriber> &subscriber);
    void OnSessionDelete(SessionPtr sess);
    bool InitSessionDeleteCallback();

private:
    std::list<std::shared_ptr<Subscriber>> subscribers_ {};
    std::atomic_bool callbackInitialized_ { false };
    std::shared_ptr<SwitchEvent> switchEvent_ { nullptr };
    std::unordered_map<int32_t, int32_t> switchStateRecord_;
    std::atomic<int32_t> lidState_{ 0 };
    std::atomic<int32_t> tabletStandState_{ 0 };
};
} // namespace MMI
} // namespace OHOS
#endif // SWITCH_SUBSCRIBER_HANDLER_H
