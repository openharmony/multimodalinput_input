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

#ifndef EVENT_PRE_MONITOR_HANDLER_H
#define EVENT_PRE_MONITOR_HANDLER_H

#include <mutex>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include "nocopyable.h"

#include "i_input_event_collection_handler.h"
#include "i_input_event_handler.h"
#include "input_handler_type.h"
#include "uds_session.h"

namespace OHOS {
namespace MMI {
class EventPreMonitorHandler final : public IInputEventHandler {
public:
    EventPreMonitorHandler() = default;
    DISALLOW_COPY_AND_MOVE(EventPreMonitorHandler);
    ~EventPreMonitorHandler() override = default;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_TOUCH

    int32_t AddInputHandler(SessionPtr sess, int32_t handlerId, HandleEventType eventType, std::vector<int32_t> keys);
    void RemoveInputHandler(SessionPtr sess, int32_t handlerId);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    bool OnHandleEvent(std::shared_ptr<KeyEvent> KeyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    bool OnHandleEvent(std::shared_ptr<PointerEvent> PointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    void Dump(int32_t fd, const std::vector<std::string> &args);

private:
    void InitSessionLostCallback();
    void OnSessionLost(SessionPtr session);

private:
    class SessionHandler {
    public:
        SessionHandler(SessionPtr session, int32_t handlerId, HandleEventType eventType, std::vector<int32_t> keys)
            : session_(session), handlerId_(handlerId), eventType_(eventType), keys_(keys)
        {}

        SessionHandler(const SessionHandler& other)
        {
            session_ = other.session_;
            handlerId_ = other.handlerId_;
            eventType_ = other.eventType_;
            keys_ = other.keys_;
        }

        void SendToClient(std::shared_ptr<KeyEvent> keyEvent, NetPacket &pkt, int32_t handlerId) const;
        bool operator<(const SessionHandler& other) const
        {
            return (session_ < other.session_);
        }

        SessionPtr session_ { nullptr };
        int32_t handlerId_;
        HandleEventType eventType_;
        std::shared_ptr<IInputEventConsumer> callback_ { nullptr };
        std::vector<int32_t> keys_;
    };

    class MonitorCollection : public IInputEventCollectionHandler, protected NoCopyable {
    public:
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
        virtual bool HandleEvent(std::shared_ptr<KeyEvent> KeyEvent) override;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
        virtual bool HandleEvent(std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
        int32_t AddMonitor(const std::shared_ptr<SessionHandler> monitor, std::vector<int32_t> keys);
        void RemoveMonitor(SessionPtr sess, int32_t handlerId);
        bool IsEqualsKeys(std::vector<int32_t> newKeys, std::vector<int32_t> oldKeys);

        void OnSessionLost(SessionPtr session);
        void Dump(int32_t fd, const std::vector<std::string> &args);

    private:
        std::map<std::vector<int32_t>, std::list<std::shared_ptr<SessionHandler>>> sessionHandlers_;
    };

private:
    bool sessionLostCallbackInitialized_ { false };
    MonitorCollection monitors_;
};
} // namespace MMI
} // namespace OHOS
#endif // EVENT_PRE_MONITOR_HANDLER_H