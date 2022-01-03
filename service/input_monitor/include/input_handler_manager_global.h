/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_MULTIMDOALINPUT_INPUT_HANDLER_MANAGER_GLOBAL_H
#define OHOS_MULTIMDOALINPUT_INPUT_HANDLER_MANAGER_GLOBAL_H
#include <mutex>
#include <set>
#include "input_handler_type.h"
#include "i_input_event_handler.h"
#include "uds_session.h"
#include "singleton.h"

namespace OHOS {
namespace MMI {
class InputHandlerManagerGlobal : public Singleton<OHOS::MMI::InputHandlerManagerGlobal> {
public:
    int32_t AddInputHandler(int32_t handlerId, InputHandlerType handlerType, SessionPtr session);
    void RemoveInputHandler(int32_t handlerId, InputHandlerType handlerType, SessionPtr session);
    void MarkConsumed(int32_t handlerId, int32_t eventId, SessionPtr session);
    bool HandleEvent(std::shared_ptr<KeyEvent> KeyEvent);
    bool HandleEvent(std::shared_ptr<PointerEvent> PointerEvent);

private:
    struct SessionMonitor {
        SessionMonitor(int32_t id, SessionPtr session)
            : id_(id), session_(session) { }
        void SendToClient(std::shared_ptr<KeyEvent> keyEvent) const;
        void SendToClient(std::shared_ptr<PointerEvent> pointerEvent) const;
        bool operator<(const SessionMonitor& other) const
        {
            return ((id_ < other.id_) && (session_ < other.session_));
        }
        int32_t id_;
        SessionPtr session_;
    };
    struct MonitorCollection : public IInputEventHandler, protected NoCopyable {
        virtual int32_t GetPriority() const override;
        virtual bool HandleEvent(std::shared_ptr<KeyEvent> KeyEvent) override;
        virtual bool HandleEvent(std::shared_ptr<PointerEvent> PointerEvent) override;

        int32_t AddMonitor(const SessionMonitor& mon);
        void RemoveMonitor(const SessionMonitor& mon);
        void MarkConsumed(int32_t monitorId, int32_t eventId, SessionPtr session);

        void SendToSession(SessionPtr session, int32_t handleId, std::shared_ptr<KeyEvent> keyEvent);
        void SendToSession(SessionPtr session, int32_t handleId, std::shared_ptr<PointerEvent> pointerEvent);

        std::set<SessionMonitor> monitors_;
        std::shared_ptr<PointerEvent> downEvent_;
        std::shared_ptr<PointerEvent> pointerEvent_;

        bool monitorConsumed_ { false };
        const size_t MAX_N_MONITORS { 64 };
    };
private:
    MonitorCollection monitors_;
};
}
} // namespace OHOS::MMI

#endif // OHOS_MULTIMDOALINPUT_INPUT_HANDLER_MANAGER_GLOBAL_H
