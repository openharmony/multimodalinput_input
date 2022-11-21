/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SERVER_MSG_HANDLER_H
#define SERVER_MSG_HANDLER_H

#include "nocopyable.h"

#include "event_dispatch_handler.h"
#include "i_event_filter.h"
#include "input_handler_type.h"
#include "key_option.h"
#include "msg_handler.h"

namespace OHOS {
namespace MMI {
typedef std::function<int32_t(SessionPtr sess, NetPacket& pkt)> ServerMsgFun;
class ServerMsgHandler : public MsgHandler<MmiMessageId, ServerMsgFun> {
public:
    ServerMsgHandler();
    DISALLOW_COPY_AND_MOVE(ServerMsgHandler);
    virtual ~ServerMsgHandler() override;

    void Init(UDSServer& udsServer);
    void OnMsgHandler(SessionPtr sess, NetPacket& pkt);
#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    int32_t OnAddInputHandler(SessionPtr sess, InputHandlerType handlerType, HandleEventType eventType);
    int32_t OnRemoveInputHandler(SessionPtr sess, InputHandlerType handlerType, HandleEventType eventType);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
#ifdef OHOS_BUILD_ENABLE_MONITOR
    int32_t OnMarkConsumed(SessionPtr sess, int32_t eventId);
#endif // OHOS_BUILD_ENABLE_MONITOR
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t OnSubscribeKeyEvent(IUdsServer *server, int32_t pid,
        int32_t subscribeId, const std::shared_ptr<KeyOption> option);
    int32_t OnUnsubscribeKeyEvent(IUdsServer *server, int32_t pid, int32_t subscribeId);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t OnMoveMouse(int32_t offsetX, int32_t offsetY);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t OnInjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent);
    int32_t OnGetFunctionKeyState(int32_t funcKey, bool &state);
    int32_t OnSetFunctionKeyState(int32_t funcKey, bool enable);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    int32_t OnInjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    int32_t AddInputEventFilter(sptr<IEventFilter> filter);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
protected:
    int32_t MarkProcessed(SessionPtr sess, NetPacket& pkt);
    int32_t OnRegisterMsgHandler(SessionPtr sess, NetPacket& pkt);
    int32_t OnDisplayInfo(SessionPtr sess, NetPacket& pkt);

private:
#ifdef OHOS_BUILD_ENABLE_TOUCH
    bool FixTargetWindowId(std::shared_ptr<PointerEvent> pointerEvent, int32_t action);
#endif // OHOS_BUILD_ENABLE_TOUCH

private:
    UDSServer *udsServer_ { nullptr };
    int32_t targetWindowId_ { -1 };
};
} // namespace MMI
} // namespace OHOS
#endif // SERVER_MSG_HANDLER_H
