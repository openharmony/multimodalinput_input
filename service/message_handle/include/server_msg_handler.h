/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "msg_handler.h"
#include "event_dispatch.h"
#include "senior_input_func_proc_base.h"

namespace OHOS {
namespace MMI {
typedef std::function<int32_t(SessionPtr sess, NetPacket& pkt)> ServerMsgFun;
class ServerMsgHandler : public MsgHandler<ServerMsgFun> {
public:
    ServerMsgHandler();
    virtual ~ServerMsgHandler() override;

    bool Init(UDSServer& udsServer);
    void OnMsgHandler(SessionPtr sess, NetPacket& pkt);

#ifdef OHOS_BUILD_AI
    void SetSeniorInputHandle(SeniorInputFuncProcBase& seniorInputFuncProc);
#endif

protected:
    int32_t OnVirtualKeyEvent(SessionPtr sess, NetPacket& pkt);
    int32_t OnRegisterAppInfo(SessionPtr sess, NetPacket& pkt);
    int32_t OnRegisterMsgHandler(SessionPtr sess, NetPacket& pkt);
    int32_t OnUnregisterMsgHandler(SessionPtr sess, NetPacket& pkt);
    int32_t OnSeniorInputFuncProc(SessionPtr sess, NetPacket& pkt);
    int32_t OnListInject(SessionPtr sess, NetPacket& pkt);
#ifdef OHOS_BUILD_HDF
    int32_t OnHdiInject(SessionPtr sess, NetPacket& pkt);
#endif
    int32_t OnWindow(SessionPtr sess, NetPacket& pkt);
    int32_t OnDump(SessionPtr sess, NetPacket& pkt);
    int32_t CheckReplyMessageFormClient(SessionPtr sess, NetPacket& pkt);
    int32_t NewCheckReplyMessageFormClient(SessionPtr sess, NetPacket& pkt);
    int32_t GetMultimodeInputInfo(SessionPtr sess, NetPacket& pkt);
    int32_t OnInjectKeyEvent(SessionPtr sess, NetPacket& pkt);
    int32_t OnNewInjectKeyEvent(SessionPtr sess, NetPacket& pkt);
    int32_t OnInjectPointerEvent(SessionPtr sess, NetPacket& pkt);
    int32_t OnAddKeyEventFilter(SessionPtr sess, NetPacket& pkt);
    int32_t OnRemoveKeyEventFilter(SessionPtr sess, NetPacket& pkt);
    int32_t OnAddTouchEventFilter(SessionPtr sess, NetPacket& pkt);
    int32_t OnRemoveTouchEventFilter(SessionPtr sess, NetPacket& pkt);
    int32_t OnDisplayInfo(SessionPtr sess, NetPacket& pkt);
    int32_t OnAddEventInterceptor(SessionPtr sess, NetPacket& pkt);
    int32_t OnRemoveEventInterceptor(SessionPtr sess, NetPacket& pkt);
    int32_t OnAddInputHandler(SessionPtr sess, NetPacket& pkt);
    int32_t OnRemoveInputHandler(SessionPtr sess, NetPacket& pkt);
    int32_t OnMarkConsumed(SessionPtr sess, NetPacket& pkt);
    int32_t OnInputDevice(SessionPtr sess, NetPacket& pkt);
    int32_t OnInputDeviceIds(SessionPtr sess, NetPacket& pkt);
    int32_t OnAddInputEventMontior(SessionPtr sess, NetPacket& pkt);
    int32_t OnRemoveInputEventMontior(SessionPtr sess, NetPacket& pkt);
    int32_t OnAddInputEventTouchpadMontior(SessionPtr sess, NetPacket& pkt);
    int32_t OnRemoveInputEventTouchpadMontior(SessionPtr sess, NetPacket& pkt);
    int32_t OnSubscribeKeyEvent(SessionPtr sess, NetPacket& pkt);
    int32_t OnUnSubscribeKeyEvent(SessionPtr sess, NetPacket& pkt);
    int32_t OnAddTouchpadEventFilter(SessionPtr sess, NetPacket& pkt);
    int32_t OnRemoveTouchpadEventFilter(SessionPtr sess, NetPacket& pkt);

private:
    UDSServer *udsServer_ = nullptr; // External references, do not delete
    SeniorInputFuncProcBase *seniorInput_ = nullptr;
    EventDispatch eventDispatch_;
    std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent_;
};
} // namespace MMI
} // namespace OHOS
#endif // SERVER_MSG_HANDLER_H