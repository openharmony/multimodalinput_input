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
#ifndef OHOS_SERVER_MSG_HANDLER_H
#define OHOS_SERVER_MSG_HANDLER_H
#include "msg_handler.h"
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
    int32_t GetMultimodeInputInfo(SessionPtr sess, NetPacket& pkt);
    int32_t OnInjectKeyEvent(SessionPtr sess, NetPacket& pkt);
#ifdef OHOS_AUTO_TEST_FRAME
    int32_t AutoTestFrameRegister(SessionPtr sess, NetPacket& pkt);
    int32_t AutoTestReceiveClientPkt(SessionPtr sess, NetPacket& pkt);
#endif  // OHOS_AUTO_TEST_FRAME

private:
    UDSServer *udsServer_ = nullptr; // External references, do not delete
    SeniorInputFuncProcBase *seniorInput_ = nullptr;
};
}
}
#endif
