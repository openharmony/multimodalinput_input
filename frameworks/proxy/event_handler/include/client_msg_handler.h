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
#ifndef CLIENT_MSG_HANDLER_H
#define CLIENT_MSG_HANDLER_H

#include "nocopyable.h"

#include "if_client_msg_handler.h"
#include "key_event_input_subscribe_manager.h"
#include "msg_handler.h"
#include "uds_client.h"

namespace OHOS {
namespace MMI {
typedef std::function<int32_t(const UDSClient&, NetPacket&)> ClientMsgFun;
class ClientMsgHandler : public MsgHandler<ClientMsgFun>,
    public IfClientMsgHandler, public std::enable_shared_from_this<IfClientMsgHandler> {
public:
    ClientMsgHandler();
    DISALLOW_COPY_AND_MOVE(ClientMsgHandler);
    virtual ~ClientMsgHandler();
    virtual bool Init() override;
    virtual void OnMsgHandler(const UDSClient& client, NetPacket& pkt) override;
    virtual MsgClientFunCallback GetCallback() override;

protected:
    virtual int32_t OnKeyEvent(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnKeyMonitor(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnTouchPadMonitor(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnPointerEvent(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnSubscribeKeyEventCallback(const UDSClient& client, NetPacket& pkt);
    virtual int32_t GetMultimodeInputInfo(const UDSClient& client, NetPacket& pkt);
    virtual int32_t ReportKeyEvent(const UDSClient& client, NetPacket& pkt);
    virtual int32_t ReportPointerEvent(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnInputDevice(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnInputDeviceIds(const UDSClient& client, NetPacket& pkt);
    virtual int32_t TouchpadEventInterceptor(const UDSClient& client, NetPacket& pkt);
    virtual int32_t KeyEventInterceptor(const UDSClient& client, NetPacket& pkt);

private:
    static void OnEventProcessed(int32_t eventId);

private:
    std::function<void(int32_t)> eventProcessedCallback_;
};
} // namespace MMI
} // namespace OHOS
#endif // CLIENT_MSG_HANDLER_H
