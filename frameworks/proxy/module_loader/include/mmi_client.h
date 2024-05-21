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

#ifndef MMI_CLIENT_H
#define MMI_CLIENT_H

#include "nocopyable.h"

#include "if_mmi_client.h"

#include "circle_stream_buffer.h"
#include "client_msg_handler.h"

namespace OHOS {
namespace MMI {
class MMIClient final : public UDSClient, public IfMMIClient, public std::enable_shared_from_this<IfMMIClient> {
public:
    MMIClient() = default;
    DISALLOW_COPY_AND_MOVE(MMIClient);
    ~MMIClient() override;

    int32_t Socket() override;
    void SetEventHandler(EventHandlerPtr eventHandler) override;
    void MarkIsEventHandlerChanged(EventHandlerPtr eventHandler) override;
    bool Start() override;
    void RegisterConnectedFunction(ConnectCallback fun) override;
    void RegisterDisconnectedFunction(ConnectCallback fun) override;
    void Stop() override;
    bool SendMessage(const NetPacket& pkt) const override;
    bool GetCurrentConnectedStatus() const override;
    void OnRecvMsg(const char *buf, size_t size) override;
    int32_t Reconnect() override;
    void OnDisconnect() override;
    MMIClientPtr GetSharedPtr() override;
    bool IsEventHandlerChanged() override
    {
        return isEventHandlerChanged_;
    }
    EventHandlerPtr GetEventHandler() const override;

private:
    bool StartEventRunner();
    void OnReconnect();
    bool AddFdListener(int32_t fd);
    bool DelFdListener(int32_t fd);
    void OnPacket(NetPacket& pkt);
    const std::string& GetErrorStr(ErrCode code) const;
    void OnConnected() override;
    void OnDisconnected() override;
    void SetThreadQosLevel(std::shared_ptr<AppExecFwk::EventHandler> handler);

private:
    ClientMsgHandler msgHandler_;
    ConnectCallback funConnected_;
    ConnectCallback funDisconnected_;
    CircleStreamBuffer circBuf_;
    std::mutex mtx_;
    EventHandlerPtr eventHandler_ { nullptr };
    bool isEventHandlerChanged_ { false };
    bool isListening_ { false };
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_CLIENT_H
