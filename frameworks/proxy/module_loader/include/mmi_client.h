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
#ifndef MMI_CLIENT_H
#define MMI_CLIENT_H
#include "nocopyable.h"
#include "if_mmi_client.h"
#include "client_msg_handler.h"
#include "mmi_event_handler.h"

namespace OHOS {
namespace MMI {
class MMIClient : public UDSClient, public IfMMIClient, public std::enable_shared_from_this<IfMMIClient> {
public:
    MMIClient();
    DISALLOW_COPY_AND_MOVE(MMIClient);
    virtual ~MMIClient() override;

    int32_t Socket() override;
    virtual void Stop() override;
    virtual bool SendMessage(const NetPacket& pkt) const override;
    virtual bool GetCurrentConnectedStatus() const override;

    bool Start(bool detachMode) override;
    void RegisterConnectedFunction(ConnectCallback fun) override;
    void RegisterDisconnectedFunction(ConnectCallback fun) override;
    void VirtualKeyIn(RawInputEvent virtualKeyEvent);

    MMIClientPtr GetSharedPtr()
    {
        return shared_from_this();
    }

protected:
    virtual void OnConnected() override;
    virtual void OnDisconnected() override;
    void OnMsgHandler(NetPacket& pkt);
    
    void OnEventHandlerThread();
    bool StartEventRunner();

protected:
    ClientMsgHandler msgHandler_;
    ConnectCallback funConnected_;
    ConnectCallback funDisconnected_;

    std::thread ehThread_;
    bool selfRunner_ = false;
    std::shared_ptr<MMIEventHandler> eventHandler_ = nullptr;
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_CLIENT_H
