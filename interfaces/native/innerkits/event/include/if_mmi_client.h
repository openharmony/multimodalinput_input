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
#ifndef IF_MMI_CLIENT_H
#define IF_MMI_CLIENT_H
#include <memory>
#include <functional>
#include "if_client_msg_handler.h"

namespace OHOS::MMI {
class NetPacket;
class IfMMIClient;
typedef std::function<void(const IfMMIClient&)> ConnectCallback;
class IfMMIClient {
public:
    virtual bool GetCurrentConnectedStatus() const = 0;
    virtual bool Start(IClientMsgHandlerPtr msgHdl, bool detachMode) = 0;
    virtual bool SendMessage(const NetPacket& pkt) const = 0;
    virtual void RegisterConnectedFunction(ConnectCallback fun) = 0;
    virtual void RegisterDisconnectedFunction(ConnectCallback fun) = 0;
};
using MMIClientPtr = std::shared_ptr<IfMMIClient>;
}
#endif // IF_MMI_CLIENT_H