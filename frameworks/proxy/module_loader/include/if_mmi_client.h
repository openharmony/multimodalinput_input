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

#ifndef IF_MMI_CLIENT_H
#define IF_MMI_CLIENT_H

#include "event_handler.h"

namespace OHOS {
namespace MMI {
class NetPacket;
class IfMMIClient;
using MMIClientPtr = std::shared_ptr<IfMMIClient>;
using EventHandlerPtr = std::shared_ptr<AppExecFwk::EventHandler>;
typedef std::function<void(const IfMMIClient&)> ConnectCallback;
class IfMMIClient {
public:
    virtual MMIClientPtr GetSharedPtr() = 0;
    virtual bool GetCurrentConnectedStatus() const = 0;
    virtual bool Start() = 0;
    virtual bool SendMessage(const NetPacket& pkt) const = 0;
    virtual void RegisterConnectedFunction(ConnectCallback fun) = 0;
    virtual void RegisterDisconnectedFunction(ConnectCallback fun) = 0;
    virtual void OnRecvMsg(const char *buf, size_t size) = 0;
    virtual int32_t Reconnect() = 0;
    virtual void OnDisconnect() = 0;
    virtual void SetEventHandler(EventHandlerPtr eventHandler) = 0;
    virtual void MarkIsEventHandlerChanged(EventHandlerPtr eventHandler) = 0;
    virtual bool IsEventHandlerChanged() = 0;
    virtual EventHandlerPtr GetEventHandler() const = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // IF_MMI_CLIENT_H