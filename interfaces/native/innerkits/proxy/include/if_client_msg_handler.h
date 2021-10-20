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
#ifndef OHOS_IF_CLIENT_MSG_HANDLER_H
#define OHOS_IF_CLIENT_MSG_HANDLER_H

#include <memory>

namespace OHOS {
namespace MMI {
class UDSClient;
class NetPacket;
class IfClientMsgHandler {
public:
    virtual bool Init() = 0;
    virtual void OnMsgHandler(const UDSClient& client, NetPacket& pkt) = 0;
};

using IClientMsgHandlerPtr = std::shared_ptr<IfClientMsgHandler>;
}
}
#endif
