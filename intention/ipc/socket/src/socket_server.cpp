/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "socket_server.h"

#include "accesstoken_kit.h"

#include "devicestatus_define.h"
#include "socket_params.h"

#undef LOG_TAG
#define LOG_TAG "SocketServer"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

SocketServer::SocketServer(IContext *context)
    : context_(context)
{}

int32_t SocketServer::Enable(CallingContext &context, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

int32_t SocketServer::Disable(CallingContext &context, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

int32_t SocketServer::Start(CallingContext &context, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

int32_t SocketServer::Stop(CallingContext &context, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

int32_t SocketServer::AddWatch(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

int32_t SocketServer::RemoveWatch(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

int32_t SocketServer::SetParam(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

int32_t SocketServer::GetParam(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

int32_t SocketServer::Control(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    if (id != SocketAction::SOCKET_ACTION_CONNECT) {
        FI_HILOGE("Unsupported action");
        return RET_ERR;
    }
    AllocSocketPairParam param;
    if (!param.Unmarshalling(data)) {
        FI_HILOGE("AllocSocketPairParam::Unmarshalling fail");
        return RET_ERR;
    }
    int32_t tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    int32_t clientFd { -1 };
    CHKPR(context_, RET_ERR);
    int32_t ret = context_->GetSocketSessionManager().AllocSocketFd(
        param.programName, param.moduleType, tokenType, context.uid, context.pid, clientFd);
    if (ret != RET_OK) {
        FI_HILOGE("AllocSocketFd failed");
        return RET_ERR;
    }
    AllocSocketPairReply replyData(tokenType, clientFd);
    if (!replyData.Marshalling(reply)) {
        FI_HILOGE("AllocSocketPairReply::Marshalling fail");
        return RET_ERR;
    }
    return RET_OK;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
