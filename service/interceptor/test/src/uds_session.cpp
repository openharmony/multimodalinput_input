/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "uds_session.h"
#include "input_event_data_transformation.h"

namespace OHOS {
namespace MMI {
void UDSSession::Close()
{
    keyEvents_.clear();
}

bool UDSSession::SendMsg(NetPacket &pkt)
{
    auto keyEvent = KeyEvent::Create();
    CHKPF(keyEvent);
    auto ret = InputEventDataTransformation::NetPacketToKeyEvent(pkt, keyEvent);
    if (ret != RET_OK) {
        return false;
    }
    keyEvents_.push_back(keyEvent);
    return true;
}

int32_t UDSSession::GetUid() const
{
    return -1;
}

int32_t UDSSession::GetPid() const
{
    return -1;
}

int32_t UDSSession::GetModuleType() const
{
    return -1;
}

int32_t UDSSession::GetFd() const
{
    return -1;
}

const std::string UDSSession::GetDescript() const
{
    return std::string();
}

const std::string UDSSession::GetProgramName() const
{
    return std::string();
}

int32_t UDSSession::GetTokenType() const
{
    return tokenType_;
}

int64_t UDSSession::GetEarliestEventTime(int32_t type) const
{
    return -1;
}

SessionPtr UDSSession::GetSharedPtr()
{
    return nullptr;
}

void UDSSession::SetTokenType(int32_t type)
{
    tokenType_ = type;
}

void UDSSession::SetTokenId(uint32_t tokenId)
{}

void UDSSession::SetIsRealProcessName(bool isRealProcessName)
{}
} // namespace MMI
} // namespace OHOS
