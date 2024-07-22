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

#include "socket_params.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
AllocSocketPairParam::AllocSocketPairParam(const std::string &programName, int32_t moduleType)
    : programName(programName), moduleType(moduleType)
{}

bool AllocSocketPairParam::Marshalling(MessageParcel &parcel) const
{
    return (
        parcel.WriteString(programName) &&
        parcel.WriteInt32(moduleType)
    );
}

bool AllocSocketPairParam::Unmarshalling(MessageParcel &parcel)
{
    return (
        parcel.ReadString(programName) &&
        parcel.ReadInt32(moduleType)
    );
}

AllocSocketPairReply::AllocSocketPairReply(int32_t tokenType, int32_t socketFd)
    : tokenType(tokenType), socketFd(socketFd)
{}

bool AllocSocketPairReply::Marshalling(MessageParcel &parcel) const
{
    return (
        parcel.WriteInt32(tokenType) &&
        parcel.WriteFileDescriptor(socketFd)
    );
}

bool AllocSocketPairReply::Unmarshalling(MessageParcel &parcel)
{
    bool ret = parcel.ReadInt32(tokenType);
    socketFd = parcel.ReadFileDescriptor();
    return (ret && (socketFd >= 0));
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
