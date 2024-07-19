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

#ifndef SOCKET_PARAMS_H
#define SOCKET_PARAMS_H

#include <cstdint>

#include "intention_identity.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
enum SocketAction : uint32_t {
    SOCKET_ACTION_UNKNOWN,
    SOCKET_ACTION_CONNECT,
};

struct AllocSocketPairParam final : public ParamBase {
    AllocSocketPairParam() = default;
    AllocSocketPairParam(const std::string &programName, int32_t moduleType);
    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    std::string programName;
    int32_t moduleType { -1 };
};

struct AllocSocketPairReply final : public ParamBase {
    AllocSocketPairReply() = default;
    AllocSocketPairReply(int32_t tokenType, int32_t socketFd);
    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    int32_t tokenType { -1 };
    int32_t socketFd { -1 };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // SOCKET_PARAMS_H