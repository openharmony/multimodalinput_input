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

#ifndef I_SOCKET_SESSION_H
#define I_SOCKET_SESSION_H

#include <cstdint>
#include <memory>
#include <string>

#include "net_packet.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
enum TokenType : int32_t {
    TOKEN_INVALID = -1,
    TOKEN_HAP = 0,
    TOKEN_NATIVE,
    TOKEN_SHELL
};

class ISocketSession {
public:
    ISocketSession() = default;
    virtual ~ISocketSession() = default;

    virtual bool SendMsg(NetPacket &pkt) const = 0;

    virtual int32_t GetUid() const = 0;
    virtual int32_t GetPid() const = 0;
    virtual int32_t GetFd() const = 0;
    virtual std::string ToString() const = 0;
    virtual std::string GetProgramName() const = 0;
    virtual void SetProgramName(const std::string &programName) = 0;
};

using SocketSessionPtr = std::shared_ptr<ISocketSession>;
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // I_SOCKET_SESSION_H
