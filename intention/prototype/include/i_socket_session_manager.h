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

#ifndef I_SOCKET_SESSION_MANAGER_H
#define I_SOCKET_SESSION_MANAGER_H

#include "i_socket_session.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class ISocketSessionManager {
public:
    ISocketSessionManager() = default;
    virtual ~ISocketSessionManager() = default;

    virtual void AddSessionDeletedCallback(int32_t pid, std::function<void(SocketSessionPtr)> callback) = 0;
    virtual void RemoveSessionDeletedCallback(int32_t pid) = 0;
    virtual int32_t AllocSocketFd(const std::string& programName, int32_t moduleType, int32_t tokenType,
                          int32_t uid, int32_t pid, int32_t& clientFd) = 0;
    virtual SocketSessionPtr FindSessionByPid(int32_t pid) const = 0;
    virtual void RegisterApplicationState() = 0;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // I_SOCKET_SESSION_MANAGER_H
