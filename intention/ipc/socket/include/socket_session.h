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

#ifndef SOCKET_SESSION_H
#define SOCKET_SESSION_H

#include "nocopyable.h"

#include "i_epoll_event_source.h"
#include "i_socket_session.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class SocketSession final : public ISocketSession, public IEpollEventSource {
public:
    SocketSession(const std::string &programName, int32_t moduleType,
                  int32_t tokenType, int32_t fd, int32_t uid, int32_t pid);
    DISALLOW_COPY_AND_MOVE(SocketSession);
    ~SocketSession();

    bool SendMsg(NetPacket &pkt) const override;

    int32_t GetUid() const override;
    int32_t GetPid() const override;
    std::string ToString() const override;
    std::string GetProgramName() const override;
    void SetProgramName(const std::string &programName) override;

    int32_t GetFd() const override;
    void Dispatch(const struct epoll_event &ev) override;

private:
    bool SendMsg(const char *buf, size_t size) const;

private:
    int32_t fd_ { -1 };
    int32_t uid_ { -1 };
    int32_t pid_ { -1 };
    int32_t tokenType_ { TokenType::TOKEN_INVALID };
    std::string programName_;
};

inline int32_t SocketSession::GetUid() const
{
    return uid_;
}

inline int32_t SocketSession::GetPid() const
{
    return pid_;
}

inline int32_t SocketSession::GetFd() const
{
    return fd_;
}

inline std::string SocketSession::GetProgramName() const
{
    return programName_;
}

inline void SocketSession::SetProgramName(const std::string &programName)
{
    programName_ = programName;
}
} // namespace Msdp
} // namespace OHOS
} // namespace DeviceStatus
#endif // SOCKET_SESSION_H