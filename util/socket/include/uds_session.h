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
 
#ifndef UDS_SESSION_H
#define UDS_SESSION_H

#include <list>
#include <memory>

#include <sys/socket.h>
#include <sys/un.h>

#include "nocopyable.h"

#include "net_packet.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
class UDSSession;
using SessionPtr = std::shared_ptr<UDSSession>;
class UDSSession : public std::enable_shared_from_this<UDSSession> {
public:
    UDSSession(const std::string &programName, const int32_t moduleType, const int32_t fd, const int32_t uid,
               const int32_t pid);
    DISALLOW_COPY_AND_MOVE(UDSSession);
    virtual ~UDSSession() = default;

    bool SendMsg(const char *buf, size_t size) const;
    bool SendMsg(NetPacket &pkt) const;
    void Close();

    int32_t GetUid() const
    {
        return uid_;
    }

    int32_t GetPid() const
    {
        return pid_;
    }

    int32_t GetModuleType() const
    {
        return moduleType_;
    }

    SessionPtr GetSharedPtr()
    {
        return shared_from_this();
    }

    int32_t GetFd() const
    {
        return fd_;
    }

    const std::string& GetDescript() const
    {
        return descript_;
    }

    const std::string GetProgramName() const
    {
        return programName_;
    }

    void SetAnrStatus(int32_t type, bool status)
    {
        isAnrProcess_[type] = status;
    }

    bool CheckAnrStatus(int32_t type)
    {
        return isAnrProcess_[type];
    }

    void SetTokenType(int32_t type)
    {
        tokenType_ = type;
    }

    int32_t GetTokenType() const
    {
        return tokenType_;
    }

    bool IsSocketValid()
    {
        return !invalidSocket_;
    }
    void UpdateDescript();
    void SaveANREvent(int32_t type, int32_t id, int64_t time, int32_t timerId);
    std::vector<int32_t> GetTimerIds(int32_t type);
    std::list<int32_t> DelEvents(int32_t type, int32_t id);
    int64_t GetEarliestEventTime(int32_t type = 0) const;
    bool IsEventQueueEmpty(int32_t type = 0);
    void ReportSocketBufferFull() const;

protected:
    struct EventTime {
        int32_t id { 0 };
        int64_t eventTime { 0 };
        int32_t timerId { -1 };
    };
    std::map<int32_t, std::vector<EventTime>> events_;
    std::map<int32_t, bool> isAnrProcess_;
    std::string descript_;
    const std::string programName_;
    const int32_t moduleType_ { -1 };
    int32_t fd_ { -1 };
    const int32_t uid_ { -1 };
    const int32_t pid_ { -1 };
    int32_t tokenType_ { TokenType::TOKEN_INVALID };
    mutable bool invalidSocket_ { false };
};
} // namespace MMI
} // namespace OHOS
#endif // UDS_SESSION_H