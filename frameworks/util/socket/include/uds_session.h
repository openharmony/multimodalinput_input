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
#ifndef OHOS_UDS_SESSION_H
#define OHOS_UDS_SESSION_H
#include <sys/socket.h>
#include <sys/un.h>
#include <memory>
#include "net_packet.h"

namespace OHOS {
namespace MMI {
class UDSSession;
using SessionPtr = std::shared_ptr<UDSSession>;
class UDSSession : public std::enable_shared_from_this<UDSSession> {
public:
    UDSSession(const std::string& programName, const int moduleType, const int32_t fd);
    virtual ~UDSSession();

    bool SendMsg(const char *buf, size_t size) const;
    bool SendMsg(NetPacket& pkt) const;
    void Close();

    SessionPtr GetPtr()
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

    void UpdateDescript();

#ifdef OHOS_BUILD_MMI_DEBUG
    void SetClientFd(const int clientFd)
    {
        clientFd_ = clientFd;
        UpdateDescript();
    }
#endif

protected:
    std::string descript_;
    bool bHasClosed_ = false;
    const std::string programName_;
    const int moduleType_;
    const int32_t fd_;
#ifdef OHOS_BUILD_MMI_DEBUG
    int clientFd_ = -1;
#endif // OHOS_BUILD_MMI_DEBUG
};
}
}
#endif // HOS_UDS_SESSION_H
