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

#ifndef MMI_UDS_SESSION_MOCK_H
#define MMI_UDS_SESSION_MOCK_H

#include <memory>
#include <vector>

#include "key_event.h"
#include "net_packet.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
class UDSSession;
using SessionPtr = std::shared_ptr<UDSSession>;

class UDSSession {
public:
    UDSSession() = default;
    UDSSession(const std::string &programName, int32_t moduleType, int32_t fd, int32_t uid, int32_t pid) {}
    ~UDSSession() = default;
    DISALLOW_COPY_AND_MOVE(UDSSession);

    void Close();
    bool SendMsg(NetPacket &pkt);
    int32_t GetUid() const;
    int32_t GetPid() const;
    int32_t GetModuleType() const;
    int32_t GetFd() const;
    const std::string GetDescript() const;
    const std::string GetProgramName() const;
    int32_t GetTokenType() const;
    int64_t GetEarliestEventTime(int32_t type = 0) const;
    SessionPtr GetSharedPtr();

    void SetTokenType(int32_t type);
    void SetTokenId(uint32_t tokenId);
    void SetIsRealProcessName(bool isRealProcessName);

private:
    std::vector<std::shared_ptr<KeyEvent>> keyEvents_;
    int32_t tokenType_ { TokenType::TOKEN_INVALID };
};

using SessionPtr = std::shared_ptr<UDSSession>;
} // namespace MMI
} // namespace OHOS
#endif // MMI_UDS_SESSION_MOCK_H
