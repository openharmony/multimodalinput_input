/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef AUTHORIZE_HELPER_H
#define AUTHORIZE_HELPER_H

#include <mutex>
#include <memory>
#include <functional>

#include "nocopyable.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
enum class AuthorizeState : int32_t {
    STATE_AUTHORIZE = 0,
    STATE_UNAUTHORIZE = 1,
};

using AuthorizeExitCallback = std::function<void(int32_t)>;

class AuthorizeHelper final {
public:
    AuthorizeHelper();
    ~AuthorizeHelper();
    DISALLOW_COPY_AND_MOVE(AuthorizeHelper);
    void Init(UDSServer& udsServer);
    void CancelAuthorize(int32_t pid);
    int32_t GetAuthorizePid();
    int32_t AddAuthorizeProcess(int32_t pid, AuthorizeExitCallback exitCallback);
    bool IsAuthorizing();
    static std::shared_ptr<AuthorizeHelper> GetInstance();

protected:
    void OnSessionLost(SessionPtr session);
    void AuthorizeProcessExit();

private:
    int32_t pid_;
    AuthorizeState state_ { AuthorizeState::STATE_UNAUTHORIZE };
    UDSServer *udsServer_ { nullptr };
    AuthorizeExitCallback exitCallback_ { nullptr };
    static std::mutex mutex_;
    static std::shared_ptr<AuthorizeHelper> instance_;
};

#define AUTHORIZE_HELPER ::OHOS::MMI::AuthorizeHelper::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // AUTHORIZE_HELPER_H
