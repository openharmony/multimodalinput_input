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

#include "authorize_helper.h"

#include <chrono>

#include "define_multimodal.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AuthorizeHelper"

namespace OHOS {
namespace MMI {
namespace {
    constexpr int32_t INVALID_AUTHORIZE_PID = -1; // The pid must be greater than 0(0 is the init process, except here)
} // namespace

std::mutex AuthorizeHelper::mutex_;
std::shared_ptr<AuthorizeHelper> AuthorizeHelper::instance_;

AuthorizeHelper::AuthorizeHelper() : pid_(INVALID_AUTHORIZE_PID)
{
}

AuthorizeHelper::~AuthorizeHelper()
{
}

std::shared_ptr<AuthorizeHelper> AuthorizeHelper::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<AuthorizeHelper>();
        }
    }
    return instance_;
}

int32_t AuthorizeHelper::GetAuthorizePid()
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto pid = pid_;
    return pid;
}

void AuthorizeHelper::Init(UDSServer& udsServer)
{
    CALL_DEBUG_ENTER;
    if (udsServer_ != nullptr) {
        MMI_HILOGI("Already initialized, no need to initialize again");
        return;
    }
    udsServer_ = &udsServer;
    CHKPV(udsServer_);
    udsServer_->AddSessionDeletedCallback(std::bind(&AuthorizeHelper::OnSessionLost, this, std::placeholders::_1));
}

void AuthorizeHelper::OnSessionLost(SessionPtr session)
{
    CALL_DEBUG_ENTER;
    CHKPV(session);
    int32_t pid = session->GetPid();
    if (pid != pid_) {
        MMI_HILOGD("Cancel process is inconsistent with authorize, cancel pid:%{public}d, authorize pid:%{public}d",
            pid, pid_);
        return;
    }
    AuthorizeProcessExit();
}

void AuthorizeHelper::AuthorizeProcessExit()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> lock(mutex_);
    state_ = AuthorizeState::STATE_UNAUTHORIZE;
    if (exitCallback_ != nullptr) {
        MMI_HILOGI("Exit callback function will be called, authorize pid:%{public}d", pid_);
        exitCallback_(pid_);
    }
}

int32_t AuthorizeHelper::AddAuthorizeProcess(int32_t pid, AuthorizeExitCallback exitCallback)
{
    CALL_DEBUG_ENTER;
    if (pid <= 0) {
        MMI_HILOGI("Invalid process id, pid:%{public}d", pid);
        return RET_ERR;
    }
    CHKPR(udsServer_, RET_ERR);
    if (exitCallback == nullptr) {
        MMI_HILOGI("Authorize process exit callback function is NULL");
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == AuthorizeState::STATE_AUTHORIZE) {
        if (pid != pid_) {
            MMI_HILOGI("A process is authorizing, and the second process cannot be authorized at the same time");
            return RET_ERR;
        }
    }
    pid_ = pid;
    exitCallback_ = exitCallback;
    MMI_HILOGI("A process will be authorized, authorize pid:%{public}d", pid_);
    return RET_OK;
}

void AuthorizeHelper::CancelAuthorize(int32_t pid)
{
    CALL_DEBUG_ENTER;
    if (pid <= 0) {
        MMI_HILOGI("Invalid process id, pid:%{public}d", pid);
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (pid != pid_) {
        MMI_HILOGI("Cancel pid isn't the authorized process id, cancel pid:%{public}d, authorize pid:%{public}d",
            pid, pid_);
    }
    state_ = AuthorizeState::STATE_UNAUTHORIZE;
    exitCallback_ = nullptr;
}

bool AuthorizeHelper::IsAuthorizing()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return (state_ == AuthorizeState::STATE_AUTHORIZE) ? true : false;
}
} // namespace MMI
} // namespace OHOS
