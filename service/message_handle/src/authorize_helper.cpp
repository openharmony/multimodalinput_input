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

#include "error_multimodal.h"
#include "iinput_binder_client.h"
#include "input_binder_client_proxy.h"
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

void AuthorizeHelper::Init(ClientDeathHandler* clientDeathHandler)
{
    CALL_DEBUG_ENTER;
    if (isInit_) {
        MMI_HILOGD("Already initialized, no need to initialize again");
        return;
    }

    if (clientDeathHandler == nullptr) {
        MMI_HILOGE("clientDeathHandler is nullptr");
        return;
    }

    clientDeathHandler->AddClientDeathCallback(CallBackType::CALLBACK_TYPE_AUTHORIZE_HELPER,
        [&](int32_t pid) -> void { OnClientDeath(pid); });
    clientDeathHandler_ = clientDeathHandler;
    isInit_ = true;
}

void AuthorizeHelper::OnClientDeath(int32_t pid)
{
    CALL_DEBUG_ENTER;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ClearRequestInjectionCallback(pid);
    }
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
    pid_ = INVALID_AUTHORIZE_PID;
}

int32_t AuthorizeHelper::AddAuthorizeProcess(int32_t pid, AuthorizeExitCallback exitCallback, const int32_t reqId)
{
    CALL_DEBUG_ENTER;
    if (!isInit_) {
        MMI_HILOGI("Not init");
        return RET_ERR;
    }

    if (pid <= 0) {
        MMI_HILOGI("Invalid process id, pid:%{public}d", pid);
        return RET_ERR;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == AuthorizeState::STATE_UNAUTHORIZE) {
        if (pid_ != INVALID_AUTHORIZE_PID) {
            MMI_HILOGI("Failed to authorize helper state.state:%{public}d,pid_:%{public}d,pid:%{public}d",
                state_, pid_, pid);
            return RET_ERR;
        }
        pid_ = pid;
        state_ = AuthorizeState::STATE_SELECTION_AUTHORIZE;
        exitCallback_ = exitCallback;
        if (reqId > 0) {
            mapQueryAuthorizeInfo_.insert(std::make_pair(reqId, pid_));
        }
        MMI_HILOGD("A process enters the authorization select state %{public}d", state_);
        return RET_OK;
    }
    if (pid_ != pid) {
        MMI_HILOGI("The process that has been authorized is different from input.pid_:%{public}d,pid:%{public}d",
            pid_, pid);
        return RET_ERR;
    }
    if (state_ == AuthorizeState::STATE_SELECTION_AUTHORIZE) {
        state_ = AuthorizeState::STATE_AUTHORIZE;
        NotifyRequestInjectionResult();
    }
    exitCallback_ = exitCallback;
    MMI_HILOGD("A process will be authorized, authorize pid:%{public}d", pid_);
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
        MMI_HILOGI("Cancel pid isn't the authorized process id, cancel pid:%{public}d, authorize pid:%{public}d", pid,
            pid_);
    }
    state_ = AuthorizeState::STATE_UNAUTHORIZE;
    pid_ = INVALID_AUTHORIZE_PID;
    NotifyRequestInjectionResult();
    exitCallback_ = nullptr;
}

void AuthorizeHelper::NotifyRequestInjectionResult()
{
    CALL_DEBUG_ENTER;
    if (clientDeathHandler_ == nullptr) {
        MMI_HILOGE("clientDeathHandler is nullptr");
        return;
    }
    for (auto it = mapQueryAuthorizeInfo_.begin(); it != mapQueryAuthorizeInfo_.end();) {
        NoticeRequestInjectionResult(it->first, it->second);
        mapQueryAuthorizeInfo_.erase(it++);
    }
}

void AuthorizeHelper::NoticeRequestInjectionResult(const int32_t reqId, const int32_t callingPid)
{
    auto object =  clientDeathHandler_->GetClientProxy(callingPid);
    sptr<IInputBinderClient> pClientProxy = iface_cast<IInputBinderClient>(object);
    if (!pClientProxy) {
        MMI_HILOGE("clientDeathHandler is nullptr");
        return;
    }
    auto sendStatus = AUTHORIZE_QUERY_STATE::UNAUTHORIZE;
    if (state_ == AuthorizeState::STATE_AUTHORIZE) {
        if (pid_ == callingPid) {
            sendStatus = AUTHORIZE_QUERY_STATE::CURRENT_PID_AUTHORIZED;
        }
    }
    MMI_HILOGD("result callback! pid_:%{public}d,sendStatus:%{public}d,state_:%{public}d,mapId:%{public}d",
        pid_, sendStatus, pid_, callingPid);
    pClientProxy->NoticeRequestInjectionResult(reqId, static_cast<int32_t>(sendStatus));
}

void AuthorizeHelper::ClearRequestInjectionCallback(int32_t callingPid)
{
    CALL_DEBUG_ENTER;
    for (auto it = mapQueryAuthorizeInfo_.begin(); it != mapQueryAuthorizeInfo_.end();) {
        if (it->second == callingPid) {
            mapQueryAuthorizeInfo_.erase(it++);
        } else {
            it++;
        }
    }
}
} // namespace MMI
} // namespace OHOS
