/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "suspend_state_manager.h"
#include "suspend_manager_base_client.h"
#include "mmi_log.h"
#include "parameters.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SuspendStateManager"

namespace OHOS {
namespace MMI {
namespace {
const bool SUPPORTED_SUSPEND_MANAGER =
    system::GetBoolParameter("const.taskmanager.low_memory_frozen_enable", false);
}

sptr<SuspendStateObserver> SuspendStateObserver::GetInstance()
{
    static sptr<SuspendStateObserver> observer = sptr<SuspendStateObserver>(new SuspendStateObserver());
    return observer;
}

SuspendStateObserver::~SuspendStateObserver()
{
    frozenPidList_.clear();
}

ErrCode SuspendStateObserver::OnActive(const std::vector<int32_t> &pidList, int32_t uid)
{
    MMI_HILOGI("SuspendStateObserver, get onActive event");
    std::lock_guard<std::mutex> lock(mutex_);
    for (const int32_t& pid : pidList) {
        frozenPidList_.erase(pid);
    }
    return RET_OK;
}

ErrCode SuspendStateObserver::OnFrozen(const std::vector<int32_t> &pidList, int32_t uid)
{
    MMI_HILOGI("SuspendStateObserver, get onFrozen event");
    std::lock_guard<std::mutex> lock(mutex_);
    for (const int32_t& pid : pidList) {
        frozenPidList_.insert(pid);
    }
    return RET_OK;
}

bool SuspendStateObserver::IsFrozenPid(int32_t pid)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return frozenPidList_.count(pid) > 0;
}

std::unordered_set<int32_t> SuspendStateObserver::GetFrozenPidList()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return frozenPidList_;
}

SuspendStateManager::SuspendStateManager()
{
    suspendStateObserver_ = SuspendStateObserver::GetInstance();
}

SuspendStateManager::~SuspendStateManager()
{
    suspendStateObserver_ = nullptr;
}

SuspendStateManager &SuspendStateManager::GetInstance()
{
    static SuspendStateManager instance;
    return instance;
}

int32_t SuspendStateManager::RegisterSuspendStateChanged()
{
    if (!SUPPORTED_SUSPEND_MANAGER) {
        MMI_HILOGI("product is not support register suspend state observer");
        return RET_OK;
    }
    if (!isRssSaReady_.load()) {
        MMI_HILOGE("RegisterSuspendStateChanged failed, rss sa is not ready");
        return RET_ERR;
    }
    if (!isSuspendManagerSaReady_.load()) {
        MMI_HILOGE("RegisterSuspendStateChanged failed, suspend manager sa is not ready");
        return RET_ERR;
    }
    bool expected = false;
    if (!hasRegisteredObserver_.compare_exchange_strong(expected, true)) {
        MMI_HILOGI("RegisterSuspendStateChanged, observer has been registered");
        return RET_OK;
    }
    ErrCode code = ResourceSchedule::SuspendManagerBaseClient::GetInstance().RegisterSuspendObserver(
    suspendStateObserver_);
    if (code != ERR_OK) {
        MMI_HILOGE("RegisterSuspendStateChanged failed, err code:%{public}d", code);
        hasRegisteredObserver_.store(false);
        return code;
    }
    MMI_HILOGI("RegisterSuspendStateChanged success");
    return RET_OK;
}

int32_t SuspendStateManager::UnRegisterSuspendStateChanged()
{
    if (!SUPPORTED_SUSPEND_MANAGER) {
        MMI_HILOGI("product is not support register suspend state observer");
        return RET_OK;
    }
    if (!hasRegisteredObserver_.load()) {
        return RET_OK;
    }
    if (suspendStateObserver_ == nullptr) {
        return RET_ERR;
    }
    ResourceSchedule::SuspendManagerBaseClient::GetInstance().UnregisterSuspendObserver(suspendStateObserver_);
    hasRegisteredObserver_.store(false);
    return RET_OK;
}

bool SuspendStateManager::IsFrozen(int32_t pid)
{
    return suspendStateObserver_->IsFrozenPid(pid);
}

void SuspendStateManager::SetRssSaReady()
{
    MMI_HILOGI("rss sa is ready");
    isRssSaReady_.store(true);
    RegisterSuspendStateChanged();
}

void SuspendStateManager::SetSuspendSaReady()
{
    MMI_HILOGI("suspend sa is ready");
    isSuspendManagerSaReady_.store(true);
    RegisterSuspendStateChanged();
}

void SuspendStateManager::Dump(int32_t fd)
{
    if (suspendStateObserver_ == nullptr) {
        mprintf(fd, "Total frozen pid size:0");
        return;
    }
    std::unordered_set<int32_t> pidList = suspendStateObserver_->GetFrozenPidList();
    mprintf(fd, "Total frozen pid size:%zu, frozen pid list:\t", pidList.size());
    for (const auto &pid : pidList) {
        mprintf(fd, "frozePid:%d\t", pid);
    }
}
} // namespace MMI
} // namespace OHOS
