/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "client_death_handler.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ClientDeathHandler"

namespace OHOS {
namespace MMI {
ClientDeathHandler::ClientDeathHandler() {}

ClientDeathHandler::~ClientDeathHandler() {}

bool ClientDeathHandler::RegisterClientDeathRecipient(const sptr<IRemoteObject> &binderClientSrv, int32_t pid)
{
    CALL_DEBUG_ENTER;
    if (!RegisterClientDeathRecipient(binderClientSrv)) {
        return false;
    }
    if (!AddClientPid(binderClientSrv, pid)) {
        return false;
    }
    return true;
}

bool ClientDeathHandler::AddClientDeathCallback(CallBackType type, ClientDeathCallback callback)
{
    CALL_DEBUG_ENTER;
    CHKPF(callback);
    std::lock_guard<std::mutex> callBackLock(mutexCallbacks_);
    [[ maybe_unused ]] bool bFind = false;
    auto it = deathCallbacks_.find(type);
    if (it != deathCallbacks_.end()) {
        MMI_HILOGE("Death callBack has existed type:%{public}d", type);
        return false;
    }
    deathCallbacks_.insert(std::make_pair(type, callback));
    return true;
}

bool ClientDeathHandler::UnregisterClientDeathRecipient(const wptr<IRemoteObject> &remoteObj)
{
    CALL_DEBUG_ENTER;
    CHKPF(remoteObj);
    CHKPF(deathRecipient_);
    return remoteObj->RemoveDeathRecipient(deathRecipient_);
}

void ClientDeathHandler::RemoveClientDeathCallback(CallBackType type)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> callBackLock(mutexCallbacks_);
    deathCallbacks_.erase(type);
}

void ClientDeathHandler::OnDeath(const wptr<IRemoteObject> &remoteObj)
{
    CALL_DEBUG_ENTER;
    CHKPV(remoteObj);
    auto sptrRemote = sptr<IRemoteObject>(remoteObj.GetRefPtr());
    CHKPV(sptrRemote);
    int32_t pid = FindClientPid(sptrRemote);
    if (pid == INVALID_PID) {
        MMI_HILOGE("Failed to found pid");
    } else {
        NotifyDeath(pid);
    }
    UnregisterClientDeathRecipient(remoteObj);
    RemoveClientPid(pid);
}

bool ClientDeathHandler::RegisterClientDeathRecipient(const sptr<IRemoteObject> &binderClientSrv)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> clientDeathLock(mutexDeathRecipient_);
    CHKPF(binderClientSrv);
    auto deathCallback = [this](const wptr<IRemoteObject> &object) {
        CALL_DEBUG_ENTER;
        OnDeath(object);
    };
    if (deathRecipient_ == nullptr) {
        deathRecipient_ = new (std::nothrow) InputBinderClientDeathRecipient(deathCallback);
    }
    CHKPF(deathRecipient_);
    if (!binderClientSrv->AddDeathRecipient(deathRecipient_)) {
        MMI_HILOGE("Failed to add death recipient");
        return false;
    }
    return true;
}

bool ClientDeathHandler::AddClientPid(const sptr<IRemoteObject> &binderClientSrv, int32_t pid)
{
    CALL_DEBUG_ENTER;
    CHKPF(binderClientSrv);
    std::lock_guard<std::mutex> lockPidMap(mutexPidMap_);
    auto it = clientPidMap_.find(pid);
    if (it == clientPidMap_.end()) {
        MMI_HILOGI("Insert Death recipient pid:%{public}d has existed", pid);
    }
    clientPidMap_.insert(std::make_pair(pid, binderClientSrv));
    return true;
}

void ClientDeathHandler::RemoveClientPid(int32_t pid)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> lock(mutexPidMap_);
    auto it = clientPidMap_.begin();
    while (it != clientPidMap_.end()) {
        if (it->first == pid) {
            clientPidMap_.erase(it);
            break;
        }
        it++;
    }
}

int32_t ClientDeathHandler::FindClientPid(const sptr<IRemoteObject> &binderClientSrv)
{
    CALL_DEBUG_ENTER;
    CHKPR(binderClientSrv, INVALID_PID);
    std::lock_guard<std::mutex> lock(mutexPidMap_);
    std::vector<int32_t> pids;
    auto it = clientPidMap_.begin();
    for (; it != clientPidMap_.end(); it++) {
        if (it->second == binderClientSrv) {
            pids.push_back(it->first);
        }
    }
    if (pids.size() > 0) {
        if (pids.size() > 1) {
            MMI_HILOGI("Found one remote to many %{public}zu pid", pids.size());
        }
        return pids[0];
    }
    return INVALID_PID;
}
void ClientDeathHandler::NotifyDeath(int32_t pid)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> lock(mutexCallbacks_);
    auto it = deathCallbacks_.begin();
    for (; it != deathCallbacks_.end(); it++) {
        CHKPC(it->second);
        (it->second)(pid);
    }
}
} // namespace MMI
} // namespace OHOS
