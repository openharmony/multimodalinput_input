/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
#include "ipc_skeleton.h"

#include "nap_process.h"
#include "input_event_handler.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "NapProcess" };
constexpr int32_t REMOVE_OBSERVER = -2;
constexpr int32_t NAP_EVENT = 0;
constexpr int32_t ACTIVE_EVENT = 2;
} // namespace

NapProcess *NapProcess::instance_ = new (std::nothrow) NapProcess();
NapProcess *NapProcess::GetInstance()
{
    return instance_;
}

void NapProcess::Init(UDSServer& udsServer)
{
    udsServer_ = &udsServer;
    CHKPV(udsServer_);
}

int32_t NapProcess::NotifyBundleName(NapStatusData data)
{
    CALL_DEBUG_ENTER;
    if (napClientPid_ < 0) {
        MMI_HILOGE("Client pid is unavailable!");
        return RET_ERR;
    }
    MMI_HILOGD("NotifyBundle info is : %{public}d, %{public}d, %{public}s, %{public}d",
        data.pid, data.uid, data.bundleName.c_str(), data.syncStatus);
    NetPacket pkt(MmiMessageId::NOTIFY_BUNDLE_NAME);
    pkt << data.pid;
    pkt << data.uid;
    pkt << data.bundleName;
    pkt << data.syncStatus;
    CHKPR(udsServer_, RET_ERR);
    int32_t fd = udsServer_->GetClientFd(napClientPid_);
    auto udsServer = InputHandler->GetUDSServer();
    CHKPR(udsServer, RET_ERR);
    auto session = udsServer->GetSession(fd);
    if (!udsServer->SendMsg(fd, pkt)) {
        MMI_HILOGE("Sending structure of EventTouch failed! errCode:%{public}d", MSG_SEND_FAIL);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t NapProcess::SetNapStatus(int32_t pid, int32_t uid, std::string bundleName, int32_t napStatus)
{
    CALL_DEBUG_ENTER;
    NapStatusData napData;
    napData.pid = pid;
    napData.uid = uid;
    napData.bundleName = bundleName;
    napData.syncStatus = napStatus;
    if (napStatus == ACTIVE_EVENT) {
        AddMmiSubscribedEventData(napData);
        MMI_HILOGD("Add active event to napMap, pid = %{public}d, uid = %{public}d, bundleName = %{public}s",
            pid, uid, bundleName.c_str());
    }
    if (napStatus == NAP_EVENT) {
        RemoveMmiSubscribedEventData(napData);
        MMI_HILOGD("Remove nap process from napMap, pid = %{public}d, uid = %{public}d, bundleName = %{public}s",
            pid, uid, bundleName.c_str());
    }
    return RET_OK;
}

int32_t NapProcess::AddMmiSubscribedEventData(const NapStatusData& napData)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(mapMtx_);
    napMap_.push_back(napData);
    return RET_OK;
}

int32_t NapProcess::RemoveMmiSubscribedEventData(const NapStatusData& napData)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(mapMtx_);
    for (auto it = napMap_.begin(); it != napMap_.end(); ++it) {
        if (napData.pid == it->pid) {
            napMap_.erase(it);
            break;
        }
    }
    return RET_OK;
}

int32_t NapProcess::GetNapClientPid()
{
    return napClientPid_;
}

int32_t NapProcess::NotifyNapOnline()
{
    CALL_DEBUG_ENTER;
    int32_t pid = IPCSkeleton::GetCallingPid();
    napClientPid_ = pid;
    MMI_HILOGD("NotifyNapOnline pid is %{public}d", pid);
    return RET_OK;
}

int32_t NapProcess::RemoveInputEventObserver()
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(mapMtx_);
    napMap_.clear();
    napClientPid_ = REMOVE_OBSERVER;
    return RET_OK;
}

int32_t NapProcess::GetAllMmiSubscribedEvents(std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> &datas)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(mapMtx_);
    for (auto it = napMap_.begin(); it != napMap_.end(); ++it) {
        int32_t getPid = it->pid;
        int32_t getUid = it->uid;
        std::string getName = it->bundleName;
        int32_t getStatus = it->syncStatus;
        std::tuple<int32_t, int32_t, std::string> tuple(getPid, getUid, getName);
        datas.emplace(tuple, getStatus);
    }
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
