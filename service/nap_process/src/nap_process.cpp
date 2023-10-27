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
    MMI_HILOGD("NotifyBundle info is : %{public}d, %{public}d, %{public}s",
        data.pid, data.uid, data.bundleName.c_str());
    NetPacket pkt(MmiMessageId::NOTIFY_BUNDLE_NAME);
    pkt << data.pid;
    pkt << data.uid;
    pkt << data.bundleName;
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

int32_t NapProcess::SetNapStatus(int32_t pid, int32_t uid, std::string bundleName, bool napStatus)
{
    CALL_DEBUG_ENTER;
    NapStatusData napData;
    napData.pid = pid;
    napData.uid = uid;
    napData.bundleName = bundleName;
    if (napStatus == true) {
        napMap_.emplace(napData, napStatus);
        MMI_HILOGD("Set NapStatus to napMap, pid = %{public}d, uid = %{public}d, bundleName = %{public}s",
            pid, uid, bundleName.c_str());
    } else {
        napMap_.erase(napData);
        MMI_HILOGD("Remove NapStatus from napMap, pid = %{public}d, uid = %{public}d, bundleName = %{public}s",
            pid, uid, bundleName.c_str());
    }
    return RET_OK;
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
    napMap_.clear();
    napClientPid_ = REMOVE_OBSERVER;
    return RET_OK;
}

int32_t NapProcess::GetAllNapStatusData(std::vector<std::tuple<int32_t, int32_t, std::string>> &datas)
{
    CALL_DEBUG_ENTER;
    for (const auto& map : napMap_) {
        int pid = map.first.pid;
        int uid = map.first.uid;
        std::string name = map.first.bundleName;
        std::tuple<int32_t, int32_t, std::string> tuple(pid, uid, name);
        datas.push_back(tuple);
    }
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
