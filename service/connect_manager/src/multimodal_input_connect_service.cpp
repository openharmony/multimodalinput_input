/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "multimodal_input_connect_service.h"
#include <cstring>
#include <sys/types.h>
#include <unistd.h>
#include "mmi_log.h"
#include "multimodal_input_connect_def_parcel.h"
#include "singleton.h"
#include "string_ex.h"
#include "system_ability.h"

namespace OHOS {
namespace MMI {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MultimodalInputConnectService" };
}
const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<MultimodalInputConnectService>::GetInstance().get());

int32_t MultimodalInputConnectService::AllocSocketFd(const std::string &programName, const int32_t moduleType,
                                                     int32_t &toReturnClientFd)
{
    MMI_LOGI("MultimodalInputConnectService::AllocSocketFd enter, programName:%{public}s,moduleType:%{public}d",
             programName.c_str(), moduleType);
    if (udsServer_ == nullptr) {
        MMI_LOGE("called, udsServer_ is nullptr");
        return RET_ERR;
    }
    toReturnClientFd = INVALID_SOCKET_FD;
    int32_t serverFd = INVALID_SOCKET_FD;
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t pid = IPCSkeleton::GetCallingPi
    const int32_t ret = udsServer_->AddSocketPairInfo(programName, moduleType, serverFd, uid, pid, toReturnClientFd);
    if (ret != RET_OK) {
        MMI_LOGE("call AddSocketPairInfo return %{public}d", ret);
        return RET_ERR;
    }

    MMI_LOGIK("leave, programName:%{public}s,moduleType:%{public}d,alloc success",
        programName.c_str(), moduleType);
    return RET_OK;
}

int32_t MultimodalInputConnectService::AddInputEventFilter(sptr<IEventFilter> filter)
{
    MMI_LOGF("enter, this code is discarded, and it runs with Weston");
    return RET_ERR;
}

MultimodalInputConnectService::MultimodalInputConnectService()
    : SystemAbility(MULTIMODAL_INPUT_CONNECT_SERVICE_ID, true), state_(ServiceRunningState::STATE_NOT_START)
{
    MMI_LOGI("MultimodalInputConnectService()");
}

MultimodalInputConnectService::~MultimodalInputConnectService()
{
    MMI_LOGI("~MultimodalInputConnectService()");
}

void MultimodalInputConnectService::OnStart()
{
    MMI_LOGD("enter");
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        MMI_LOGI("MultimodalInputConnectService has already started");
        return;
    }
    MMI_LOGI("MultimodalInputConnectService is starting");
    if (!Initialize()) {
        MMI_LOGE("Failed to initialize");
        return;
    }
    bool ret = Publish(DelayedSingleton<MultimodalInputConnectService>::GetInstance().get());
    if (!ret) {
        MMI_LOGE("Failed to publish service");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    MMI_LOGIK("Congratulations, MultimodalInputConnectService start successfully");
    MMI_LOGD("leave");
}

void MultimodalInputConnectService::OnStop()
{
    MMI_LOGD("enter");
    state_ = ServiceRunningState::STATE_NOT_START;
    MMI_LOGD("leave");
}

void MultimodalInputConnectService::OnDump()
{
    MMI_LOGD("enter");
    MMI_LOGD("leave");
}

bool MultimodalInputConnectService::Initialize() const
{
    MMI_LOGD("enter");
    MMI_LOGD("leave");
    return true;
}

int32_t MultimodalInputConnectService::StubHandleAllocSocketFd(MessageParcel& data, MessageParcel& reply)
{
    MMI_LOGD("enter");
    sptr<ConnectReqParcel> req = data.ReadParcelable<ConnectReqParcel>();
    if (req == nullptr) {
        MMI_LOGE("read data error.");
        return RET_ERR;
    }
    MMI_LOGIK("clientName:%{public}s,moduleId:%{public}d", req->data.clientName.c_str(), req->data.moduleId);
    
    if (udsServer_ == nullptr) {
        MMI_LOGE("udsServer_ is nullptr");
        return RET_ERR;
    }

    int32_t clientFd = INVALID_SOCKET_FD;
    int32_t ret = AllocSocketFd(req->data.clientName, req->data.moduleId, clientFd);
    if (ret != RET_OK) {
        MMI_LOGE("call AddSocketPairInfo return %{public}d", ret);
        reply.WriteInt32(RET_ERR);
        return RET_ERR;
    }

    MMI_LOGI("call AllocSocketFd success");

    reply.WriteInt32(RET_OK);
    reply.WriteFileDescriptor(clientFd);

    MMI_LOGI("send clientFd to client, clientFd = %d", clientFd);
    close(clientFd);
    MMI_LOGD("leave");
    return RET_OK;
}

void MultimodalInputConnectService::SetUdsServer(IUdsServer *server)
{
    MMI_LOGD("enter");
    udsServer_ = server;
    MMI_LOGD("leave");
}

int32_t MultimodalInputConnectServiceSetUdsServer(IUdsServer* server)
{
    MMI_LOGD("enter");
    auto s = DelayedSingleton<MultimodalInputConnectService>::GetInstance();
    if (s == nullptr) {
        MMI_LOGE("MultimodalInputConnectService not initialize");
        return RET_ERR;
    }

    s->SetUdsServer(server);
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t MultimodalInputConnectServiceStart()
{
    MMI_LOGD("enter");
    auto s = DelayedSingleton<MultimodalInputConnectService>::GetInstance();
    if (s == nullptr) {
        MMI_LOGE("MultimodalInputConnectService not initialize");
        return RET_ERR;
    }

    s->OnStart();
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t MultimodalInputConnectServiceStop()
{
    MMI_LOGD("enter");
    auto s = DelayedSingleton<MultimodalInputConnectService>::GetInstance();
    if (s == nullptr) {
        MMI_LOGE("MultimodalInputConnectService not initialize");
        return RET_ERR;
    }

    s->OnStop();
    MMI_LOGD("leave");
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
