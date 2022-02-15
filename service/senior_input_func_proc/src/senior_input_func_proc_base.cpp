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

#include "senior_input_func_proc_base.h"
#include "mmi_server.h"
#include "util.h"

namespace OHOS {
namespace MMI {
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "SeniorInputFuncProcBase" };
    }
}
}

using namespace std;
using namespace OHOS::MMI;
UDSServer* OHOS::MMI::SeniorInputFuncProcBase::udsServerPtr_ = nullptr;
std::map<int32_t, OHOS::sptr<SeniorInputFuncProcBase>> OHOS::MMI::SeniorInputFuncProcBase::deviceInfoMap_ = {};

OHOS::MMI::SeniorInputFuncProcBase::SeniorInputFuncProcBase()
{
}

OHOS::MMI::SeniorInputFuncProcBase::~SeniorInputFuncProcBase()
{
}

bool SeniorInputFuncProcBase::Init(UDSServer& sess)
{
    udsServerPtr_ = &sess;
    return true;
}

void SeniorInputFuncProcBase::SetSessionFd(int32_t fd)
{
    sessionFd_ = fd;
}

int32_t OHOS::MMI::SeniorInputFuncProcBase::GetSessionFd()
{
    if (sessionFd_ < 0) {
        return RET_ERR;
    }
    return sessionFd_;
}

void OHOS::MMI::SeniorInputFuncProcBase::DeviceDisconnect(const int32_t sessionId)
{
    auto it = deviceInfoMap_.find(sessionId);
    if (it != deviceInfoMap_.end()) {
        deviceInfoMap_.erase(it);
        return;
    }
}

int32_t SeniorInputFuncProcBase::DeviceEventDispatchProcess(const RawInputEvent &event)
{
    return 0;
}

bool SeniorInputFuncProcBase::DeviceEventDispatch(int32_t fd, RawInputEvent event)
{
    auto it = deviceInfoMap_.find(fd);
    if (it != deviceInfoMap_.end()) {
        it->second->DeviceEventDispatchProcess(event);
        return true;
    } else {
        return false;
    }
}

bool SeniorInputFuncProcBase::DeviceInit(int32_t sessionId, sptr<SeniorInputFuncProcBase> ptr)
{
    auto it = deviceInfoMap_.find(sessionId);
    if (it != deviceInfoMap_.end()) {
        return false;
    }
    deviceInfoMap_[sessionId] = ptr;
    return true;
}

int32_t SeniorInputFuncProcBase::DeviceEventProcess(const RawInputEvent& event)
{
    const MmiMessageId msgId = static_cast<MmiMessageId>(event.ev_code);
    const uint32_t occurredTime = static_cast<uint32_t>(event.stamp);
    const std::string uuid = GetUUid();

    if (msgId == MmiMessageId::INVALID) {
        MMI_LOGE("msgId is invalid.");
        return RET_ERR;
    }

    std::vector<int32_t> fds;
    RegEventHM->FindSocketFds(msgId, fds);
    if (fds.empty()) {
        MMI_LOGE("can not find handle by fd:%{public}d.", msgId);
        return RET_ERR;
    }

    const int32_t deviceType = GetDevType();
    int32_t deviceId;
    if (deviceType == static_cast<int32_t>(INPUT_DEVICE_CAP_AISENSOR)) {
        deviceId = static_cast<int32_t>(INPUT_DEVICE_AISENSOR);
    } else if (deviceType == static_cast<int32_t>(INPUT_DEVICE_CAP_KNUCKLE)) {
        deviceId = static_cast<int32_t>(INPUT_DEVICE_KNUCKLE);
    }
    for (const auto &fd : fds) {
        auto appInfo = AppRegs->FindBySocketFd(fd);
        NetPacket newPacket(msgId);
        const uint64_t serverStartTime = GetSysClockTime();
        newPacket << deviceType << msgId << deviceId << fd << appInfo.windowId << appInfo.abilityId <<
            serverStartTime << uuid << occurredTime;
        if (!udsServerPtr_->SendMsg(fd, newPacket)) {
            MMI_LOGE("Sending structure of event failed! fd:%{public}d", fd);
            return RET_ERR;
        }
        MMI_LOGI("senior input func process server: fd:%{public}d, windowId:%{public}d, abilityId:%{public}d, "
                 "conbinecode:%{public}d",
                 fd, appInfo.windowId, appInfo.abilityId, event.ev_code);
    }
    MMI_LOGI("successed send to client event[%{public}d] to Application management", event.ev_code);
    return RET_OK;
}

int32_t SeniorInputFuncProcBase::GetDevType()
{
    return 0;
}

int32_t SeniorInputFuncProcBase::ReplyMessage(SessionPtr aiSessionPtr, int32_t status)
{
    CHKPR(aiSessionPtr, ERROR_NULL_POINTER);
    NetPacket newPacket(MmiMessageId::SENIOR_INPUT_FUNC);
    newPacket << status;
    if (!aiSessionPtr->SendMsg(newPacket)) {
        return RET_ERR;
    }
    return RET_OK;
}