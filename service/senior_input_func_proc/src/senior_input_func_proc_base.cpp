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

#include "senior_input_func_proc_base.h"
#include "util.h"

namespace OHOS {
namespace MMI {
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "SeniorInputFuncProcBase" };
    }
} // namespace MMI
} // namespace OHOS

using namespace std;
using namespace OHOS::MMI;
UDSServer* OHOS::MMI::SeniorInputFuncProcBase::udsServerPtr_ = nullptr;
std::map<int32_t, OHOS::sptr<SeniorInputFuncProcBase>> OHOS::MMI::SeniorInputFuncProcBase::deviceInfoMap_ = {};

OHOS::MMI::SeniorInputFuncProcBase::SeniorInputFuncProcBase() {}

OHOS::MMI::SeniorInputFuncProcBase::~SeniorInputFuncProcBase() {}

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
        MMI_LOGE("The current sessionFd_ is invalid");
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
    if (it == deviceInfoMap_.end()) {
        MMI_LOGE("Failed to find fd");
        return false;
    }
    it->second->DeviceEventDispatchProcess(event);
    return true;
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
    MMI_LOGE("enter, not implement");
    return RET_ERR;
}

int32_t SeniorInputFuncProcBase::GetDevType()
{
    return 0;
}

int32_t SeniorInputFuncProcBase::ReplyMessage(SessionPtr aiSessionPtr, int32_t status)
{
    CHKPR(aiSessionPtr, ERROR_NULL_POINTER);
    NetPacket pkt(MmiMessageId::SENIOR_INPUT_FUNC);
    pkt << status;
    if (!aiSessionPtr->SendMsg(pkt)) {
        return RET_ERR;
    }
    return RET_OK;
}