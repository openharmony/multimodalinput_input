/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "input_device_cooperate_impl.h"

#include "mmi_log.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputDeviceCooperateImpl"};
} // namespace

InputDeviceCooperateImpl &InputDeviceCooperateImpl::GetInstance()
{
    static InputDeviceCooperateImpl instance;
    return instance;
}

int32_t InputDeviceCooperateImpl::RegisterCooperateListener(InputDevCooperateListenerPtr listener)
{
    CALL_DEBUG_ENTER;
    CHKPR(listener, RET_ERR);
    std::lock_guard<std::mutex> guard(mtx_);
    for (const auto &item : devCooperateListener_) {
        if (item == listener) {
            MMI_HILOGW("The listener already exists");
            return RET_ERR;
        }
    }
    devCooperateListener_.push_back(listener);
    if (!isListeningProcess_) {
        MMI_HILOGI("Start monitoring");
        isListeningProcess_ = true;
        return MultimodalInputConnMgr->RegisterCooperateListener();
    }
    return RET_OK;
}

int32_t InputDeviceCooperateImpl::UnregisterCooperateListener(InputDevCooperateListenerPtr listener)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (listener == nullptr) {
        devCooperateListener_.clear();
        goto listenerLabel;
    }
    for (auto it = devCooperateListener_.begin(); it != devCooperateListener_.end(); ++it) {
        if (*it == listener) {
            devCooperateListener_.erase(it);
            goto listenerLabel;
        }
    }

listenerLabel:
    if (isListeningProcess_ && devCooperateListener_.empty()) {
        isListeningProcess_ = false;
        return MultimodalInputConnMgr->UnregisterCooperateListener();
    }
    return RET_OK;
}

int32_t InputDeviceCooperateImpl::EnableInputDeviceCooperate(bool enabled, FuncCooperationMessage callback)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    CooperateEvent event;
    event.msg = callback;
    if (userData_ == INT32_MAX) {
        MMI_HILOGE("userData exceeds the maximum");
        return RET_ERR;
    }
    devCooperateEvent_[userData_] = event;
    return MultimodalInputConnMgr->EnableInputDeviceCooperate(userData_++, enabled);
}

int32_t InputDeviceCooperateImpl::StartInputDeviceCooperate(const std::string &sinkDeviceId, int32_t srcInputDeviceId,
    FuncCooperationMessage callback)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    CooperateEvent event;
    event.msg = callback;
    if (userData_ == INT32_MAX) {
        MMI_HILOGE("userData exceeds the maximum");
        return RET_ERR;
    }
    devCooperateEvent_[userData_] = event;
    return MultimodalInputConnMgr->StartInputDeviceCooperate(userData_++, sinkDeviceId, srcInputDeviceId);
}

int32_t InputDeviceCooperateImpl::StopDeviceCooperate(FuncCooperationMessage callback)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    CooperateEvent event;
    event.msg = callback;
    if (userData_ == INT32_MAX) {
        MMI_HILOGE("userData exceeds the maximum");
        return RET_ERR;
    }
    devCooperateEvent_[userData_] = event;
    return MultimodalInputConnMgr->StopDeviceCooperate(userData_++);
}

int32_t InputDeviceCooperateImpl::GetInputDeviceCooperateState(
    const std::string &deviceId, FuncCooperateionState callback)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    CooperateEvent event;
    event.state = callback;
    if (userData_ == INT32_MAX) {
        MMI_HILOGE("userData exceeds the maximum");
        return RET_ERR;
    }
    devCooperateEvent_[userData_] = event;
    return MultimodalInputConnMgr->GetInputDeviceCooperateState(userData_++, deviceId);
}

void InputDeviceCooperateImpl::OnDevCooperateListener(const std::string deviceId, CooperationMessage msg)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    for (const auto &item : devCooperateListener_) {
        item->OnCooperateMessage(deviceId, msg);
    }
}

void InputDeviceCooperateImpl::OnCooprationMessage(int32_t userData, const std::string deviceId, CooperationMessage msg)
{
    CALL_DEBUG_ENTER;
    CHK_PID_AND_TID();
    std::lock_guard<std::mutex> guard(mtx_);
    auto event = GetCooprateMessageEvent(userData);
    CHKPV(event);
    (*event)(deviceId, msg);
}

void InputDeviceCooperateImpl::OnCooperationState(int32_t userData, bool state)
{
    CALL_DEBUG_ENTER;
    CHK_PID_AND_TID();
    std::lock_guard<std::mutex> guard(mtx_);
    auto event = GetCooprateStateEvent(userData);
    CHKPV(event);
    (*event)(state);
    MMI_HILOGD("Cooperatinon state event callback userData:%{public}d state:(%{public}d)", userData, state);
}

int32_t InputDeviceCooperateImpl::GetUserData()
{
    std::lock_guard<std::mutex> guard(mtx_);
    return userData_;
}

const InputDeviceCooperateImpl::DevCooperationMsg *InputDeviceCooperateImpl::GetCooprateMessageEvent(
    int32_t userData) const
{
    auto iter = devCooperateEvent_.find(userData);
    return iter == devCooperateEvent_.end() ? nullptr : &iter->second.msg;
}

const InputDeviceCooperateImpl::DevCooperateionState *InputDeviceCooperateImpl::GetCooprateStateEvent(
    int32_t userData) const
{
    auto iter = devCooperateEvent_.find(userData);
    return iter == devCooperateEvent_.end() ? nullptr : &iter->second.state;
}
} // namespace MMI
} // namespace OHOS