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

#include "distributed_input_adapter.h"

#include <algorithm>
#include <map>
#include <mutex>

#include "error_multimodal.h"
#include "timer_manager.h"

namespace OHOS {
namespace MMI {
using namespace DistributedHardware::DistributedInput;
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "DistributedInputAdapter"};
constexpr int32_t DEFAULT_DELAY_TIME = 4000;
constexpr int32_t RETRY_TIME = 2;
} // namespace
DistributedInputAdapter::DistributedInputAdapter()
{
    CALL_INFO_TRACE;
    simulationEventListener_ = new (std::nothrow) SimulateEventCallbackImpl();
    CHKPL(simulationEventListener_);
    DistributedInputKit::RegisterSimulationEventListener(simulationEventListener_);
}

DistributedInputAdapter::~DistributedInputAdapter()
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(adapterLock_);
    DistributedInputKit::UnregisterSimulationEventListener(simulationEventListener_);
    simulationEventListener_ = nullptr;
    callbackMap_.clear();
}

bool DistributedInputAdapter::IsNeedFilterOut(const std::string &deviceId, const BusinessEvent &event)
{
    CALL_INFO_TRACE;
    return DistributedInputKit::IsNeedFilterOut(deviceId, event);
}

int32_t DistributedInputAdapter::StartRemoteInput(const std::string &deviceId, const std::vector<std::string> &dhIds,
                                                  DInputCallback callback)
{
    CALL_INFO_TRACE;
    sptr<IStartStopDInputsCallback> cb = new (std::nothrow) StartDInputCallbackDHIds();
    CHKPR(cb, ERROR_NULL_POINTER);
    SaveCallback(CallbackType::StartDInputCallbackDHIds, callback);
    return DistributedInputKit::StartRemoteInput(deviceId, dhIds, cb);
}

int32_t DistributedInputAdapter::StartRemoteInput(const std::string &srcId, const std::string &sinkId,
                                                  const uint32_t &inputTypes, DInputCallback callback)
{
    CALL_INFO_TRACE;
    sptr<IStartDInputCallback> cb = new (std::nothrow) StartDInputCallback();
    CHKPR(cb, ERROR_NULL_POINTER);
    SaveCallback(CallbackType::StartDInputCallback, callback);
    return DistributedInputKit::StartRemoteInput(srcId, sinkId, inputTypes, cb);
}

int32_t DistributedInputAdapter::StartRemoteInput(const std::string &srcId, const std::string &sinkId,
                                                  const std::vector<std::string> &dhIds, DInputCallback callback)
{
    CALL_INFO_TRACE;
    sptr<IStartStopDInputsCallback> cb = new (std::nothrow) StartDInputCallbackSink();
    CHKPR(cb, ERROR_NULL_POINTER);
    SaveCallback(CallbackType::StartDInputCallbackSink, callback);
    return DistributedInputKit::StartRemoteInput(srcId, sinkId, dhIds, cb);
}

int32_t DistributedInputAdapter::StopRemoteInput(const std::string &deviceId, const std::vector<std::string> &dhIds,
                                                 DInputCallback callback)
{
    CALL_INFO_TRACE;
    sptr<IStartStopDInputsCallback> cb = new (std::nothrow) StopDInputCallbackDHIds();
    CHKPR(cb, ERROR_NULL_POINTER);
    SaveCallback(CallbackType::StopDInputCallbackDHIds, callback);
    return DistributedInputKit::StopRemoteInput(deviceId, dhIds, cb);
}

int32_t DistributedInputAdapter::StopRemoteInput(const std::string &srcId, const std::string &sinkId,
                                                 const uint32_t &inputTypes, DInputCallback callback)
{
    CALL_INFO_TRACE;
    sptr<IStopDInputCallback> cb = new (std::nothrow) StopDInputCallback();
    CHKPR(cb, ERROR_NULL_POINTER);
    SaveCallback(CallbackType::StopDInputCallback, callback);
    return DistributedInputKit::StopRemoteInput(srcId, sinkId, inputTypes, cb);
}

int32_t DistributedInputAdapter::StopRemoteInput(const std::string &srcId, const std::string &sinkId,
                                                 const std::vector<std::string> &dhIds, DInputCallback callback)
{
    CALL_INFO_TRACE;
    sptr<IStartStopDInputsCallback> cb = new (std::nothrow) StopDInputCallbackSink();
    CHKPR(cb, ERROR_NULL_POINTER);
    SaveCallback(CallbackType::StopDInputCallbackSink, callback);
    return DistributedInputKit::StopRemoteInput(srcId, sinkId, dhIds, cb);
}

int32_t DistributedInputAdapter::PrepareRemoteInput(const std::string &srcId, const std::string &sinkId,
                                                    DInputCallback callback)
{
    CALL_INFO_TRACE;
    sptr<IPrepareDInputCallback> cb = new (std::nothrow) PrepareStartDInputCallbackSink();
    CHKPR(cb, ERROR_NULL_POINTER);
    SaveCallback(CallbackType::PrepareStartDInputCallbackSink, callback);
    return DistributedInputKit::PrepareRemoteInput(srcId, sinkId, cb);
}

int32_t DistributedInputAdapter::UnPrepareRemoteInput(const std::string &srcId, const std::string &sinkId,
                                                      DInputCallback callback)
{
    CALL_INFO_TRACE;
    sptr<IUnprepareDInputCallback> cb = new (std::nothrow) UnPrepareStopDInputCallbackSink();
    CHKPR(cb, ERROR_NULL_POINTER);
    SaveCallback(CallbackType::UnPrepareStopDInputCallbackSink, callback);
    return DistributedInputKit::UnprepareRemoteInput(srcId, sinkId, cb);
}

int32_t DistributedInputAdapter::PrepareRemoteInput(const std::string &deviceId, DInputCallback callback)
{
    CALL_INFO_TRACE;
    sptr<IPrepareDInputCallback> cb = new (std::nothrow) PrepareStartDInputCallback();
    CHKPR(cb, ERROR_NULL_POINTER);
    SaveCallback(CallbackType::PrepareStartDInputCallback, callback);
    return DistributedInputKit::PrepareRemoteInput(deviceId, cb);
}

int32_t DistributedInputAdapter::UnPrepareRemoteInput(const std::string &deviceId, DInputCallback callback)
{
    CALL_INFO_TRACE;
    sptr<IUnprepareDInputCallback> cb = new (std::nothrow) UnPrepareStopDInputCallback();
    CHKPR(cb, ERROR_NULL_POINTER);
    SaveCallback(CallbackType::UnPrepareStopDInputCallback, callback);
    return DistributedInputKit::UnprepareRemoteInput(deviceId, cb);
}

int32_t DistributedInputAdapter::RegisterEventCallback(SimulateEventCallback callback)
{
    std::lock_guard<std::mutex> guard(adapterLock_);
    CHKPR(callback, RET_ERR);
    SimulateEventCallback_ = callback;
    return RET_OK;
}
int32_t DistributedInputAdapter::UnregisterEventCallback(SimulateEventCallback callback)
{
    std::lock_guard<std::mutex> guard(adapterLock_);
    CHKPR(callback, RET_ERR);
    SimulateEventCallback_ = nullptr;
    return RET_OK;
}

void DistributedInputAdapter::SaveCallback(CallbackType type, DInputCallback callback)
{
    std::lock_guard<std::mutex> guard(adapterLock_);
    CHKPV(callback);
    callbackMap_[type] = callback;
    AddTimer(type);
}

void DistributedInputAdapter::AddTimer(const CallbackType &type)
{
    MMI_HILOGD("AddTimer type:%{public}d", type);
    int32_t timerId = TimerMgr->AddTimer(DEFAULT_DELAY_TIME, RETRY_TIME, [this, type]() {
        if ((callbackMap_.find(type) == callbackMap_.end()) || (watchingMap_.find(type) == watchingMap_.end())) {
            MMI_HILOGE("Callback or watching is not exist");
            return;
        }
        if (watchingMap_[type].times == 0) {
            MMI_HILOGI("It will be retry to call callback next time");
            watchingMap_[type].times++;
            return;
        }
        callbackMap_[type](false);
        callbackMap_.erase(type);
    });
    if (timerId < 0) {
        MMI_HILOGE("Add timer failed timeId:%{public}d", timerId);
        return;
    }
    watchingMap_[type].timerId = timerId;
    watchingMap_[type].times = 0;
}

void DistributedInputAdapter::RemoveTimer(const CallbackType &type)
{
    MMI_HILOGD("RemoveTimer type:%{public}d", type);
    if (watchingMap_.find(type) != watchingMap_.end()) {
        TimerMgr->RemoveTimer(watchingMap_[type].timerId);
        watchingMap_.erase(type);
    }
}

void DistributedInputAdapter::ProcessDInputCallback(CallbackType type, int32_t status)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(adapterLock_);
    RemoveTimer(type);
    auto it = callbackMap_.find(type);
    if (it == callbackMap_.end()) {
        MMI_HILOGI("Dinput callback not exist");
        return;
    }
    it->second(status == RET_OK);
    callbackMap_.erase(it);
}

void DistributedInputAdapter::OnSimulationEvent(uint32_t type, uint32_t code, int32_t value)
{
    std::lock_guard<std::mutex> guard(adapterLock_);
    CHKPV(SimulateEventCallback_);
    SimulateEventCallback_(type, code, value);
}

void DistributedInputAdapter::StartDInputCallback::OnResult(const std::string &devId, const uint32_t &inputTypes,
                                                            const int32_t &status)
{
    DistributedAdapter->ProcessDInputCallback(CallbackType::StartDInputCallback, status);
}

void DistributedInputAdapter::StopDInputCallback::OnResult(const std::string &devId, const uint32_t &inputTypes,
                                                           const int32_t &status)
{
    DistributedAdapter->ProcessDInputCallback(CallbackType::StopDInputCallback, status);
}

void DistributedInputAdapter::StartDInputCallbackDHIds::OnResultDhids(const std::string &devId, const int32_t &status)
{
    DistributedAdapter->ProcessDInputCallback(CallbackType::StartDInputCallbackDHIds, status);
}

void DistributedInputAdapter::StopDInputCallbackDHIds::OnResultDhids(const std::string &devId, const int32_t &status)
{
    DistributedAdapter->ProcessDInputCallback(CallbackType::StopDInputCallbackDHIds, status);
}

void DistributedInputAdapter::StartDInputCallbackSink::OnResultDhids(const std::string &devId, const int32_t &status)
{
    DistributedAdapter->ProcessDInputCallback(CallbackType::StartDInputCallbackSink, status);
}

void DistributedInputAdapter::StopDInputCallbackSink::OnResultDhids(const std::string &devId, const int32_t &status)
{
    DistributedAdapter->ProcessDInputCallback(CallbackType::StopDInputCallbackSink, status);
}

void DistributedInputAdapter::PrepareStartDInputCallback::OnResult(const std::string &devId, const int32_t &status)
{
    DistributedAdapter->ProcessDInputCallback(CallbackType::PrepareStartDInputCallback, status);
}

void DistributedInputAdapter::UnPrepareStopDInputCallback::OnResult(const std::string &devId, const int32_t &status)
{
    DistributedAdapter->ProcessDInputCallback(CallbackType::UnPrepareStopDInputCallback, status);
}

void DistributedInputAdapter::PrepareStartDInputCallbackSink::OnResult(const std::string &devId, const int32_t &status)
{
    DistributedAdapter->ProcessDInputCallback(CallbackType::PrepareStartDInputCallbackSink, status);
}

void DistributedInputAdapter::UnPrepareStopDInputCallbackSink::OnResult(const std::string &devId, const int32_t &status)
{
    DistributedAdapter->ProcessDInputCallback(CallbackType::UnPrepareStopDInputCallbackSink, status);
}

int32_t DistributedInputAdapter::SimulateEventCallbackImpl::OnSimulationEvent(uint32_t type, uint32_t code,
    int32_t value)
{
    DistributedAdapter->OnSimulationEvent(type, code, value);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
