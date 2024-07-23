/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "cooperate.h"

#ifdef ENABLE_PERFORMANCE_CHECK
#include <sstream>
#include "utility.h"
#endif // ENABLE_PERFORMANCE_CHECK

#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "Cooperate"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {

Cooperate::Cooperate(IContext *env)
    : env_(env), context_(env), sm_(env)
{
    auto [sender, receiver] = Channel<CooperateEvent>::OpenChannel();
    receiver_ = receiver;
    receiver_.Enable();
    context_.AttachSender(sender);
    context_.Enable();
    StartWorker();
}

Cooperate::~Cooperate()
{
    StopWorker();
    context_.Disable();
}

void Cooperate::AddObserver(std::shared_ptr<ICooperateObserver> observer)
{
    CALL_DEBUG_ENTER;
    auto ret = context_.Sender().Send(CooperateEvent(
        CooperateEventType::ADD_OBSERVER,
        AddObserverEvent {
            .observer = observer
        }));
    if (ret != Channel<CooperateEvent>::NO_ERROR) {
        FI_HILOGE("Failed to send event via channel, error:%{public}d", ret);
    }
}

void Cooperate::RemoveObserver(std::shared_ptr<ICooperateObserver> observer)
{
    CALL_DEBUG_ENTER;
    auto ret = context_.Sender().Send(CooperateEvent(
        CooperateEventType::REMOVE_OBSERVER,
        RemoveObserverEvent {
            .observer = observer
        }));
    if (ret != Channel<CooperateEvent>::NO_ERROR) {
        FI_HILOGE("Failed to send event via channel, error:%{public}d", ret);
    }
}

int32_t Cooperate::RegisterListener(int32_t pid)
{
    CALL_DEBUG_ENTER;
    auto ret = context_.Sender().Send(CooperateEvent(
        CooperateEventType::REGISTER_LISTENER,
        RegisterListenerEvent {
            .pid = pid
        }));
    if (ret != Channel<CooperateEvent>::NO_ERROR) {
        FI_HILOGE("Failed to send event via channel, error:%{public}d", ret);
    }
    return RET_OK;
}

int32_t Cooperate::UnregisterListener(int32_t pid)
{
    CALL_DEBUG_ENTER;
    auto ret = context_.Sender().Send(CooperateEvent(
        CooperateEventType::UNREGISTER_LISTENER,
        UnregisterListenerEvent {
            .pid = pid
        }));
    if (ret != Channel<CooperateEvent>::NO_ERROR) {
        FI_HILOGE("Failed to send event via channel, error:%{public}d", ret);
    }
    return RET_OK;
}

int32_t Cooperate::RegisterHotAreaListener(int32_t pid)
{
    CALL_DEBUG_ENTER;
    auto ret = context_.Sender().Send(CooperateEvent(
        CooperateEventType::REGISTER_HOTAREA_LISTENER,
        RegisterHotareaListenerEvent {
            .pid = pid
        }));
    if (ret != Channel<CooperateEvent>::NO_ERROR) {
        FI_HILOGE("Failed to send event via channel, error:%{public}d", ret);
    }
    return RET_OK;
}

int32_t Cooperate::UnregisterHotAreaListener(int32_t pid)
{
    CALL_DEBUG_ENTER;
    auto ret = context_.Sender().Send(CooperateEvent(
        CooperateEventType::UNREGISTER_HOTAREA_LISTENER,
        UnregisterHotareaListenerEvent {
            .pid = pid
        }));
    if (ret != Channel<CooperateEvent>::NO_ERROR) {
        FI_HILOGE("Failed to send event via channel, error:%{public}d", ret);
    }
    return RET_OK;
}

int32_t Cooperate::Enable(int32_t tokenId, int32_t pid, int32_t userData)
{
    CALL_DEBUG_ENTER;
    auto ret = context_.Sender().Send(CooperateEvent(
        CooperateEventType::ENABLE,
        EnableCooperateEvent {
            .tokenId = tokenId,
            .pid = pid,
            .userData = userData,
        }));
    if (ret != Channel<CooperateEvent>::NO_ERROR) {
        FI_HILOGE("Failed to send event via channel, error:%{public}d", ret);
    }
    return RET_OK;
}

int32_t Cooperate::Disable(int32_t pid, int32_t userData)
{
    CALL_DEBUG_ENTER;
    auto ret = context_.Sender().Send(CooperateEvent(
        CooperateEventType::DISABLE,
        DisableCooperateEvent {
            .pid = pid,
            .userData = userData,
        }));
    if (ret != Channel<CooperateEvent>::NO_ERROR) {
        FI_HILOGE("Failed to send event via channel, error:%{public}d", ret);
    }
    return RET_OK;
}

int32_t Cooperate::Start(int32_t pid, int32_t userData, const std::string &remoteNetworkId, int32_t startDeviceId)
{
    CALL_DEBUG_ENTER;

#ifdef ENABLE_PERFORMANCE_CHECK
    std::ostringstream ss;
    ss << "start_cooperation_with_" << Utility::Anonymize(remoteNetworkId).c_str();
    context_.StartTrace(ss.str());
#endif // ENABLE_PERFORMANCE_CHECK
    StartCooperateEvent event {
        .pid = pid,
        .userData = userData,
        .remoteNetworkId = remoteNetworkId,
        .startDeviceId = startDeviceId,
        .errCode = std::make_shared<std::promise<int32_t>>(),
    };
    auto errCode = event.errCode->get_future();
    auto ret = context_.Sender().Send(CooperateEvent(CooperateEventType::START, event));
    if (ret != Channel<CooperateEvent>::NO_ERROR) {
        FI_HILOGE("Failed to send event via channel, error:%{public}d", ret);
    }
    return errCode.get();
}

int32_t Cooperate::Stop(int32_t pid, int32_t userData, bool isUnchained)
{
    CALL_DEBUG_ENTER;
    auto ret = context_.Sender().Send(CooperateEvent(
        CooperateEventType::STOP,
        StopCooperateEvent {
            .pid = pid,
            .userData = userData,
            .isUnchained = isUnchained,
        }));
    if (ret != Channel<CooperateEvent>::NO_ERROR) {
        FI_HILOGE("Failed to send event via channel, error:%{public}d", ret);
    }
    return RET_OK;
}

int32_t Cooperate::GetCooperateState(int32_t pid, int32_t userData, const std::string &networkId)
{
    CALL_DEBUG_ENTER;
    auto ret = context_.Sender().Send(CooperateEvent(
        CooperateEventType::GET_COOPERATE_STATE,
        GetCooperateStateEvent {
            .pid = pid,
            .userData = userData,
            .networkId = networkId,
        }));
    if (ret != Channel<CooperateEvent>::NO_ERROR) {
        FI_HILOGE("Failed to send event via channel, error:%{public}d", ret);
    }
    return RET_OK;
}

int32_t Cooperate::RegisterEventListener(int32_t pid, const std::string &networkId)
{
    CALL_DEBUG_ENTER;
    auto ret = context_.Sender().Send(CooperateEvent(
        CooperateEventType::REGISTER_EVENT_LISTENER,
        RegisterEventListenerEvent {
            .pid = pid,
            .networkId = networkId,
        }));
    if (ret != Channel<CooperateEvent>::NO_ERROR) {
        FI_HILOGE("Failed to send event via channel, error:%{public}d", ret);
    }
    return RET_OK;
}

int32_t Cooperate::UnregisterEventListener(int32_t pid, const std::string &networkId)
{
    CALL_DEBUG_ENTER;
    auto ret = context_.Sender().Send(CooperateEvent(
        CooperateEventType::UNREGISTER_EVENT_LISTENER,
        UnregisterEventListenerEvent {
            .pid = pid,
            .networkId = networkId,
        }));
    if (ret != Channel<CooperateEvent>::NO_ERROR) {
        FI_HILOGE("Failed to send event via channel, error:%{public}d", ret);
    }
    return RET_OK;
}

int32_t Cooperate::GetCooperateState(const std::string &udId, bool &state)
{
    CALL_DEBUG_ENTER;
    state = sm_.IsCooperateEnable();
    return RET_OK;
}

int32_t Cooperate::Update(uint32_t mask, uint32_t flag)
{
    auto ret = context_.Sender().Send(CooperateEvent(
        CooperateEventType::UPDATE_COOPERATE_FLAG,
        UpdateCooperateFlagEvent {
            .mask = mask,
            .flag = flag,
        }));
    if (ret != Channel<CooperateEvent>::NO_ERROR) {
        FI_HILOGE("Failed to send event via channel, error:%{public}d", ret);
    }
    return RET_OK;
}

void Cooperate::Dump(int32_t fd)
{
    CALL_DEBUG_ENTER;
    auto ret = context_.Sender().Send(CooperateEvent(
        CooperateEventType::DUMP,
        DumpEvent {
            .fd = fd
        }));
    if (ret != Channel<CooperateEvent>::NO_ERROR) {
        FI_HILOGE("Failed to send event via channel, error:%{public}d", ret);
    }
}

void Cooperate::Loop()
{
    CALL_DEBUG_ENTER;
    bool running = true;
    SetThreadName("OS_Cooperate");
    LoadMotionDrag();

    while (running) {
        CooperateEvent event = receiver_.Receive();
        switch (event.type) {
            case CooperateEventType::NOOP: {
                break;
            }
            case CooperateEventType::QUIT: {
                FI_HILOGI("Skip out of loop");
                running = false;
                break;
            }
            default: {
                sm_.OnEvent(context_, event);
                break;
            }
        }
    }
}

void Cooperate::StartWorker()
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(lock_);
    if (!workerStarted_) {
        workerStarted_ = true;
        worker_ = std::thread([this] { this->Loop(); });
    }
}

void Cooperate::StopWorker()
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(lock_);
    if (workerStarted_) {
        auto ret = context_.Sender().Send(CooperateEvent(CooperateEventType::QUIT));
        if (ret != Channel<CooperateEvent>::NO_ERROR) {
            FI_HILOGE("Failed to send event via channel, error:%{public}d", ret);
        }
        if (worker_.joinable()) {
            worker_.join();
        }
        workerStarted_ = false;
    }
}

void Cooperate::LoadMotionDrag()
{
    FI_HILOGI("Load 'MotionDrag' module");
    IMotionDrag *motionDrag = env_->GetPluginManager().LoadMotionDrag();
    if (motionDrag == nullptr) {
        FI_HILOGE("Failed to load motion drag");
        return;
    }
    motionDrag->Enable(context_.EventHandler());
}

extern "C" ICooperate* CreateInstance(IContext *env)
{
    CHKPP(env);
    return new Cooperate(env);
}

extern "C" void DestroyInstance(ICooperate *instance)
{
    if (instance != nullptr) {
        delete instance;
    }
}
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS