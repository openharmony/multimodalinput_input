/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "i_cooperate_state.h"

#undef LOG_TAG
#define LOG_TAG "ICooperateState"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {

ICooperateState::ICooperateStep::ICooperateStep(ICooperateState &parent, std::shared_ptr<ICooperateStep> prev)
    : parent_(parent), prev_(prev)
{}

void ICooperateState::TransiteTo(Context &context, CooperateState state)
{
    parent_.TransiteTo(context, state);
}

void ICooperateState::Switch(std::shared_ptr<ICooperateStep> step)
{
    if (step != nullptr) {
        current_ = step;
    }
}

void ICooperateState::ICooperateStep::OnEvent(Context &context, const CooperateEvent &event)
{
    if (auto iter = handlers_.find(event.type); iter != handlers_.end()) {
        iter->second(context, event);
    } else if (event.type != CooperateEventType::INPUT_POINTER_EVENT) {
        FI_HILOGD("Unhandled event(%{public}d)", event.type);
    }
}

void ICooperateState::ICooperateStep::SetNext(std::shared_ptr<ICooperateStep> next)
{
    if (next != nullptr) {
        next_ = next;
    } else if (next_ != nullptr) {
        next_->SetNext(nullptr);
        next_ = nullptr;
    }
}

void ICooperateState::ICooperateStep::TransiteTo(Context &context, CooperateState state)
{
    parent_.TransiteTo(context, state);
}

void ICooperateState::ICooperateStep::Switch(std::shared_ptr<ICooperateStep> step)
{
    parent_.Switch(step);
}

void ICooperateState::ICooperateStep::Proceed(Context &context, const CooperateEvent &event)
{
    if (next_ != nullptr) {
        Switch(next_);
        next_->OnProgress(context, event);
    }
}

void ICooperateState::ICooperateStep::Reset(Context &context, const CooperateEvent &event)
{
    if (prev_ != nullptr) {
        Switch(prev_);
        prev_->OnReset(context, event);
    }
}

std::string ICooperateState::Process::Peer() const
{
    return remoteNetworkId_;
}

int32_t ICooperateState::Process::StartDeviceId() const
{
    return startDeviceId_;
}

bool ICooperateState::Process::IsPeer(const std::string &networkId) const
{
    return (networkId == remoteNetworkId_);
}

void ICooperateState::Process::StartCooperate(Context &context, const StartCooperateEvent &event)
{
    remoteNetworkId_ = event.remoteNetworkId;
    startDeviceId_ = event.startDeviceId;
}

void ICooperateState::Process::RemoteStart(Context &context, const DSoftbusStartCooperate &event)
{
    remoteNetworkId_ = event.networkId;
}

void ICooperateState::Process::RelayCooperate(Context &context, const DSoftbusRelayCooperate &event)
{
    remoteNetworkId_ = event.targetNetworkId;
}
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
