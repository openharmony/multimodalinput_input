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

#ifndef IINPUT_DEVICE_COOPERATE_STATE_H
#define IINPUT_DEVICE_COOPERATE_STATE_H

#include <atomic>
#include <map>
#include <mutex>
#include <set>
#include <string>

#include "cooperate_event_handler.h"
#include "cooperation_message.h"
#include "define_multimodal.h"

namespace OHOS {
namespace MMI {
class IInputDeviceCooperateState {
public:
    IInputDeviceCooperateState();
    virtual ~IInputDeviceCooperateState() = default;
    virtual int32_t StartInputDeviceCooperate(const std::string &remoteNetworkId, int32_t startInputDeviceId)
    {
        return static_cast<int32_t>(CooperationMessage::COOPERATE_FAIL);
    }
    virtual int32_t StopInputDeviceCooperate(const std::string &networkId)
    {
        return static_cast<int32_t>(CooperationMessage::COOPERATE_FAIL);
    }
    virtual void OnKeyboardOnline(const std::string &dhid) {}
    virtual void UpdateSinkDeviceInfo(const std::map<std::string, std::set<std::string>> &sinkDeviceInfo) {}

protected:
    int32_t PrepareAndStart(const std::string &srcNetworkId, int32_t startInputDeviceId);
    bool NeedPrepare(const std::string &srcNetworkId, const std::string &sinkNetworkId);
    void OnPrepareDistributedInput(bool isSuccess, const std::string &srcNetworkId, int32_t startInputDeviceId);
    int32_t StartRemoteInput(int32_t startInputDeviceId);
    virtual void OnStartRemoteInput(bool isSuccess, const std::string &srcNetworkId, int32_t startInputDeviceId);

protected:
    std::shared_ptr<AppExecFwk::EventRunner> runner_ { nullptr };
    std::shared_ptr<CooperateEventHandler> eventHandler_ { nullptr };
};
} // namespace MMI
} // namespace OHOS
#endif // IINPUT_DEVICE_COOPERATE_STATE_H
