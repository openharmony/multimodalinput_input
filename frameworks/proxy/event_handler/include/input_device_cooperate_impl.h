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
#ifndef INPUT_DEVICE_COOPERATE_IMPL_H
#define INPUT_DEVICE_COOPERATE_IMPL_H

#include <functional>
#include <list>
#include <map>
#include <mutex>

#include "nocopyable.h"

#include "cooperation_message.h"
#include "i_input_device_cooperate_listener.h"

namespace OHOS {
namespace MMI {
class InputDeviceCooperateImpl {
public:
    static InputDeviceCooperateImpl &GetInstance();
    DISALLOW_COPY_AND_MOVE(InputDeviceCooperateImpl);
    ~InputDeviceCooperateImpl() = default;

    using FuncCooperationMessage = std::function<void(std::string, CooperationMessage)>;
    using FuncCooperateionState = std::function<void(bool)>;

    using DevCooperationMsg = FuncCooperationMessage;
    using DevCooperateionState = FuncCooperateionState;

    using InputDevCooperateListenerPtr = std::shared_ptr<IInputDeviceCooperateListener>;

    struct CooperateEvent {
        DevCooperationMsg msg;
        DevCooperateionState state;
    };

    int32_t RegisterCooperateListener(InputDevCooperateListenerPtr listener);
    int32_t UnregisterCooperateListener(InputDevCooperateListenerPtr listener = nullptr);
    int32_t EnableInputDeviceCooperate(bool enabled, FuncCooperationMessage callback);
    int32_t StartInputDeviceCooperate(const std::string &sinkDeviceId, int32_t srcInputDeviceId,
        FuncCooperationMessage callback);
    int32_t StopDeviceCooperate(FuncCooperationMessage callback);
    int32_t GetInputDeviceCooperateState(const std::string &deviceId, FuncCooperateionState callback);
    void OnDevCooperateListener(const std::string deviceId, CooperationMessage msg);
    void OnCooprationMessage(int32_t userData, const std::string deviceId, CooperationMessage msg);
    void OnCooperationState(int32_t userData, bool state);
    int32_t GetUserData();

private:
    const DevCooperationMsg *GetCooprateMessageEvent(int32_t userData) const;
    const DevCooperateionState *GetCooprateStateEvent(int32_t userData) const;

private:
    InputDeviceCooperateImpl() = default;
    std::list<InputDevCooperateListenerPtr> devCooperateListener_;
    std::map<int32_t, CooperateEvent> devCooperateEvent_;
    std::mutex mtx_;
    int32_t userData_ { 0 };
    bool isListeningProcess_ { false };
};
} // namespace MMI
} // namespace OHOS
#define InputDevCooperateImpl OHOS::MMI::InputDeviceCooperateImpl::GetInstance()
#endif // INPUT_DEVICE_COOPERATE_IMPL_H