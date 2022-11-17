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

#ifndef DISTRIBUTED_INPUT_ADAPTER_H
#define DISTRIBUTED_INPUT_ADAPTER_H

#include <functional>
#include <map>

#include <string>
#include <vector>

#include "distributed_input_kit.h"
#include "i_start_stop_d_inputs_call_back.h"
#include "nocopyable.h"
#include "prepare_d_input_call_back_stub.h"
#include "simulation_event_listener_stub.h"
#include "singleton.h"
#include "start_d_input_call_back_stub.h"
#include "start_stop_d_inputs_call_back_stub.h"
#include "start_stop_result_call_back_stub.h"
#include "stop_d_input_call_back_stub.h"
#include "unprepare_d_input_call_back_stub.h"

#include "define_multimodal.h"

namespace OHOS {
namespace MMI {
class DistributedInputAdapter final {
    DECLARE_DELAYED_SINGLETON(DistributedInputAdapter);
public:
    using DInputCallback = std::function<void(bool)>;
    using SimulateEventCallback = std::function<void(uint32_t type, uint32_t code, int32_t value)>;
    DISALLOW_COPY_AND_MOVE(DistributedInputAdapter);

    bool IsNeedFilterOut(const std::string &deviceId,
                         const DistributedHardware::DistributedInput::BusinessEvent &event);

    int32_t StartRemoteInput(const std::string &srcId, const std::string &sinkId, const uint32_t &inputTypes,
                             DInputCallback callback);
    int32_t StopRemoteInput(const std::string &srcId, const std::string &sinkId, const uint32_t &inputTypes,
                            DInputCallback callback);

    int32_t StartRemoteInput(const std::string &srcId, const std::string &sinkId, const std::vector<std::string> &dhIds,
                             DInputCallback callback);
    int32_t StopRemoteInput(const std::string &srcId, const std::string &sinkId, const std::vector<std::string> &dhIds,
                            DInputCallback callback);

    int32_t StartRemoteInput(const std::string &deviceId,
                             const std::vector<std::string> &dhIds, DInputCallback callback);
    int32_t StopRemoteInput(const std::string &deviceId,
                            const std::vector<std::string> &dhIds, DInputCallback callback);

    int32_t PrepareRemoteInput(const std::string &srcId, const std::string &sinkId, DInputCallback callback);
    int32_t UnPrepareRemoteInput(const std::string &srcId, const std::string &sinkId, DInputCallback callback);

    int32_t PrepareRemoteInput(const std::string &deviceId, DInputCallback callback);
    int32_t UnPrepareRemoteInput(const std::string &deviceId, DInputCallback callback);

    int32_t RegisterEventCallback(SimulateEventCallback callback);
    int32_t UnregisterEventCallback(SimulateEventCallback callback);

private:
    enum class CallbackType {
        StartDInputCallback,
        StartDInputCallbackDHIds,
        StartDInputCallbackSink,
        StopDInputCallback,
        StopDInputCallbackDHIds,
        StopDInputCallbackSink,
        PrepareStartDInputCallback,
        UnPrepareStopDInputCallback,
        PrepareStartDInputCallbackSink,
        UnPrepareStopDInputCallbackSink,
    };

    struct TimerInfo {
        int32_t times { 0 };
        int32_t timerId { 0 };
    };

    class StartDInputCallback final : public DistributedHardware::DistributedInput::StartDInputCallbackStub {
    public:
        void OnResult(const std::string &devId, const uint32_t &inputTypes, const int32_t &status) override;
    };

    class StopDInputCallback final : public DistributedHardware::DistributedInput::StopDInputCallbackStub {
    public:
        void OnResult(const std::string &devId, const uint32_t &inputTypes, const int32_t &status) override;
    };

    class StartDInputCallbackDHIds final :
        public DistributedHardware::DistributedInput::StartStopDInputsCallbackStub {
    public:
        void OnResultDhids(const std::string &devId, const int32_t &status) override;
    };

    class StopDInputCallbackDHIds final :
        public DistributedHardware::DistributedInput::StartStopDInputsCallbackStub {
    public:
        void OnResultDhids(const std::string &devId, const int32_t &status) override;
    };

    class StartDInputCallbackSink final :
        public DistributedHardware::DistributedInput::StartStopDInputsCallbackStub {
    public:
        void OnResultDhids(const std::string &devId, const int32_t &status) override;
    };

    class StopDInputCallbackSink final :
        public DistributedHardware::DistributedInput::StartStopDInputsCallbackStub {
    public:
        void OnResultDhids(const std::string &devId, const int32_t &status) override;
    };

    class PrepareStartDInputCallback final :
        public DistributedHardware::DistributedInput::PrepareDInputCallbackStub {
    public:
        void OnResult(const std::string &devId, const int32_t &status) override;
    };

    class UnPrepareStopDInputCallback final :
        public DistributedHardware::DistributedInput::UnprepareDInputCallbackStub {
    public:
        void OnResult(const std::string &devId, const int32_t &status) override;
    };

    class PrepareStartDInputCallbackSink final :
        public DistributedHardware::DistributedInput::PrepareDInputCallbackStub {
    public:
        void OnResult(const std::string &devId, const int32_t &status) override;
    };

    class UnPrepareStopDInputCallbackSink final :
        public DistributedHardware::DistributedInput::UnprepareDInputCallbackStub {
    public:
        void OnResult(const std::string &devId, const int32_t &status) override;
    };

    class SimulateEventCallbackImpl final :
        public DistributedHardware::DistributedInput::SimulationEventListenerStub {
    public:
        int32_t OnSimulationEvent(uint32_t type, uint32_t code, int32_t value) override;
    };
    
    void SaveCallback(CallbackType type, DInputCallback callback);
    void AddTimer(const CallbackType &type);
    void RemoveTimer(const CallbackType &type);
    void ProcessDInputCallback(CallbackType type, int32_t status);
    void OnSimulationEvent(uint32_t type, uint32_t code, int32_t value);
    std::map<CallbackType, TimerInfo> watchingMap_;
    std::map<CallbackType, DInputCallback> callbackMap_;
    SimulateEventCallback SimulateEventCallback_ = { nullptr };
    sptr<SimulateEventCallbackImpl> simulationEventListener_ { nullptr };
    std::mutex adapterLock_;
};

#define DistributedAdapter ::OHOS::DelayedSingleton<DistributedInputAdapter>::GetInstance()
} // namespace MMI
} // namespace OHOS

#endif // DISTRIBUTED_INPUT_ADAPTER_H
