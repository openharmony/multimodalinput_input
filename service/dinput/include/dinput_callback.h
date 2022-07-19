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

#ifndef DINPUT_CALLBACK_H
#define DINPUT_CALLBACK_H
#ifdef OHOS_DISTRIBUTED_INPUT_MODEL

#include <string>
#include <vector>

#include "prepare_d_input_call_back_stub.h"
#include "start_d_input_call_back_stub.h"
#include "stop_d_input_call_back_stub.h"
#include "unprepare_d_input_call_back_stub.h"

#include "i_call_dinput.h"

namespace OHOS {
namespace MMI {
class PrepareDInputCallback : public OHOS::DistributedHardware::DistributedInput::PrepareDInputCallbackStub {
public:
    explicit PrepareDInputCallback(sptr<ICallDinput> prepareDinput) : callback_(prepareDinput) {}
    ~PrepareDInputCallback() = default;
    void OnResult(const std::string& deviceId, const int32_t& status) override;
private:
    sptr<ICallDinput> callback_ { nullptr };
};

class StartDInputCallback : public OHOS::DistributedHardware::DistributedInput::StartDInputCallbackStub {
public:
    explicit StartDInputCallback(sptr<ICallDinput> prepareDinput) : callback_(prepareDinput) {}
    ~StartDInputCallback() = default;
    void OnResult(const std::string& deviceId, const uint32_t& inputTypes, const int32_t& status) override;
private:
    sptr<ICallDinput> callback_ { nullptr };
};

class StopDInputCallback : public OHOS::DistributedHardware::DistributedInput::StopDInputCallbackStub {
public:
    explicit StopDInputCallback(sptr<ICallDinput> prepareDinput) : callback_(prepareDinput) {}
    ~StopDInputCallback() = default;
    void OnResult(const std::string& deviceId, const uint32_t& inputTypes, const int32_t& status) override;
private:
    sptr<ICallDinput> callback_ { nullptr };
};

class UnprepareDInputCallback : public OHOS::DistributedHardware::DistributedInput::UnprepareDInputCallbackStub {
public:
    explicit UnprepareDInputCallback(sptr<ICallDinput> prepareDinput) : callback_(prepareDinput) {}
    ~UnprepareDInputCallback() = default;
    void OnResult(const std::string& deviceId, const int32_t& status) override;
private:
    sptr<ICallDinput> callback_ { nullptr };
};
}
}
#endif // OHOS_DISTRIBUTED_INPUT_MODEL
#endif // DINPUT_CALLBACK_H
