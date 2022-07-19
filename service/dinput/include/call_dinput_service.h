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

#ifndef CALL_DINPUT_SERVICE_H
#define CALL_DINPUT_SERVICE_H
#ifdef OHOS_DISTRIBUTED_INPUT_MODEL

#include "iremote_object.h"

#include "call_dinput_stub.h"

namespace OHOS {
namespace MMI {
class CallDinputService final : public CallDinputStub {
public:
    CallDinputService() = default;
    ~CallDinputService() = default;
    int32_t HandlePrepareDinput(const std::string& deviceId, int32_t status) override;
    int32_t HandleUnprepareDinput(const std::string& deviceId, int32_t status) override;
    int32_t HandleStartDinput(const std::string& deviceId, uint32_t inputTypes, int32_t status) override;
    int32_t HandleStopDinput(const std::string& deviceId, uint32_t inputTypes, int32_t status) override;
    int32_t HandleRemoteInputAbility(const std::set<int32_t>& remoteInputAbility) override;
    void SetPrepareCallback(const std::function<void(int32_t)>& callback);
    void SetUnprepareCallback(const std::function<void(int32_t)>& callback);
    void SetStartCallback(const std::function<void(int32_t)>& callback);
    void SetStopCallback(const std::function<void(int32_t)>& callback);
    void SetRemoteAbilityCallback(std::function<void(std::set<int32_t>)>& callback);
private:
    std::function<void(int32_t)> prepareCallback_ { nullptr };
    std::function<void(int32_t)> unprepareCallback_ { nullptr };
    std::function<void(int32_t)> startCallback_ { nullptr };
    std::function<void(int32_t)> stopCallback_ { nullptr };
    std::function<void(std::set<int32_t>)> remoteAbilityCallback_ { nullptr };
};
} // namespace MMI
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_INPUT_MODEL
#endif // CALL_DINPUT_SERVICE_H
