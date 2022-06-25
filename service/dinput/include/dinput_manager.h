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

#ifndef OHOS_DINPUT_MANAGER_H
#define OHOS_DINPUT_MANAGER_H
#ifdef OHOS_DISTRIBUTED_INPUT_MODEL

#include <string>
#include <vector>

#include "constants_dinput.h"
#include "i_call_dinput.h"
#include "key_event.h"
#include "singleton.h"

namespace OHOS {
namespace MMI {
struct DMouseLocation {
    int32_t globalX = 0;
    int32_t globalY = 0;
    int32_t dx = 0;
    int32_t dy = 0;
    int32_t displayId = 0;
};
class DInputManager : public DelayedSingleton<DInputManager> {
public:
    static const uint32_t DEFAULT_ABILITY;
    static const uint32_t MOUSE_ABILITY;
    static const uint32_t KEYBOARD_ABILITY;
    static const uint32_t FULL_ABILITY;
public:
    DInputManager() = default;
    ~DInputManager() = default;
    void SetMouseLocation(const DMouseLocation& info);
    DMouseLocation& GetMouseLocation();
    bool IsControllerSide(uint32_t inputAbility);
    bool IsDistributedInput(uint32_t inputAbility);
    bool IsNeedFilterOut(const std::string& deviceId, const std::shared_ptr<KeyEvent>& key);
    bool CheckWhiteList(const std::shared_ptr<KeyEvent>& key, bool &jumpIntercept);
    OHOS::DistributedHardware::DistributedInput::DInputServerType GetDInputServerType(uint32_t inputAbility);

    int32_t PrepareRemoteInput(const std::string& deviceId, sptr<ICallDinput> prepareDinput);
    int32_t UnprepareRemoteInput(const std::string& deviceId, sptr<ICallDinput> prepareDinput);
    int32_t StartRemoteInput(const std::string& deviceId, uint32_t inputAbility,
        sptr<ICallDinput> prepareDinput);
    int32_t StopRemoteInput(const std::string& deviceId, uint32_t inputAbility,
        sptr<ICallDinput> prepareDinput);
    void OnStartRemoteInput(const std::string& deviceId, uint32_t inputTypes);
    void OnStopRemoteInput(const std::string& deviceId, uint32_t inputTypes);
private:
    DMouseLocation mouseLocation_;
    int32_t inputTypes_ = 0;
};
}
}
#define DInputMgr OHOS::MMI::DInputManager::GetInstance()
#endif // OHOS_DISTRIBUTED_INPUT_MODEL
#endif // OHOS_DINPUT_MANAGER_H
