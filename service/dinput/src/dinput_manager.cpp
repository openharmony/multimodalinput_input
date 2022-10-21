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

#include "define_multimodal.h"
#include "dinput_callback.h"
#include "distributed_input_kit.h"
#include "input_device_manager.h"
#include "dinput_manager.h"

using namespace OHOS::DistributedHardware::DistributedInput;
namespace OHOS {
namespace MMI {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "DInputManager" };
}

DInputManager::DInputManager() {}
DInputManager::~DInputManager() {}

void DInputManager::SetMouseLocation(const DMouseLocation& info)
{
    mouseLocation_ = info;
}

DMouseLocation& DInputManager::GetMouseLocation()
{
    return mouseLocation_;
}

bool DInputManager::IsControllerSide(uint32_t inputAbility)
{
    CALL_INFO_TRACE;
    DInputServerType type = GetDInputServerType(inputAbility);
    MMI_HILOGI("type:%{public}d", type);
    return type != DInputServerType::SINK_SERVER_TYPE;
}

bool DInputManager::IsDistributedInput(uint32_t inputAbility)
{
    CALL_INFO_TRACE;
    DInputServerType type = GetDInputServerType(inputAbility);
    MMI_HILOGI("type:%{public}d", type);
    return type != DInputServerType::NULL_SERVER_TYPE;
}

bool DInputManager::CheckWhiteList(const std::shared_ptr<KeyEvent>& key, bool &jumpIntercept)
{
    CALL_INFO_TRACE;
    jumpIntercept = false;
    std::string deviceId = "";
    DInputServerType type = GetDInputServerType(DInputManager::KEYBOARD_ABILITY);
    if (DInputServerType::SOURCE_SERVER_TYPE == type) {
        std::shared_ptr<InputDevice> inputDevice = InputDevMgr->GetRemoteInputDevice(key->GetDeviceId());
        if (inputDevice != nullptr) {
            deviceId = inputDevice->GetNetworkId();
            if (!IsNeedFilterOut(deviceId, key)) {
                return true;
            }
        }
    } else if (DInputServerType::SINK_SERVER_TYPE == type) {
        if (!IsNeedFilterOut(deviceId, key)) {
            return true;
        } else {
            jumpIntercept = true;
            MMI_HILOGW("Events are filtered");
        }
    }
    return false;
}

DInputServerType DInputManager::GetDInputServerType(uint32_t inputAbility)
{
    CALL_INFO_TRACE;
    DInputServerType type = DistributedInputKit::IsStartDistributedInput(inputAbility);
    MMI_HILOGI("type:%{public}d", type);
    return type;
}

bool DInputManager::IsNeedFilterOut(const std::string& deviceId, const std::shared_ptr<KeyEvent>& key)
{
    CALL_INFO_TRACE;
    CHKPF(key);
    const std::vector<OHOS::MMI::KeyEvent::KeyItem>& pressedKeys = key->GetKeyItems();
    std::vector<int32_t> pressedKeysForDInput;
    pressedKeysForDInput.reserve(pressedKeys.size());
    for (size_t i = 0; i < pressedKeys.size(); i++) {
        pressedKeysForDInput.push_back(pressedKeys[i].GetKeyCode());
    }
    BusinessEvent businessEvent;
    businessEvent.keyCode = key->GetKeyCode();
    businessEvent.keyAction = key->GetKeyAction();
    businessEvent.pressedKeys = pressedKeysForDInput;
    for (const auto &item : businessEvent.pressedKeys) {
        MMI_HILOGI("pressedKeys:%{public}d", item);
    }
    MMI_HILOGI("deviceId:%{public}s, keyCode:%{public}d, keyAction:%{public}d",
        GetAnonyString(deviceId).c_str(), businessEvent.keyCode, businessEvent.keyAction);
    if (!DistributedInputKit::IsNeedFilterOut(deviceId, businessEvent)) {
        MMI_HILOGI("IsNeedFilterOut:%{public}s", "false");
    }
    return true;
}

int32_t DInputManager::PrepareRemoteInput(const std::string& deviceId, sptr<ICallDinput> prepareDinput)
{
    CALL_INFO_TRACE;
    sptr<PrepareDInputCallback> callback = new PrepareDInputCallback(prepareDinput);
    CHKPR(callback, ERROR_NULL_POINTER);
    return DistributedInputKit::PrepareRemoteInput(deviceId, callback);
}

int32_t DInputManager::UnprepareRemoteInput(const std::string& deviceId, sptr<ICallDinput> prepareDinput)
{
    CALL_INFO_TRACE;
    sptr<UnprepareDInputCallback> callback = new UnprepareDInputCallback(prepareDinput);
    CHKPR(callback, ERROR_NULL_POINTER);
    return DistributedInputKit::UnprepareRemoteInput(deviceId, callback);
}

int32_t DInputManager::StartRemoteInput(const std::string& deviceId, uint32_t inputAbility,
    sptr<ICallDinput> prepareDinput)
{
    CALL_INFO_TRACE;
    sptr<StartDInputCallback> callback = new StartDInputCallback(prepareDinput);
    CHKPR(callback, ERROR_NULL_POINTER);
    DistributedInputKit::IsStartDistributedInput(inputAbility);
    return DistributedInputKit::StartRemoteInput(deviceId, inputAbility, callback);
}

int32_t DInputManager::StopRemoteInput(const std::string& deviceId, uint32_t inputAbility,
    sptr<ICallDinput> prepareDinput)
{
    CALL_INFO_TRACE;
    sptr<StopDInputCallback> callback = new StopDInputCallback(prepareDinput);
    CHKPR(callback, ERROR_NULL_POINTER);
    return DistributedInputKit::StopRemoteInput(deviceId,
        inputAbility, callback);
}

void DInputManager::OnStartRemoteInput(const std::string& deviceId, uint32_t inputTypes)
{
    MMI_HILOGI("Enter: inputTypes:%{public}d", inputTypes);
    int32_t diffBit = (inputTypes_ & DInputManager::FULL_ABILITY) ^ (inputTypes & DInputManager::FULL_ABILITY);
    MMI_HILOGI("diffBit:%{public}d", diffBit);
    if (diffBit == 0) {
        return;
    }
    inputTypes_ = (inputTypes_ & DInputManager::FULL_ABILITY) | (inputTypes & DInputManager::FULL_ABILITY);
    MMI_HILOGI("inputTypes_:%{public}d", inputTypes_);
    int32_t addTypes = diffBit & (inputTypes & DInputManager::FULL_ABILITY);
    MMI_HILOGI("addTypes:%{public}d", addTypes);
    if (addTypes != 0) {
        InputDevMgr->OnStartRemoteInput(deviceId, addTypes);
    }
}

void DInputManager::OnStopRemoteInput(const std::string& deviceId, uint32_t inputTypes)
{
    MMI_HILOGI("Enter: inputTypes:%{public}d", inputTypes);
    int32_t removeTypes = (inputTypes_ & DInputManager::FULL_ABILITY) & (inputTypes & DInputManager::FULL_ABILITY);
    MMI_HILOGI("removeTypes:%{public}d", removeTypes);
    if (removeTypes == 0) {
        MMI_HILOGE("Stop remoteInput failed");
        return;
    }
    inputTypes_ = inputTypes_ ^ removeTypes;
    MMI_HILOGI("inputTypes_:%{public}d", inputTypes_);
    InputDevMgr->OnStopRemoteInput(deviceId, removeTypes);
}
} // namespace MMI
} // namespace OHOS
