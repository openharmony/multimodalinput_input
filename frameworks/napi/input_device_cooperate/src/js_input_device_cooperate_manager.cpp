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

#include "js_input_device_cooperate_manager.h"

#include <functional>

#include "constants.h"
#include "define_multimodal.h"
#include "input_device_cooperate_impl.h"
#include "input_manager.h"
#include "mmi_log.h"
#include "util_napi.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsInputDeviceCooperateContext" };
} // namespace

napi_value JsInputDeviceCooperateManager::Enable(napi_env env, bool enable, napi_value handle)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    int32_t userData = InputDevCooperateImpl.GetUserData();
    napi_value result = CreateCallbackInfo(env, handle, userData);
    if (result == nullptr) {
        MMI_HILOGE("create callback info failed");
        return nullptr;
    }
    auto callback = std::bind(EmitJsEnable, userData, std::placeholders::_1, std::placeholders::_2);
    InputMgr->EnableInputDeviceCooperate(enable, callback);
    return result;
}

napi_value JsInputDeviceCooperateManager::Start(napi_env env, const std::string &sinkDeviceDescriptor,
    int32_t srcInputDeviceId, napi_value handle)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    int32_t userData = InputDevCooperateImpl.GetUserData();
    napi_value result = CreateCallbackInfo(env, handle, userData);
    if (result == nullptr) {
        MMI_HILOGE("create callback info failed");
        return nullptr;
    }
    auto callback = std::bind(EmitJsStart, userData, std::placeholders::_1, std::placeholders::_2);
    InputMgr->StartInputDeviceCooperate(sinkDeviceDescriptor, srcInputDeviceId, callback);
    return result;
}

napi_value JsInputDeviceCooperateManager::Stop(napi_env env, napi_value handle)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    int32_t userData = InputDevCooperateImpl.GetUserData();
    napi_value result = CreateCallbackInfo(env, handle, userData);
    if (result == nullptr) {
        MMI_HILOGE("create callback info failed");
        return nullptr;
    }
    auto callback = std::bind(EmitJsStop, userData, std::placeholders::_1, std::placeholders::_2);
    InputMgr->StopDeviceCooperate(callback);
    return result;
}

napi_value JsInputDeviceCooperateManager::GetState(napi_env env, const std::string &deviceDescriptor, napi_value handle)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    int32_t userData = InputDevCooperateImpl.GetUserData();
    napi_value result = CreateCallbackInfo(env, handle, userData);
    if (result == nullptr) {
        MMI_HILOGE("create callback info failed");
        return nullptr;
    }
    auto callback = std::bind(EmitJsGetState, userData, std::placeholders::_1);
    InputMgr->GetInputDeviceCooperateState(deviceDescriptor, callback);
    return result;
}

void JsInputDeviceCooperateManager::RegisterListener(napi_env env, const std::string &type, napi_value handle)
{
    CALL_INFO_TRACE;
    AddListener(env, type, handle);
}

void JsInputDeviceCooperateManager::UnregisterListener(napi_env env, const std::string &type, napi_value handle)
{
    CALL_INFO_TRACE;
    RemoveListener(env, type, handle);
}

void JsInputDeviceCooperateManager::ResetEnv()
{
    CALL_INFO_TRACE;
    JsEventTarget::ResetEnv();
}
} // namespace MMI
} // namespace OHOS
