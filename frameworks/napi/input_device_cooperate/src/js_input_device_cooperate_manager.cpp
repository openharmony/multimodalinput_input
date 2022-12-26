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

#include "define_multimodal.h"
#include "input_device_cooperate_impl.h"
#include "input_manager_impl.h"
#include "mmi_log.h"
#include "napi_constants.h"
#include "util_napi.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsInputDeviceCooperateManager" };
} // namespace

napi_value JsInputDeviceCooperateManager::Enable(napi_env env, bool enable, napi_value handle)
{
    CALL_INFO_TRACE;
    sptr<JsUtil::CallbackInfo> cb = new (std::nothrow) JsUtil::CallbackInfo();
    CHKPP(cb);
    napi_value ret = CreateCallbackInfo(env, handle, cb);
    auto callback = std::bind(EmitJsEnable, cb, std::placeholders::_1, std::placeholders::_2);
    int32_t errCode = InputMgrImpl.EnableInputDeviceCooperate(enable, callback);
    HandleExecuteResult(env, errCode);
    return ret;
}

napi_value JsInputDeviceCooperateManager::Start(napi_env env, const std::string &sinkDeviceDescriptor,
    int32_t srcInputDeviceId, napi_value handle)
{
    CALL_INFO_TRACE;
    sptr<JsUtil::CallbackInfo> cb = new (std::nothrow) JsUtil::CallbackInfo();
    CHKPP(cb);
    napi_value ret = CreateCallbackInfo(env, handle, cb);
    auto callback = std::bind(EmitJsStart, cb, std::placeholders::_1, std::placeholders::_2);
    int32_t errCode = InputMgrImpl.StartInputDeviceCooperate(sinkDeviceDescriptor, srcInputDeviceId, callback);
    HandleExecuteResult(env, errCode);
    return ret;
}

napi_value JsInputDeviceCooperateManager::Stop(napi_env env, napi_value handle)
{
    CALL_INFO_TRACE;
    sptr<JsUtil::CallbackInfo> cb = new (std::nothrow) JsUtil::CallbackInfo();
    CHKPP(cb);
    napi_value ret = CreateCallbackInfo(env, handle, cb);
    auto callback = std::bind(EmitJsStop, cb, std::placeholders::_1, std::placeholders::_2);
    int32_t errCode = InputMgrImpl.StopDeviceCooperate(callback);
    HandleExecuteResult(env, errCode);
    return ret;
}

napi_value JsInputDeviceCooperateManager::GetState(napi_env env, const std::string &deviceDescriptor, napi_value handle)
{
    CALL_INFO_TRACE;
    sptr<JsUtil::CallbackInfo> cb = new (std::nothrow) JsUtil::CallbackInfo();
    CHKPP(cb);
    napi_value ret = CreateCallbackInfo(env, handle, cb);
    auto callback = std::bind(EmitJsGetState, cb, std::placeholders::_1);
    int32_t errCode = InputMgrImpl.GetInputDeviceCooperateState(deviceDescriptor, callback);
    HandleExecuteResult(env, errCode);
    return ret;
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
