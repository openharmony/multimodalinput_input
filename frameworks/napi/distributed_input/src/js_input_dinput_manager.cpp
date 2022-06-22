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


#include "js_input_dinput_manager.h"

#include <map>

#include "input_manager.h"
#include "util_napi.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsInputDinputManager" };
const std::string CREATE_ARRAY = "napi_create_array";
const std::string CREATE_INT32 = "napi_create_int32";
const std::string CREATE_STRING = "napi_create_string";
const std::string CREATE_OBJECT = "napi_create_object";
const std::string SET_NAMED_PROPERTY = "napi_set_named_property";
const std::string SET_ELEMENT = "napi_set_element";
const std::string GET_REFERENCE = "napi_get_reference_value";
const std::string CALL_FUNCTION = "napi_call_function";
const std::string RESOLVE_DEFERRED = "napi_resolve_deferred";
const std::string REFERENCE_UNREF = "reference_unref";
const std::string DELETE_REFERENCE = "napi_delete_reference";
const std::string DELETE_ASYNC_WORK = "napi_delete_async_work";
const std::string CREATE_STRING_LATIN = "napi_create_string_latin1";
std::mutex mutex_;
constexpr uint32_t EVDEV_UDEV_TAG_KEYBOARD = (1 << 1);
constexpr uint32_t EVDEV_UDEV_TAG_MOUSE = (1 << 2);
constexpr uint32_t EVDEV_UDEV_TAG_TOUCHPAD = (1 << 3);
std::map<int32_t, int32_t> deviceTypeMap = {
    {InputAbilityType::KEYBOARD, EVDEV_UDEV_TAG_KEYBOARD},
    {InputAbilityType::MOUSE, EVDEV_UDEV_TAG_MOUSE},
    {InputAbilityType::TOUCHPAD, EVDEV_UDEV_TAG_TOUCHPAD},
};
}

napi_value JsInputDinputManager::PrepareRemoteInput(napi_env env, const std::string& deviceId, napi_ref handle)
{
    CALL_LOG_ENTER;
    CHKPP(handle);
    auto cb = CreateCallbackInfo<int32_t>(env, handle);
    CHKPP(cb);
    InputManager::GetInstance()->PrepareRemoteInput(deviceId, [cb](int32_t returnResult) {
        CHKPL(cb);
        cb->returnResult = returnResult;
        JsInputDinputManager::HandleCallBack(cb);
    });
    return cb->promise;
}

napi_value JsInputDinputManager::UnprepareRemoteInput(napi_env env, const std::string& deviceId, napi_ref handle)
{
    CALL_LOG_ENTER;
    CHKPP(handle);
    auto cb = CreateCallbackInfo<int32_t>(env, handle);
    CHKPP(cb);
    InputManager::GetInstance()->UnprepareRemoteInput(deviceId, [cb](int32_t returnResult) {
        CHKPL(cb);
        cb->returnResult = returnResult;
        JsInputDinputManager::HandleCallBack(cb);
    });
    CHKPP(handle);
    return cb->promise;
}

napi_value JsInputDinputManager::StartRemoteInput(napi_env env, const std::string& deviceId,
    const std::vector<uint32_t>& inputAbility, napi_ref handle)
{
    CALL_LOG_ENTER;
    CHKPP(handle);
    auto cb = CreateCallbackInfo<int32_t>(env, handle);
    uint32_t ability = GetAbilityType(inputAbility);
    CHKPP(cb);
    InputManager::GetInstance()->StartRemoteInput(deviceId, ability, [cb](int32_t returnResult) {
        CHKPL(cb);
        cb->returnResult = returnResult;
        JsInputDinputManager::HandleCallBack(cb);
    });
    CHKPP(handle);
    return cb->promise;
}

napi_value JsInputDinputManager::StopRemoteInput(napi_env env, const std::string& deviceId,
    const std::vector<uint32_t>& inputAbility, napi_ref handle)
{
    CALL_LOG_ENTER;
    CHKPP(handle);
    auto cb = CreateCallbackInfo<int32_t>(env, handle);
    uint32_t ability = GetAbilityType(inputAbility);
    CHKPP(cb);
    InputManager::GetInstance()->StopRemoteInput(deviceId, ability, [cb](int32_t returnResult) {
        CHKPL(cb);
        cb->returnResult = returnResult;
        JsInputDinputManager::HandleCallBack(cb);
    });
    CHKPP(handle);
    return cb->promise;
}

napi_value JsInputDinputManager::GetRemoteInputAbility(napi_env env, const std::string& deviceId, napi_ref handle)
{
    CALL_LOG_ENTER;
    CHKPP(handle);
    auto cb = CreateCallbackInfo<std::set<int32_t>>(env, handle);
    CHKPP(cb);
    InputManager::GetInstance()->GetRemoteInputAbility(deviceId, [cb](std::set<int32_t> returnResult) {
        CHKPL(cb);
        cb->returnResult = returnResult;
        JsInputDinputManager::HandleCallBack(cb);
    });
    CHKPP(handle);
    return cb->promise;
}

uint32_t JsInputDinputManager::GetAbilityType(std::vector<uint32_t> abilities)
{
    CALL_LOG_ENTER;
    uint32_t inputAbility = 0;
    for (const auto& item : abilities) {
        inputAbility |= item;
    }
    return inputAbility & (InputAbilityType::MOUSE | InputAbilityType::KEYBOARD);
}

void JsInputDinputManager::HandleCallBack(CallbackInfo<int32_t>* cb)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    napi_value resourceName = nullptr;
    CHKPV(cb);
    CHKRV(cb->env, napi_create_string_latin1(cb->env, "HandleCallBack", NAPI_AUTO_LENGTH, &resourceName),
        CREATE_STRING_LATIN);
    napi_status retStatus = napi_create_async_work(
        cb->env, nullptr, resourceName,
        [](napi_env env, void *data) {},
        [](napi_env env, napi_status status, void *data) {
            (void)status;
            auto cbInfo = static_cast<CallbackInfo<int32_t>*>(data);
            napi_value resultObj[1] = { 0 };
            if (cbInfo->returnResult == RET_OK) {
               napi_get_undefined(cbInfo->env, &resultObj[0]);
            } else {
                napi_value result = nullptr;
                CHKRV(env, napi_create_int32(cbInfo->env, cbInfo->returnResult, &result), CREATE_INT32);
                CHKRV(env, napi_create_object(cbInfo->env, &resultObj[0]), CREATE_OBJECT);
                CHKRV(env, napi_set_named_property(cbInfo->env, resultObj[0], "code",
                    result), SET_NAMED_PROPERTY);
            }
            if (cbInfo->promise != nullptr) {
                CallFunctionPromise(cbInfo->env, cbInfo->deferred, resultObj[0]);
            } else if (cbInfo->ref != nullptr) {
                CallFunctionAsync(cbInfo->env, cbInfo->ref, PARAMERTER_NUM, &resultObj[0]);
            }
            MMI_HILOGD("async_work end");
            CHKRV(env, napi_delete_reference(env, cbInfo->ref), DELETE_REFERENCE);
            CHKRV(env, napi_delete_async_work(env, cbInfo->asyncWork), DELETE_ASYNC_WORK);
            delete cbInfo;
        }, (void *)cb, &cb->asyncWork);
    if (retStatus != napi_ok) {
        MMI_HILOGE("create async work fail");
    }
    napi_queue_async_work(cb->env, cb->asyncWork);
}

void JsInputDinputManager::HandleCallBack(CallbackInfo<std::set<int32_t>>* cb)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    napi_value resourceName = nullptr;
    CHKPV(cb);
    CHKRV(cb->env, napi_create_string_latin1(cb->env, "HandleCallBack", NAPI_AUTO_LENGTH, &resourceName),
        CREATE_STRING_LATIN);
    napi_status retStatus = napi_create_async_work(
        cb->env, nullptr, resourceName,
        [](napi_env env, void *data) {},
        [](napi_env env, napi_status status, void *data) {
            (void)status;
            auto cbInfo = static_cast<CallbackInfo<std::set<int32_t>>*>(data);
            napi_value resultObj[2] = {};
            napi_get_undefined(cbInfo->env, &resultObj[0]);
            resultObj[1] = MakeInputAbilityObj(cbInfo->env, cbInfo->returnResult);
            CHKPV(resultObj);
            if (cbInfo->promise != nullptr) {
                CallFunctionPromise(cbInfo->env, cbInfo->deferred, resultObj[1]);
            } else if (cbInfo->ref != nullptr) {
                CallFunctionAsync(cbInfo->env, cbInfo->ref, (PARAMERTER_NUM + 1), &resultObj[0]);
            }
            MMI_HILOGD("async_work end");
            CHKRV(env, napi_delete_reference(env, cbInfo->ref), DELETE_REFERENCE);
            CHKRV(env, napi_delete_async_work(env, cbInfo->asyncWork), DELETE_ASYNC_WORK);
            delete cbInfo;
        }, (void *)cb, &cb->asyncWork);
    if (retStatus != napi_ok) {
        MMI_HILOGE("create async work fail");
    }
    napi_queue_async_work(cb->env, cb->asyncWork);
}

napi_value JsInputDinputManager::MakeInputAbilityObj(napi_env env, std::set<int32_t> types)
{
    napi_value returnResult = nullptr;
    napi_value resultArry = nullptr;
    int32_t i = 0;
    CHKRP(env, napi_create_array(env, &resultArry), CREATE_ARRAY);
    for (const auto& deviceType : types) {
        MMI_HILOGD("deviceType:%{public}d", deviceType);
        for (const auto& item : deviceTypeMap) {
            MMI_HILOGD("deviceType:%{public}d, item.second:%{public}d", deviceType, item.second);
            if (deviceType & item.second) {
                CHKRP(env, napi_create_int32(env, item.first, &returnResult), CREATE_INT32);
                CHKRP(env, napi_set_element(env, resultArry, i++, returnResult), SET_ELEMENT);
                break;
            }
        }
    }
    napi_value resultObj;
    CHKRP(env, napi_create_object(env, &resultObj), CREATE_OBJECT);
    CHKRP(env, napi_set_named_property(env, resultObj, "inputAbility", resultArry), SET_NAMED_PROPERTY);
    return resultObj;
}

void JsInputDinputManager::CallFunctionPromise(napi_env env, napi_deferred deferred, napi_value object)
{
    CALL_LOG_ENTER;
    CHKRV(env, napi_resolve_deferred(env, deferred, object), RESOLVE_DEFERRED);
}

void JsInputDinputManager::CallFunctionAsync(napi_env env, napi_ref handleRef, size_t count, napi_value* object)
{
    CALL_LOG_ENTER;
    napi_value handler = nullptr;
    CHKRV(env, napi_get_reference_value(env, handleRef, &handler), GET_REFERENCE);
    napi_value result = nullptr;
    if (handler != nullptr) {
        CHKRV(env, napi_call_function(env, nullptr, handler, count, object, &result), CALL_FUNCTION);
    } else {
        MMI_HILOGE("handler is nullptr");
    }
    uint32_t refCount = 0;
    CHKRV(env, napi_reference_unref(env, handleRef, &refCount), REFERENCE_UNREF);
}
} // namespace MMI
} // namespace OHOS