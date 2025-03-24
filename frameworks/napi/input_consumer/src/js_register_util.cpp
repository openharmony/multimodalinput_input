/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "js_register_util.h"

#include "input_manager.h"
#include "napi_constants.h"
#include "util_napi_error.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JSRegisterUtil"

namespace OHOS {
namespace MMI {

bool TypeOf(napi_env env, napi_value value, napi_valuetype type)
{
    napi_valuetype valueType = napi_undefined;
    CHKRF(napi_typeof(env, value, &valueType), TYPEOF);
    if (valueType != type) {
        return false;
    }
    return true;
}

void SetNamedProperty(const napi_env &env, napi_value &object, const std::string &name, int32_t value)
{
    MMI_HILOGD("%{public}s=%{public}d", name.c_str(), value);
    napi_value napiValue;
    CHKRV(napi_create_int32(env, value, &napiValue), CREATE_INT32);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), napiValue));
}

void SetNamedProperty(const napi_env &env, napi_value &object, const std::string &name, uint32_t value)
{
    napi_value napiValue;
    CHKRV(napi_create_uint32(env, value, &napiValue), CREATE_UINT32);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), napiValue));
}

void SetNamedProperty(const napi_env &env, napi_value &object, const std::string &name, int64_t value)
{
    napi_value napiValue;
    CHKRV(napi_create_int64(env, value, &napiValue), CREATE_INT64);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), napiValue));
}

void SetNamedProperty(const napi_env &env, napi_value &object, const std::string &name, std::string value)
{
    MMI_HILOGD("%{public}s=%{public}s", name.c_str(), value.c_str());
    napi_value napiValue;
    CHKRV(napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &napiValue), CREATE_STRING_UTF8);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), napiValue));
}

bool GetNamedPropertyBool(const napi_env &env, const napi_value &object, const std::string &name, bool &ret)
{
    napi_value napiValue = {};
    bool exist = false;
    napi_status status = napi_has_named_property(env, object, name.c_str(), &exist);
    if (status != napi_ok || !exist) {
        MMI_HILOGD("Can not find %{public}s property", name.c_str());
        return false;
    }
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    napi_valuetype tmpType = napi_undefined;

    CHKRF(napi_typeof(env, napiValue, &tmpType), TYPEOF);
    if (tmpType != napi_boolean) {
        MMI_HILOGE("The value is not bool");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, name.c_str(), "bool");
        return false;
    }
    CHKRF(napi_get_value_bool(env, napiValue, &ret), GET_VALUE_BOOL);
    MMI_HILOGD("%{public}s=%{public}d", name.c_str(), ret);
    return true;
}

std::optional<int32_t> GetNamedPropertyInt32(const napi_env &env, const napi_value &object, const std::string &name)
{
    napi_value napiValue = {};
    bool exist = false;
    napi_status status = napi_has_named_property(env, object, name.c_str(), &exist);
    if (status != napi_ok || !exist) {
        MMI_HILOGD("Can not find %{public}s property", name.c_str());
        return std::nullopt;
    }
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    napi_valuetype tmpType = napi_undefined;
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_HILOGE("Call napi_typeof failed");
        return std::nullopt;
    }
    if (tmpType != napi_number) {
        MMI_HILOGE("The value is not number");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, name.c_str(), "number");
        return std::nullopt;
    }
    int32_t ret = 0;
    if (napi_get_value_int32(env, napiValue, &ret) != napi_ok) {
        MMI_HILOGE("Call napi_get_value_int32 failed");
        return std::nullopt;
    }
    MMI_HILOGD("%{public}s=%{public}d", name.c_str(), ret);
    return std::make_optional(ret);
}

napi_value GetPreKeys(const napi_env &env, const napi_value &value, std::set<int32_t> &params)
{
    CALL_DEBUG_ENTER;
    uint32_t arrayLength = 0;
    CHKRP(napi_get_array_length(env, value, &arrayLength), GET_ARRAY_LENGTH);
    for (uint32_t i = 0; i < arrayLength; i++) {
        napi_value napiElement;
        CHKRP(napi_get_element(env, value, i, &napiElement), GET_ELEMENT);
        napi_valuetype valuetype;
        CHKRP(napi_typeof(env, napiElement, &valuetype), TYPEOF);
        if (valuetype != napi_number) {
            MMI_HILOGE("PreKeys Wrong argument type, Number expected");
            THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "element of preKeys must be number");
            return nullptr;
        }
        int32_t value = 0;
        CHKRP(napi_get_value_int32(env, napiElement, &value), GET_VALUE_INT32);
        if (value < 0) {
            MMI_HILOGE("preKey:%{public}d is less 0, can not process", value);
            THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "element of preKeys must be greater than or equal to 0");
            return nullptr;
        }
        MMI_HILOGD("Get int array number:%{public}d", value);
        if (!params.insert(value).second) {
            MMI_HILOGE("Params insert value failed");
            return nullptr;
        }
    }
    napi_value ret;
    CHKRP(napi_create_int32(env, RET_OK, &ret), CREATE_INT32);
    return ret;
}

int32_t GetPreSubscribeId(Callbacks &callbacks, sptr<KeyEventMonitorInfo> event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    std::lock_guard guard(sCallBacksMutex);
    auto it = callbacks.find(event->eventType);
    if (it == callbacks.end() || it->second.empty()) {
        MMI_HILOGE("The callbacks is empty");
        return JS_CALLBACK_EVENT_FAILED;
    }
    CHKPR(it->second.front(), ERROR_NULL_POINTER);
    return it->second.front()->subscribeId;
}

int32_t DelEventCallbackRef(const napi_env &env, std::list<sptr<KeyEventMonitorInfo>> &info,
    napi_value handler, int32_t &subscribeId)
{
    CALL_DEBUG_ENTER;
    for (auto iter = info.begin(); iter != info.end();) {
        if (*iter == nullptr) {
            info.erase(iter++);
            continue;
        }
        if (handler != nullptr) {
            napi_value iterHandler = nullptr;
            CHKRR(napi_get_reference_value(env, (*iter)->callback, &iterHandler),
                  GET_REFERENCE_VALUE, JS_CALLBACK_EVENT_FAILED);
            bool isEquals = false;
            CHKRR(napi_strict_equals(env, handler, iterHandler, &isEquals), STRICT_EQUALS, JS_CALLBACK_EVENT_FAILED);
            if (isEquals) {
                sptr<KeyEventMonitorInfo> monitorInfo = *iter;
                info.erase(iter++);
                if (info.empty()) {
                    subscribeId = monitorInfo->subscribeId;
                }
                MMI_HILOGD("Callback has deleted, size:%{public}zu", info.size());
                return JS_CALLBACK_EVENT_SUCCESS;
            }
            ++iter;
            continue;
        }
        sptr<KeyEventMonitorInfo> monitorInfo = *iter;
        info.erase(iter++);
        if (info.empty()) {
            subscribeId = monitorInfo->subscribeId;
        }
        MMI_HILOGD("Callback has deleted, size:%{public}zu", info.size());
    }
    MMI_HILOGD("Callback size:%{public}zu", info.size());
    return JS_CALLBACK_EVENT_SUCCESS;
}

int32_t AddEventCallback(const napi_env &env, Callbacks &callbacks, sptr<KeyEventMonitorInfo> event)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(sCallBacksMutex);
    CHKPR(event, ERROR_NULL_POINTER);
    if (callbacks.find(event->eventType) == callbacks.end()) {
        MMI_HILOGD("No callback in %{public}s", event->eventType.c_str());
        callbacks[event->eventType] = {};
    }
    napi_value handler1 = nullptr;
    napi_status status = napi_get_reference_value(env, event->callback, &handler1);
    if (status != napi_ok) {
        MMI_HILOGE("Handler1 get reference value failed");
        return JS_CALLBACK_EVENT_FAILED;
    }
    auto it = callbacks.find(event->eventType);
    for (const auto &iter: it->second) {
        napi_value handler2 = nullptr;
        status = napi_get_reference_value(env, iter->callback, &handler2);
        if (status != napi_ok) {
            MMI_HILOGE("Handler2 get reference value failed");
            return JS_CALLBACK_EVENT_FAILED;
        }
        bool isEqual = false;
        status = napi_strict_equals(env, handler1, handler2, &isEqual);
        if (status != napi_ok) {
            MMI_HILOGE("Compare two handler failed");
            return JS_CALLBACK_EVENT_FAILED;
        }
        if (isEqual) {
            MMI_HILOGE("Callback already exist");
            return JS_CALLBACK_EVENT_FAILED;
        }
    }
    it->second.push_back(event);
    return JS_CALLBACK_EVENT_SUCCESS;
}

int32_t DelEventCallback(const napi_env &env, Callbacks &callbacks, sptr<KeyEventMonitorInfo> event,
    int32_t &subscribeId)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(sCallBacksMutex);
    CHKPR(event, ERROR_NULL_POINTER);
    if (callbacks.count(event->eventType) <= 0) {
        MMI_HILOGE("Callback doesn't exists");
        return JS_CALLBACK_EVENT_FAILED;
    }
    auto &info = callbacks[event->eventType];
    MMI_HILOGD("EventType:%{private}s, keyEventMonitorInfos:%{public}zu", event->eventType.c_str(), info.size());
    napi_value eventHandler = nullptr;
    if (event->callback != nullptr) {
        CHKRR(napi_get_reference_value(env, event->callback, &eventHandler), GET_REFERENCE_VALUE,
              JS_CALLBACK_EVENT_FAILED);
    }
    return DelEventCallbackRef(env, info, eventHandler, subscribeId);
}

static void AsyncWorkFn(const napi_env &env, std::shared_ptr<KeyOption> keyOption, napi_value &result,
    std::string keyType)
{
    CHKPV(keyOption);
    MMI_HILOGD("Status > 0 enter");
    CHKRV(napi_create_object(env, &result), CREATE_OBJECT);
    napi_value arr;
    CHKRV(napi_create_array(env, &arr), CREATE_ARRAY);
    std::set <int32_t> preKeys = keyOption->GetPreKeys();
    int32_t i = 0;
    napi_value value;
    for (const auto &preKey: preKeys) {
        CHKRV(napi_create_int32(env, preKey, &value), CREATE_INT32);
        CHKRV(napi_set_element(env, arr, i, value), SET_ELEMENT);
        ++i;
    }
    std::string preKeysStr = "preKeys";
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, preKeysStr.c_str(), arr));
    MMI::SetNamedProperty(env, result, "finalKey", keyOption->GetFinalKey());
    if (keyType == SUBSCRIBE_TYPE) {
        MMI::SetNamedProperty(env, result, "isFinalKeyDown", keyOption->IsFinalKeyDown());
        MMI::SetNamedProperty(env, result, "finalKeyDownDuration", keyOption->GetFinalKeyDownDuration());
    }
    MMI::SetNamedProperty(env, result, "isRepeat", static_cast<int32_t>(keyOption->IsRepeat()));
}

void UvQueueWorkAsyncCallback(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    (void)status;
    sptr<KeyEventMonitorInfo> dataWorker(static_cast<KeyEventMonitorInfo *>(work->data));
    DeletePtr<uv_work_t *>(work);
    dataWorker->DecStrongRef(nullptr);
    CHKPV(dataWorker->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(dataWorker->env, &scope);
    CHKPV(scope);
    napi_value callback = nullptr;
    MMI_HILOGD("Deliver uv work from %{public}d", GetPid());
    if (dataWorker->callback == nullptr) {
        MMI_HILOGE("dataWorker->callback is nullptr");
        napi_close_handle_scope(dataWorker->env, scope);
        return;
    }
    if ((napi_get_reference_value(dataWorker->env, dataWorker->callback, &callback)) != napi_ok) {
        MMI_HILOGE("%{public}s failed", std::string(GET_REFERENCE_VALUE).c_str());
        napi_close_handle_scope(dataWorker->env, scope);
        return;
    }
    napi_value result = nullptr;
    AsyncWorkFn(dataWorker->env, dataWorker->keyOption, result, dataWorker->name);
    napi_value callResult = nullptr;
    if ((napi_call_function(dataWorker->env, nullptr, callback, 1, &result, &callResult)) != napi_ok) {
        MMI_HILOGE("%{public}s failed", std::string(CALL_FUNCTION).c_str());
        napi_close_handle_scope(dataWorker->env, scope);
        return;
    }
    napi_close_handle_scope(dataWorker->env, scope);
}

void EmitAsyncCallbackWork(sptr<KeyEventMonitorInfo> reportEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(reportEvent);
    uv_loop_s *loop = nullptr;
    CHKRV(napi_get_uv_event_loop(reportEvent->env, &loop), GET_UV_EVENT_LOOP);
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    reportEvent->IncStrongRef(nullptr);
    work->data = reportEvent.GetRefPtr();
    int32_t ret = uv_queue_work_with_qos(
        loop, work,
        [](uv_work_t *work) {
            MMI_HILOGD("uv_queue_work callback function is called");
        },
        UvQueueWorkAsyncCallback, uv_qos_user_initiated);
    if (ret != 0) {
        DeletePtr<uv_work_t *>(work);
    }
}

napi_value ConvertHotkeyToNapiValue(napi_env env, std::unique_ptr<KeyOption> &keyOption)
{
    napi_value obj = nullptr;
    CHKRP(napi_create_object(env, &obj), CREATE_OBJECT);
    napi_value preKeysArray = nullptr;
    CHKRP(napi_create_array(env, &preKeysArray), CREATE_ARRAY);
    int32_t index = 0;
    std::set<int32_t> preKeys = keyOption->GetPreKeys();
    for (auto key : preKeys) {
        napi_value keyVal = nullptr;
        CHKRP(napi_create_int32(env, key, &keyVal), CREATE_INT32);
        CHKRP(napi_set_element(env, preKeysArray, index++, keyVal), SET_ELEMENT);
    }
    CHKRP(napi_set_named_property(env, obj, "preKeys", preKeysArray), SET_NAMED_PROPERTY);
    napi_value finalKeyVal = nullptr;
    CHKRP(napi_create_int32(env, keyOption->GetFinalKey(), &finalKeyVal), CREATE_INT32);
    CHKRP(napi_set_named_property(env, obj, "finalKey", finalKeyVal), SET_NAMED_PROPERTY);
    return obj;
}

napi_value ConvertHotkeysToNapiArray(sptr<CallbackInfo> cb)
{
    napi_value keyOptionArray = nullptr;
    CHKRP(napi_create_array(cb->env, &keyOptionArray), CREATE_ARRAY);
    if (cb->errCode != RET_OK) {
        MMI_HILOGE("Get Hotkeys failed, errCode:%{public}d", cb->errCode);
        return keyOptionArray;
    }
    for (size_t i = 0; i < cb->keyOptions.size(); ++i) {
        napi_value obj = ConvertHotkeyToNapiValue(cb->env, cb->keyOptions[i]);
        if (obj == nullptr) {
            MMI_HILOGE("ConvertHotkeyToNapiValue fail");
            return keyOptionArray;
        }
        CHKRP(napi_set_element(cb->env, keyOptionArray, i, obj), SET_ELEMENT);
    }
    return keyOptionArray;
}

napi_value GreateBusinessError(napi_env env, int32_t errCode, std::string errMessage)
{
    CALL_DEBUG_ENTER;
    napi_value result = nullptr;
    napi_value resultCode = nullptr;
    napi_value resultMessage = nullptr;
    CHKRP(napi_create_int32(env, errCode, &resultCode), CREATE_INT32);
    CHKRP(napi_create_string_utf8(env, errMessage.data(), NAPI_AUTO_LENGTH, &resultMessage), CREATE_STRING_UTF8);
    CHKRP(napi_create_error(env, nullptr, resultMessage, &result), CREATE_ERROR);
    CHKRP(napi_set_named_property(env, result, ERR_CODE.c_str(), resultCode), SET_NAMED_PROPERTY);
    return result;
}

void CallHotkeyPromiseWork(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<CallbackInfo> cb(static_cast<CallbackInfo *>(work->data));
    DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    CHKPV(scope);
    napi_value callResult = ConvertHotkeysToNapiArray(cb);
    if (callResult == nullptr) {
        MMI_HILOGE("Check callResult is nullptr");
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, callResult), RESOLVE_DEFERRED, scope);
    napi_close_handle_scope(cb->env, scope);
}

void EmitSystemHotkey(sptr<CallbackInfo> cb)
{
    CALL_DEBUG_ENTER;
    CHKPV(cb);
    CHKPV(cb->env);
    uv_loop_s *loop = nullptr;
    CHKRV(napi_get_uv_event_loop(cb->env, &loop), GET_UV_EVENT_LOOP);
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    cb->IncStrongRef(nullptr);
    work->data = cb.GetRefPtr();
    int32_t ret = 0;
    ret = uv_queue_work_with_qos(
        loop, work,
        [](uv_work_t *work) {
            MMI_HILOGD("uv_queue_work CallHotkeyPromiseWork callback function is called");
        }, CallHotkeyPromiseWork, uv_qos_user_initiated);
    if (ret != 0) {
        MMI_HILOGE("uv_queue_work_with_qos failed");
        cb->DecStrongRef(nullptr);
        DeletePtr<uv_work_t *>(work);
    }
}

napi_value GetSystemHotkey(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<CallbackInfo> cb = new (std::nothrow) CallbackInfo();
    CHKPP(cb);
    cb->env = env;
    napi_value promise = nullptr;
    CHKRP(napi_create_promise(env, &cb->deferred, &promise), CREATE_PROMISE);
    std::vector<std::unique_ptr<KeyOption>> keyOptions;
    int32_t count = 0;
    cb->errCode = InputManager::GetInstance()->GetAllSystemHotkeys(keyOptions, count);
    cb->keyOptions = std::move(keyOptions);
    EmitSystemHotkey(cb);
    return promise;
}
} // namespace MMI
} // namespace OHOS