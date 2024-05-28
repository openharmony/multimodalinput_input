/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <cinttypes>
#include <uv.h>

#include "error_multimodal.h"
#include "napi_constants.h"
#include "util_napi.h"
#include "util_napi_error.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JSRegisterUtil"

namespace OHOS {
namespace MMI {

void SetNamedProperty(const napi_env &env, napi_value &object, const std::string &name, int32_t value)
{
    MMI_HILOGD("%{public}s=%{public}d", name.c_str(), value);
    napi_value napiValue;
    CHKRV(napi_create_int32(env, value, &napiValue), CREATE_INT32);
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
    int32_t ret;
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

int32_t GetPreSubscribeId(Callbacks &callbacks, KeyEventMonitorInfo *event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto it = callbacks.find(event->eventType);
    if (it == callbacks.end() || it->second.empty()) {
        MMI_HILOGE("The callbacks is empty");
        return JS_CALLBACK_EVENT_FAILED;
    }
    CHKPR(it->second.front(), ERROR_NULL_POINTER);
    return it->second.front()->subscribeId;
}

int32_t DelEventCallbackRef(const napi_env &env, std::list<KeyEventMonitorInfo *> &info,
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
            CHKRR(napi_get_reference_value(env, (*iter)->callback[0], &iterHandler),
                GET_REFERENCE_VALUE, JS_CALLBACK_EVENT_FAILED);
            bool isEquals = false;
            CHKRR(napi_strict_equals(env, handler, iterHandler, &isEquals), STRICT_EQUALS, JS_CALLBACK_EVENT_FAILED);
            if (isEquals) {
                CHKRR(napi_delete_reference(env, (*iter)->callback[0]), DELETE_REFERENCE, JS_CALLBACK_EVENT_FAILED);
                if ((*iter)->callback[0] != nullptr) {
                    MMI_HILOGW("current (*iter)->callback[0] is not nullptr");
                    (*iter)->callback[0] = nullptr;
                }
                KeyEventMonitorInfo *monitorInfo = *iter;
                info.erase(iter++);
                if (info.empty()) {
                    subscribeId = monitorInfo->subscribeId;
                }
                delete monitorInfo;
                monitorInfo = nullptr;
                MMI_HILOGD("Callback has deleted, size:%{public}zu", info.size());
                return JS_CALLBACK_EVENT_SUCCESS;
            }
            ++iter;
            continue;
        }
        CHKRR(napi_delete_reference(env, (*iter)->callback[0]), DELETE_REFERENCE, JS_CALLBACK_EVENT_FAILED);
        if ((*iter)->callback[0] != nullptr) {
            MMI_HILOGW("(*iter)->callback[0] is not nullptr");
            (*iter)->callback[0] = nullptr;
        }
        KeyEventMonitorInfo *monitorInfo = *iter;
        info.erase(iter++);
        if (info.empty()) {
            subscribeId = monitorInfo->subscribeId;
        }
        delete monitorInfo;
        monitorInfo = nullptr;
        MMI_HILOGD("Callback has deleted, size:%{public}zu", info.size());
    }
    MMI_HILOGD("Callback size:%{public}zu", info.size());
    return JS_CALLBACK_EVENT_SUCCESS;
}

int32_t AddEventCallback(const napi_env &env, Callbacks &callbacks, KeyEventMonitorInfo *event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    if (callbacks.find(event->eventType) == callbacks.end()) {
        MMI_HILOGD("No callback in %{public}s", event->eventType.c_str());
        callbacks[event->eventType] = {};
    }
    napi_value handler1 = nullptr;
    napi_status status = napi_get_reference_value(env, event->callback[0], &handler1);
    if (status != napi_ok) {
        MMI_HILOGE("Handler1 get reference value failed");
        return JS_CALLBACK_EVENT_FAILED;
    }
    auto it = callbacks.find(event->eventType);
    for (const auto &iter : it->second) {
        napi_value handler2 = nullptr;
        status = napi_get_reference_value(env, (*iter).callback[0], &handler2);
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

int32_t DelEventCallback(const napi_env &env, Callbacks &callbacks, KeyEventMonitorInfo *event, int32_t &subscribeId)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    if (callbacks.count(event->eventType) <= 0) {
        MMI_HILOGE("Callback doesn't exists");
        return JS_CALLBACK_EVENT_FAILED;
    }
    auto &info = callbacks[event->eventType];
    MMI_HILOGD("EventType:%{public}s, keyEventMonitorInfos:%{public}zu", event->eventType.c_str(), info.size());
    napi_value eventHandler = nullptr;
    if (event->callback[0] != nullptr) {
        CHKRR(napi_get_reference_value(env, event->callback[0], &eventHandler), GET_REFERENCE_VALUE,
            JS_CALLBACK_EVENT_FAILED);
    }
    return DelEventCallbackRef(env, info, eventHandler, subscribeId);
}

static void AsyncWorkFn(const napi_env &env, KeyEventMonitorInfo *event, napi_value &result)
{
    CHKPV(event);
    CHKPV(event->keyOption);
    MMI_HILOGD("Status > 0 enter");
    CHKRV(napi_create_object(env, &result), CREATE_OBJECT);
    napi_value arr;
    CHKRV(napi_create_array(env, &arr), CREATE_ARRAY);
    std::set<int32_t> preKeys = event->keyOption->GetPreKeys();
    int32_t i = 0;
    napi_value value;
    for (const auto &preKey : preKeys) {
        CHKRV(napi_create_int32(env, preKey, &value), CREATE_INT32);
        CHKRV(napi_set_element(env, arr, i, value), SET_ELEMENT);
        ++i;
    }
    std::string preKeysStr = "preKeys";
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, preKeysStr.c_str(), arr));
    MMI::SetNamedProperty(env, result, "finalKey", event->keyOption->GetFinalKey());
    MMI::SetNamedProperty(env, result, "isFinalKeyDown", event->keyOption->IsFinalKeyDown());
    MMI::SetNamedProperty(env, result, "finalKeyDownDuration", event->keyOption->GetFinalKeyDownDuration());
}

struct KeyEventMonitorInfoWorker {
    napi_env env { nullptr };
    KeyEventMonitorInfo *reportEvent { nullptr };
};

void UvQueueWorkAsyncCallback(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        MMI_HILOGE("Check data is nullptr");
        delete work;
        work = nullptr;
        return;
    }
    (void)status;
    KeyEventMonitorInfoWorker *dataWorker = static_cast<KeyEventMonitorInfoWorker *>(work->data);
    delete work;
    work = nullptr;
    KeyEventMonitorInfo *event = dataWorker->reportEvent;
    napi_env env = dataWorker->env;
    delete dataWorker;
    dataWorker = nullptr;
    CHKPV(event);
    event->delCallback = nullptr;
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    if (scope == nullptr) {
        MMI_HILOGE("Scope is nullptr");
        return;
    }
    napi_value callback = nullptr;
    MMI_HILOGD("deliver uv work from %{public}d", GetPid());
    if (event->callback[0] == nullptr) {
        MMI_HILOGE("event->callback[0] is nullptr");
        napi_close_handle_scope(env, scope);
        return;
    }
    CHKRV_SCOPE(env, napi_get_reference_value(env, event->callback[0], &callback), GET_REFERENCE_VALUE, scope);
    napi_value result = nullptr;
    AsyncWorkFn(env, event, result);
    napi_value callResult = nullptr;
    CHKRV_SCOPE(env, napi_call_function(env, nullptr, callback, 1, &result, &callResult), CALL_FUNCTION, scope);
    napi_close_handle_scope(env, scope);
}

void EmitAsyncCallbackWork(KeyEventMonitorInfo *reportEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(reportEvent);
    uv_loop_s *loop = nullptr;
    CHKRV(napi_get_uv_event_loop(reportEvent->env, &loop), GET_UV_EVENT_LOOP);
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    KeyEventMonitorInfoWorker *dataWorker = new (std::nothrow) KeyEventMonitorInfoWorker();
    if (dataWorker == nullptr) {
        MMI_HILOGE("dataWorker is nullptr");
        delete work;
        return;
    }
    reportEvent->delCallback = [dataWorker]() {dataWorker->reportEvent = nullptr;};
    dataWorker->env = reportEvent->env;
    dataWorker->reportEvent = reportEvent;
    work->data = static_cast<void *>(dataWorker);

    int32_t ret =
        uv_queue_work_with_qos(loop, work, [](uv_work_t *work) {}, UvQueueWorkAsyncCallback, uv_qos_user_initiated);
    if (ret != 0) {
        delete dataWorker;
        delete work;
    }
}
} // namespace MMI
} // namespace OHOS