/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "js_register_util.h"

#include <cinttypes>

#include <uv.h>

#include "error_multimodal.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JSRegisterUtil" };
} // namespace

void SetNamedProperty(const napi_env &env, napi_value &object, const std::string &name, int32_t value)
{
    MMI_HILOGD("%{public}s=%{public}d", name.c_str(), value);
    napi_status status;
    napi_value napiValue;
    status = napi_create_int32(env, value, &napiValue);
    if (status != napi_ok) {
        MMI_HILOGE("%{public}s=%{public}d failed", name.c_str(), value);
        napi_throw_error(env, nullptr, "napi create int32 failed");
        return;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), napiValue));
}

void SetNamedProperty(const napi_env &env, napi_value &object, const std::string &name, std::string value)
{
    MMI_HILOGD("%{public}s=%{public}s", name.c_str(), value.c_str());
    napi_status status;
    napi_value napiValue;
    status = napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &napiValue);
    if (status != napi_ok) {
        MMI_HILOGE("%{public}s=%{public}s failed", name.c_str(), value.c_str());
        napi_throw_error(env, nullptr, "napi create string failed");
        return;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), napiValue));
}

bool GetNamedPropertyBool(const napi_env &env, const napi_value &object, const std::string &name)
{
    bool value = false;
    napi_value napiValue = {};
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    napi_valuetype tmpType = napi_undefined;
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_HILOGE("Call napi_typeof fail");
        napi_throw_error(env, nullptr, "call napi_typeof failed");
        return false;
    }
    if (tmpType != napi_boolean) {
        MMI_HILOGE("The value is not bool");
        return value;
    }

    napi_get_value_bool(env, napiValue, &value);
    MMI_HILOGD("%{public}s=%{public}d", name.c_str(), value);
    return value;
}

int32_t GetNamedPropertyInt32(const napi_env &env, const napi_value &object, const std::string &name)
{
    int32_t value = 0;
    napi_value napiValue = {};
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    napi_valuetype tmpType = napi_undefined;
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_HILOGE("Call napi_typeof failed");
        napi_throw_error(env, nullptr, "call napi_typeof failed");
        return value;
    }
    if (tmpType != napi_number) {
        MMI_HILOGE("The value is not number");
        napi_throw_error(env, nullptr, "value is not number");
        return value;
    }
    napi_get_value_int32(env, napiValue, &value);
    MMI_HILOGD("%{public}s=%{public}d", name.c_str(), value);
    return value;
}

bool GetPreKeys(const napi_env &env, const napi_value &value, std::set<int32_t> &params)
{
    CALL_DEBUG_ENTER;
    uint32_t arrayLength = 0;
    if (napi_get_array_length(env, value, &arrayLength) != napi_ok) {
        MMI_HILOGE("Get array length failed");
        napi_throw_error(env, nullptr, "Get array length failed");
        return false;
    }
    for (uint32_t i = 0; i < arrayLength; i++) {
        napi_value napiElement;
        if (napi_get_element(env, value, i, &napiElement) != napi_ok) {
            MMI_HILOGE("Get element failed");
            napi_throw_error(env, nullptr, "Get element failed");
            return false;
        }

        napi_valuetype valuetype;
        if (napi_typeof(env, napiElement, &valuetype) != napi_ok) {
            MMI_HILOGE("Call typeof napiElement failed");
            napi_throw_error(env, nullptr, "Call typeof napiElement failed");
            return false;
        }
        if (valuetype != napi_number) {
            MMI_HILOGE("Wrong argument type, Numbers expected");
            napi_throw_error(env, nullptr, "Wrong argument type, Numbers expected");
            return false;
        }
        int32_t value = 0;
        if (napi_get_value_int32(env, napiElement, &value) != napi_ok) {
            MMI_HILOGE("NapiElement get int32 value failed");
            napi_throw_error(env, nullptr, "NapiElement get int32 value failed");
            return false;
        }
        if (value < 0) {
            MMI_HILOGE("preKey:%{public}d is less 0, can not process", value);
            napi_throw_error(env, nullptr, "preKey is less 0, can not process");
            return false;
        }
        MMI_HILOGD("Get int array number:%{public}d", value);
        if (!params.insert(value).second) {
            MMI_HILOGE("Params insert value failed");
            napi_throw_error(env, nullptr, "params insert value failed");
            return false;
        }
    }
    return true;
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
        napi_throw_error(env, nullptr, "Handler1 get reference value failed");
        return JS_CALLBACK_EVENT_FAILED;
    }
    auto it = callbacks.find(event->eventType);
    for (const auto &iter : it->second) {
        napi_value handler2 = nullptr;
        status = napi_get_reference_value(env, (*iter).callback[0], &handler2);
        if (status != napi_ok) {
            MMI_HILOGE("Handler2 get reference value failed");
            napi_throw_error(env, nullptr, "Handler2 get reference value failed");
            return JS_CALLBACK_EVENT_FAILED;
        }
        bool isEqual = false;
        status = napi_strict_equals(env, handler1, handler2, &isEqual);
        if (status != napi_ok) {
            MMI_HILOGE("Compare two handler failed");
            napi_throw_error(env, nullptr, "Compare two handler failed");
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

int32_t DelEventCallback(const napi_env &env, Callbacks &callbacks,
    KeyEventMonitorInfo *event, int32_t &subscribeId)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    if (callbacks.count(event->eventType) <= 0) {
        MMI_HILOGE("Callback doesn't exists");
        return JS_CALLBACK_EVENT_FAILED;
    }
    auto &info = callbacks[event->eventType];
    MMI_HILOGD("EventType:%{public}s, keyEventMonitorInfos:%{public}zu",
        event->eventType.c_str(), info.size());
    napi_value handler1 = nullptr;
    napi_status status;
    if (event->callback[0] != nullptr) {
        status = napi_get_reference_value(env, event->callback[0], &handler1);
        if (status != napi_ok) {
            MMI_HILOGE("Handler1 get reference value failed");
            napi_throw_error(env, nullptr, "Handler1 get reference value failed");
            return JS_CALLBACK_EVENT_FAILED;
        }
    }
    for (auto iter = info.begin(); iter != info.end();) {
        if (*iter == nullptr) {
            info.erase(iter++);
            continue;
        }
        if (handler1 != nullptr) {
            napi_value handler2 = nullptr;
            status = napi_get_reference_value(env, (*iter)->callback[0], &handler2);
            if (status != napi_ok) {
                MMI_HILOGE("Handler2 get reference value failed");
                napi_throw_error(env, nullptr, "Handler2 get reference value failed");
                return JS_CALLBACK_EVENT_FAILED;
            }
            bool isEquals = false;
            status = napi_strict_equals(env, handler1, handler2, &isEquals);
            if (status != napi_ok) {
                MMI_HILOGE("Compare two handler failed");
                napi_throw_error(env, nullptr, "Compare two handler failed");
                return JS_CALLBACK_EVENT_FAILED;
            }
            if (isEquals) {
                status = napi_delete_reference(env, (*iter)->callback[0]);
                if (status != napi_ok) {
                    MMI_HILOGE("Delete reference failed");
                    napi_throw_error(env, nullptr, "Delete reference failed");
                    return JS_CALLBACK_EVENT_FAILED;
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
        status = napi_delete_reference(env, (*iter)->callback[0]);
        if (status != napi_ok) {
            MMI_HILOGE("Delete reference failed");
            napi_throw_error(env, nullptr, "Delete reference failed");
            return JS_CALLBACK_EVENT_FAILED;
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

static void AsyncWorkFn(const napi_env &env, KeyEventMonitorInfo *event, napi_value &result)
{
    CHKPV(event);
    CHKPV(event->keyOption);
    MMI_HILOGD("Status > 0 enter");
    napi_status status = napi_create_object(env, &result);
    if (status != napi_ok) {
        MMI_HILOGE("Create object failed");
        napi_throw_error(env, nullptr, "create object failed");
        return;
    }
    napi_value arr;
    status = napi_create_array(env, &arr);
    if (status != napi_ok) {
        MMI_HILOGE("Create array failed");
        napi_throw_error(env, nullptr, "create array failed");
        return;
    }
    std::set<int32_t> preKeys = event->keyOption->GetPreKeys();
    int32_t i = 0;
    napi_value value;
    for (const auto &preKey : preKeys) {
        status = napi_create_int32(env, preKey, &value);
        if (status != napi_ok) {
            MMI_HILOGE("Create int32 failed");
            napi_throw_error(env, nullptr, "create int32 failed");
            return;
        }
        status = napi_set_element(env, arr, i, value);
        if (status != napi_ok) {
            MMI_HILOGE("Set element failed");
            napi_throw_error(env, nullptr, "set element failed");
            return;
        }
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
        MMI_HILOGE("Check data is null");
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
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    if (scope == nullptr) {
        MMI_HILOGE("Scope is nullptr");
        return;
    }
    napi_value callback = nullptr;
    if (napi_get_reference_value(env, event->callback[0], &callback) != napi_ok) {
        MMI_HILOGE("Event get reference value failed");
        napi_close_handle_scope(env, scope);
        napi_throw_error(env, nullptr, "Event get reference value failed");
        return;
    }

    napi_value result = nullptr;
    AsyncWorkFn(env, event, result);
    napi_value callResult = nullptr;
    napi_status ret = napi_call_function(env, nullptr, callback, 1, &result, &callResult);
    if (ret != napi_ok) {
        napi_close_handle_scope(env, scope);
        MMI_HILOGE("Call function failed, ret:%{public}d", static_cast<int32_t>(ret));
        napi_throw_error(env, nullptr, "Call function failed");
        return;
    }
    napi_close_handle_scope(env, scope);
}

void EmitAsyncCallbackWork(KeyEventMonitorInfo *reportEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(reportEvent);
    napi_status status;
    uv_loop_s *loop = nullptr;
    status = napi_get_uv_event_loop(reportEvent->env, &loop);
    if (status != napi_ok) {
        MMI_HILOGE("Call napi_get_uv_event_loop failed");
        napi_throw_error(reportEvent->env, nullptr, "Call napi_get_uv_event_loop failed");
        return;
    }

    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    KeyEventMonitorInfoWorker *dataWorker = new (std::nothrow) KeyEventMonitorInfoWorker();
    CHKPV(dataWorker);

    dataWorker->env = reportEvent->env;
    dataWorker->reportEvent = reportEvent;
    work->data = static_cast<void *>(dataWorker);

    int32_t ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, UvQueueWorkAsyncCallback);
    if (ret != 0) {
        delete dataWorker;
        delete work;
    }
}
} // namespace MMI
} // namespace OHOS
