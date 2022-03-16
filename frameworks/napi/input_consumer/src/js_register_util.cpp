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

#include "error_multimodal.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JSRegisterUtil" };
} // namespace

void SetNamedProperty(const napi_env &env, napi_value &object, const std::string &name, int32_t value)
{
    MMI_LOGD("%{public}s=%{public}d", name.c_str(), value);
    napi_status status;
    napi_value napiValue;
    status = napi_create_int32(env, value, &napiValue);
    if (status != napi_ok) {
        MMI_LOGE("%{public}s=%{public}d failed", name.c_str(), value);
        napi_throw_error(env, nullptr, "napi create int32 failed");
        return;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), napiValue));
}

void SetNamedProperty(const napi_env &env, napi_value &object, const std::string &name, std::string value)
{
    MMI_LOGD("%{public}s=%{public}s", name.c_str(), value.c_str());
    napi_status status;
    napi_value napiValue;
    status = napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &napiValue);
    if (status != napi_ok) {
        MMI_LOGE("%{public}s=%{public}s failed", name.c_str(), value.c_str());
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
        MMI_LOGE("call napi_typeof fail");
        napi_throw_error(env, nullptr, "call napi_typeof failed");
        return false;
    }
    if (tmpType != napi_boolean) {
        MMI_LOGE("value is not bool");
        return value;
    }

    napi_get_value_bool(env, napiValue, &value);
    MMI_LOGD("%{public}s=%{public}d", name.c_str(), value);
    return value;
}

int32_t GetNamedPropertyInt32(const napi_env &env, const napi_value &object, const std::string &name)
{
    int32_t value = 0;
    napi_value napiValue = {};
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    napi_valuetype tmpType = napi_undefined;
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_LOGE("call napi_typeof fail");
        napi_throw_error(env, nullptr, "call napi_typeof failed");
        return value;
    }
    if (tmpType != napi_number) {
        MMI_LOGE("value is not number");
        napi_throw_error(env, nullptr, "value is not number");
        return value;
    }
    napi_get_value_int32(env, napiValue, &value);
    MMI_LOGD("%{public}s=%{public}d", name.c_str(), value);
    return value;
}

bool GetPreKeys(const napi_env &env, const napi_value &value, std::set<int32_t> &params)
{
    CALL_LOG_ENTER;
    uint32_t arrayLength = 0;
    if (napi_get_array_length(env, value, &arrayLength) != napi_ok) {
        MMI_LOGE("Get array length failed");
        napi_throw_error(env, nullptr, "Get array length failed");
        return false;
    }
    for (uint32_t i = 0; i < arrayLength; i++) {
        napi_value napiElement;
        if (napi_get_element(env, value, i, &napiElement) != napi_ok) {
            MMI_LOGE("Get element failed");
            napi_throw_error(env, nullptr, "Get element failed");
            return false;
        }

        napi_valuetype valuetype;
        if (napi_typeof(env, napiElement, &valuetype) != napi_ok) {
            MMI_LOGE("Call typeof napiElement failed");
            napi_throw_error(env, nullptr, "Call typeof napiElement failed");
            return false;
        }
        if (valuetype != napi_number) {
            MMI_LOGE("Wrong argument type, Numbers expected");
            napi_throw_error(env, nullptr, "Wrong argument type, Numbers expected");
            return false;
        }
        int32_t value = 0;
        if (napi_get_value_int32(env, napiElement, &value) != napi_ok) {
            MMI_LOGE("NapiElement get int32 value failed");
            napi_throw_error(env, nullptr, "NapiElement get int32 value failed");
            return false;
        }
        if (value < 0) {
            MMI_LOGE("preKey:%{public}d is less 0, can not process", value);
            napi_throw_error(env, nullptr, "preKey is less 0, can not process");
            return false;
        }
        MMI_LOGD("Get int array number:%{public}d", value);
        if (!params.insert(value).second) {
            MMI_LOGE("params insert value failed");
            napi_throw_error(env, nullptr, "params insert value failed");
            return false;
        }
    }
    return true;
}

int32_t GetPreSubscribeId(Callbacks &callbacks, KeyEventMonitorInfo *event)
{
    auto it = callbacks.find(event->eventType);
    if (it == callbacks.end() || it->second.empty()) {
        MMI_LOGE("callbacks is empty");
        return JS_CALLBACK_EVENT_FAILED;
    }
    CHKPR(it->second.front(), ERROR_NULL_POINTER);
    return it->second.front()->subscribeId;
}

int32_t AddEventCallback(const napi_env &env, Callbacks &callbacks, KeyEventMonitorInfo *event)
{
    CALL_LOG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    if (callbacks.find(event->eventType) == callbacks.end()) {
        MMI_LOGD("No callback in %{public}s", event->eventType.c_str());
        callbacks[event->eventType] = {};
    }
    napi_value handler1 = nullptr;
    napi_status status = napi_get_reference_value(env, event->callback[0], &handler1);
    if (status != napi_ok) {
        MMI_LOGE("Handler1 get reference value failed");
        napi_throw_error(env, nullptr, "Handler1 get reference value failed");
        return JS_CALLBACK_EVENT_FAILED;
    }
    auto it = callbacks.find(event->eventType);
    for (const auto &iter : it->second) {
        napi_value handler2 = nullptr;
        status = napi_get_reference_value(env, (*iter).callback[0], &handler2);
        if (status != napi_ok) {
            MMI_LOGE("Handler2 get reference value failed");
            napi_throw_error(env, nullptr, "Handler2 get reference value failed");
            return JS_CALLBACK_EVENT_FAILED;
        }
        bool isEqual = false;
        status = napi_strict_equals(env, handler1, handler2, &isEqual);
        if (status != napi_ok) {
            MMI_LOGE("Compare two handler failed");
            napi_throw_error(env, nullptr, "Compare two handler failed");
            return JS_CALLBACK_EVENT_FAILED;
        }
        if (isEqual) {
            MMI_LOGE("Callback already exist");
            return JS_CALLBACK_EVENT_FAILED;
        }
    }
    it->second.push_back(event);
    return JS_CALLBACK_EVENT_SUCCESS;
}

int32_t DelEventCallback(const napi_env &env, Callbacks &callbacks,
    KeyEventMonitorInfo *event, int32_t &subscribeId)
{
    CALL_LOG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    if (callbacks.count(event->eventType) <= 0) {
        MMI_LOGE("Callback doesn't exists");
        return JS_CALLBACK_EVENT_FAILED;
    }
    auto &info = callbacks[event->eventType];
    MMI_LOGD("EventType: %{public}s, keyEventMonitorInfos: %{public}zu",
        event->eventType.c_str(), info.size());
    napi_value handler1 = nullptr;
    napi_status status;
    if (event->callback[0] != nullptr) {
        status = napi_get_reference_value(env, event->callback[0], &handler1);
        if (status != napi_ok) {
            MMI_LOGE("Handler1 get reference value failed");
            napi_throw_error(env, nullptr, "Handler1 get reference value failed");
            return JS_CALLBACK_EVENT_FAILED;
        }
    }
    for (auto iter = info.begin(); iter != info.end();) {
        if (handler1 !=nullptr) {
            napi_value handler2 = nullptr;
	        CHKPC(*iter);
            status = napi_get_reference_value(env, (*iter)->callback[0], &handler2);
            if (status != napi_ok) {
                MMI_LOGE("Handler2 get reference value failed");
                napi_throw_error(env, nullptr, "Handler2 get reference value failed");
                return JS_CALLBACK_EVENT_FAILED;
            }
            bool isEquals = false;
            status = napi_strict_equals(env, handler1, handler2, &isEquals);
            if (status != napi_ok) {
                MMI_LOGE("Compare two handler failed");
                napi_throw_error(env, nullptr, "Compare two handler failed");
                return JS_CALLBACK_EVENT_FAILED;
            }
            if (isEquals) {
                status = napi_delete_reference(env, (*iter)->callback[0]);
                if (status != napi_ok) {
                    MMI_LOGE("Delete reference failed");
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
                MMI_LOGD("Callback has deleted, size: %{public}zu", info.size());
                return JS_CALLBACK_EVENT_SUCCESS;
            }
            ++iter;
            continue;
        }
        status = napi_delete_reference(env, (*iter)->callback[0]);
        if (status != napi_ok) {
            MMI_LOGE("Delete reference failed");
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
        MMI_LOGD("Callback has deleted, size: %{public}zu", info.size());
    }
    MMI_LOGD("Callback size: %{public}zu", info.size());
    return JS_CALLBACK_EVENT_SUCCESS;
}

static void AsyncWorkFn(const napi_env &env, KeyEventMonitorInfo *event, napi_value &result)
{
    CHKPV(event);
    MMI_LOGD("Status > 0 enter");
    napi_status status = napi_create_object(env, &result);
    if (status != napi_ok) {
        MMI_LOGE("create object failed");
        napi_throw_error(env, nullptr, "create object failed");
        return;
    }
    napi_value arr;
    status = napi_create_array(env, &arr);
    if (status != napi_ok) {
        MMI_LOGE("create array failed");
        napi_throw_error(env, nullptr, "create array failed");
        return;
    }
    std::set<int32_t> preKeys = event->keyOption->GetPreKeys();
    int32_t i = 0;
    napi_value value;
    for (const auto &preKey : preKeys) {
        status = napi_create_int32(env, preKey, &value);
        if (status != napi_ok) {
            MMI_LOGE("create int32 failed");
            napi_throw_error(env, nullptr, "create int32 failed");
            return;
        }
        status = napi_set_element(env, arr, i, value);
        if (status != napi_ok) {
            MMI_LOGE("set element failed");
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

void EmitAsyncCallbackWork(KeyEventMonitorInfo *reportEvent)
{
    CALL_LOG_ENTER;
    CHKPV(reportEvent);
    napi_value resourceName;
    napi_status status = napi_create_string_utf8(reportEvent->env, "AsyncCallback", NAPI_AUTO_LENGTH, &resourceName);
    if (status != napi_ok) {
        MMI_LOGE("Create string about resourceName failed");
        napi_throw_error(reportEvent->env, nullptr, "Create string about resourceName failed");
        return;
    }
    napi_create_async_work(
        reportEvent->env, nullptr, resourceName, [](napi_env env, void *data) {},
        [](napi_env env, napi_status status, void *data) {
            MMI_LOGD("Napi async work enter");
            KeyEventMonitorInfo *event = (KeyEventMonitorInfo *)data;
            napi_value callback = nullptr;
            if (napi_get_reference_value(env, event->callback[0], &callback) != napi_ok) {
                MMI_LOGE("Event get reference value failed");
                napi_throw_error(env, nullptr, "Event get reference value failed");
                return;
            }
            napi_value result = nullptr;
            AsyncWorkFn(env, event, result);
            napi_value callResult = nullptr;
            status = napi_call_function(env, nullptr, callback, 1, &result, &callResult);
            MMI_LOGD("CallFunResult:%{public}d", static_cast<int32_t>(status));
            if (status != napi_ok) {
                MMI_LOGE("Call function failed, status:%{public}d", status);
                napi_throw_error(env, nullptr, "Call function failed");
                return;
            }
            MMI_LOGD("Napi async work left");
        }, reportEvent, &reportEvent->asyncWork);
    napi_queue_async_work(reportEvent->env, reportEvent->asyncWork);
    MMI_LOGD("EmitAsyncCallbackWork left");
}
} // namespace MMI
} // namespace OHOS
