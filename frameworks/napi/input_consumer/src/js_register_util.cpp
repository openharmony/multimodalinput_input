/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <inttypes.h>

namespace OHOS {
namespace MMI {
namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JSRegisterUtil" };
}

void SetNamedProperty(const napi_env &env, napi_value &object, const std::string &name, int32_t value)
{
    MMI_LOGD("%{public}s=%{public}d", name.c_str(), value);
    napi_status status;
    napi_value napiValue;
    status = napi_create_int32(env, value, &napiValue);
    if (status != napi_ok) {
        MMI_LOGE("%{public}s=%{public}d failed.", name.c_str(), value);
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
        MMI_LOGE("%{public}s=%{public}s failed.", name.c_str(), value.c_str());
        return;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), napiValue));
}

bool GetNamedPropertyBool(const napi_env &env, const napi_value &object, const std::string &name)
{
    bool value = false;
    napi_value napiValue = {};
    napi_valuetype tmpType = napi_undefined;
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_LOGE("call napi_typeof fail.");
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
    napi_valuetype tmpType = napi_undefined;
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        napi_throw_error(env, nullptr, "call napi_typeof fail.");
        return value;
    }
    if (tmpType != napi_number) {
        MMI_LOGE("value is not number");
        return value;
    }
    napi_get_value_int32(env, napiValue, &value);
    MMI_LOGD("%{public}s=%{public}d", name.c_str(), value);
    return value;
}

std::vector<int32_t> GetIntArray(const napi_env &env, const napi_value &value)
{
    MMI_LOGD("enter");
    uint32_t arrayLength = 0;
    if (napi_get_array_length(env, value, &arrayLength) != napi_ok) {
        MMI_LOGE("Get array length failed");
        return {};
    }
    std::vector<int32_t> paramArrays;
    for (size_t i = 0; i < arrayLength; i++) {
        napi_value napiElement;
        if (napi_get_element(env, value, i, &napiElement) != napi_ok) {
            MMI_LOGE("Get element failed");
            return {};
        }

        napi_valuetype valuetype;
        if (napi_typeof(env, napiElement, &valuetype) != napi_ok) {
            MMI_LOGE("Call typeof napiElement failed");
            return {};
        }
        if (valuetype != napi_number) {
            MMI_LOGE("Wrong argument type, Numbers expected");
            return {};
        }
        int32_t value = 0;
        if (napi_get_value_int32(env, napiElement, &value) != napi_ok) {
            MMI_LOGE("NapiElement get int32 value failed");
            return {};
        }
        MMI_LOGD("Get int array number:%{public}d", value);
        paramArrays.push_back(value);
    }
    MMI_LOGD("leave");
    return paramArrays;
}

int32_t AddEventCallback(const napi_env &env, OHOS::MMI::Callbacks &callbacks,
    OHOS::MMI::KeyEventMonitorInfo *event, int32_t &preSubscribeId)
{
    MMI_LOGD("enter");
    if (callbacks.find(event->eventType) == callbacks.end()) {
        MMI_LOGD("No callback in %{public}s", event->eventType.c_str());
        callbacks[event->eventType] = {};
    }
    auto it = callbacks[event->eventType];
    napi_value handler1 = nullptr;
    napi_status status = napi_get_reference_value(env, event->callback[0], &handler1);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Handler1 get reference value failed");
        return JS_CALLBACK_EVENT_FAILED;
    }
    for (const auto &iter : it) {
        napi_value handler2 = nullptr;
        status = napi_get_reference_value(env, (*iter).callback[0], &handler2);
        if (status != napi_ok) {
            napi_throw_error(env, nullptr, "Handler2 get reference value failed");
            return JS_CALLBACK_EVENT_FAILED;
        }
        bool isEqual = false;
        status = napi_strict_equals(env, handler1, handler2, &isEqual);
        if (status != napi_ok) {
            napi_throw_error(env, nullptr, "Compare two handler failed");
            return JS_CALLBACK_EVENT_FAILED;
        }
        if (isEqual) {
            napi_throw_error(env, nullptr, "Callback already exists in %{public}s");
            return JS_CALLBACK_EVENT_FAILED;
        }
    }
    if (!it.empty()) {
        CHKPR(it.front(), ERROR_NULL_POINTER);
        preSubscribeId = it.front()->subscribeId;
    }
    it.push_back(event);
    return JS_CALLBACK_EVENT_SUCCESS;
}

int32_t DelEventCallback(const napi_env &env, OHOS::MMI::Callbacks &callbacks,
    OHOS::MMI::KeyEventMonitorInfo *event, int32_t &subscribeId)
{
    MMI_LOGD("enter");
    auto iter = callbacks.find(event->eventType);
    if (iter == callbacks.end()) {
        MMI_LOGD("No callback in %{public}s", event->eventType.c_str());
        return JS_CALLBACK_EVENT_FAILED;
    }
    MMI_LOGD("EventType:%{public}s, keyEventMonitorInfos:%{public}d", event->eventType.c_str(),
        static_cast<int32_t>(iter->second.size()));
    auto it = iter->second.begin();
    while (it != iter->second.end()) {
        bool isEquals = false;
        napi_value handlerTemp = nullptr;
        napi_get_reference_value(env, (*it)->callback[0], &handlerTemp);
        napi_value handlerParam = nullptr;
        napi_get_reference_value(env, event->callback[0], &handlerParam);
        napi_strict_equals(env, handlerTemp, handlerParam, &isEquals);
        if (isEquals) {
            napi_delete_reference(env, (*it)->callback[0]);
            KeyEventMonitorInfo *monitorInfo = *it;
            iter->second.erase(it);
            if (iter->second.empty()) {
                subscribeId = monitorInfo->subscribeId;
            }
            delete monitorInfo;
            monitorInfo = nullptr;
            MMI_LOGD("Callback already exists, size:%{public}d",
                static_cast<int32_t>(iter->second.size()));
            return JS_CALLBACK_EVENT_SUCCESS;
        }
        it++;
    }
    MMI_LOGD("callback size:%{public}d", static_cast<int32_t>(iter->second.size()));
    return JS_CALLBACK_EVENT_NOT_EXIST;
}

void EmitAsyncCallbackWork(OHOS::MMI::KeyEventMonitorInfo *reportEvent)
{
    MMI_LOGD("%{public}s begin", __func__);
    CHKP(reportEvent);
    napi_value resourceName;
    napi_status status = napi_create_string_utf8(reportEvent->env, "AsyncCallback", NAPI_AUTO_LENGTH, &resourceName);
    if (status != napi_ok) {
        MMI_LOGE("Create string about resourceName failed");
        return;
    }
    napi_create_async_work(
        reportEvent->env, nullptr, resourceName, [](napi_env env, void *data) {},
        [](napi_env env, napi_status status, void *data) {
            MMI_LOGD("Napi async work enter");
            OHOS::MMI::KeyEventMonitorInfo *event = (OHOS::MMI::KeyEventMonitorInfo *)data;
            napi_value callback = nullptr;
            if (napi_get_reference_value(env, event->callback[0], &callback) != napi_ok) {
                MMI_LOGE("Event get reference value failed");
                return;
            }
            napi_value callResult = nullptr;
            napi_value result[2] = { 0 };
            if (event->status < 0) {
                MMI_LOGD("Status < 0 enter");
                napi_value code = nullptr;
                napi_value message = nullptr;
                napi_create_string_utf8(env, "-1", NAPI_AUTO_LENGTH, &code);
                napi_create_string_utf8(env, "failed", NAPI_AUTO_LENGTH, &message);
                napi_create_error(env, code, message, &result[0]);
                napi_get_undefined(env, &result[1]);
            } else if (event->status == 0) {
                MMI_LOGD("Status = 0 enter");
                napi_get_undefined(env, &result[0]);
                napi_get_undefined(env, &result[1]);
            } else {
                MMI_LOGD("Status > 0 enter");
                if (napi_create_object(env, &result[1]) != napi_ok) {
                    MMI_LOGE("Result1 create object failed");
                    return;
                }
                napi_value arr;
                napi_value value;
                napi_create_array(env, &arr);
                std::vector<int32_t> preKeys = event->keyOption->GetPreKeys();
                for (size_t i = 0; i < preKeys.size(); i++) {
                    napi_create_int32(env, preKeys[i], &value);
                    napi_set_element(env, arr, i, value);
                }

                std::string preKeysStr = "preKeys";
                NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result[1], preKeysStr.c_str(), arr));
                MMI::SetNamedProperty(env, result[1], "finalKey", event->keyOption->GetFinalKey());
                MMI::SetNamedProperty(env, result[1], "isFinalKeyDown", event->keyOption->IsFinalKeyDown());
                MMI::SetNamedProperty(env, result[1], "finalKeyDownDuration",
                    event->keyOption->GetFinalKeyDownDuration());
                if (napi_get_undefined(env, &result[0]) != napi_ok) {
                    MMI_LOGE("Result0 get undefined failed");
                    return;
                }
            }
            auto callFunResult = napi_call_function(env, nullptr, callback, 2, result, &callResult);
            MMI_LOGD("CallFunResult:%{public}d", static_cast<int32_t>(callFunResult));
            if (callFunResult != napi_ok) {
                MMI_LOGE("Call function fail, callFunResult: %{public}d", callFunResult);
                return;
            }
            if (event->status <= 0) {
                napi_delete_reference(env, event->callback[0]);
                napi_delete_async_work(env, event->asyncWork);
                delete event;
                event = nullptr;
            }
            MMI_LOGD("Napi async work left");
        },
        reportEvent, &reportEvent->asyncWork);
    napi_queue_async_work(reportEvent->env, reportEvent->asyncWork);
    MMI_LOGD("EmitAsyncCallbackWork left");
}
}
}
