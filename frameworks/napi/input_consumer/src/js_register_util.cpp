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
void SetNamedProperty(const napi_env &env, napi_value &object, const std::string &name, int32_t value)
{
    HILOG_DEBUG("SetNamedProperty: %{public}s=%{public}d", name.c_str(), value);
    napi_status status;
    napi_value napiValue;
    status = napi_create_int32(env, value, &napiValue);
    if (status != napi_ok) {
        HILOG_ERROR("SetNamedProperty: %{public}s=%{public}d failed.", name.c_str(), value);
        return;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), napiValue));
}

void SetNamedProperty(const napi_env &env, napi_value &object, const std::string &name, std::string value)
{
    HILOG_DEBUG("SetNamedProperty: %{public}s=%{public}s", name.c_str(), value.c_str());
    napi_status status;
    napi_value napiValue;
    status = napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &napiValue);
    if (status != napi_ok) {
        HILOG_ERROR("SetNamedProperty: %{public}s=%{public}s failed.", name.c_str(), value.c_str());
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
        HILOG_ERROR("GetNamedPropertyBool: call napi_typeof fail.");
        return false;
    }
    if (tmpType != napi_boolean) {
        HILOG_ERROR("GetNamedPropertyBool: value is not bool");
        return value;
    }

    napi_get_value_bool(env, napiValue, &value);
    HILOG_DEBUG("GetNamedPropertyBool: %{public}s=%{public}d", name.c_str(), value);
    return value;
}

int32_t GetNamedPropertyInt32(const napi_env &env, const napi_value &object, const std::string &name)
{
    int32_t value = 0;
    napi_value napiValue = {};
    napi_valuetype tmpType = napi_undefined;
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        HILOG_ERROR("GetNamedPropertyInt32: call napi_typeof fail.");
        return value;
    }
    if (tmpType != napi_number) {
        HILOG_ERROR("GetNamedPropertyInt32: value is not number");
        return value;
    }
    napi_get_value_int32(env, napiValue, &value);
    HILOG_DEBUG("GetNamedPropertyInt32: %{public}s=%{public}d", name.c_str(), value);
    return value;
}

std::vector<int32_t> GetCppArrayInt(napi_value value, napi_env env)
{
    HILOG_DEBUG("enter");
    uint32_t arrayLength = 0;
    if (napi_get_array_length(env, value, &arrayLength) != napi_ok) {
        HILOG_ERROR("GetCppArrayInt: call napi_get_array_length fail.");
        return std::vector<int32_t>();
    }
    if (arrayLength <= 0) {
        HILOG_ERROR("%{public}s The array is empty.", __func__);
        return std::vector<int32_t>();
    }

    std::vector<int32_t> paramArrays;
    for (size_t i = 0; i < arrayLength; i++) {
        napi_value napiElement;
        if (napi_get_element(env, value, i, &napiElement) != napi_ok) {
            HILOG_ERROR("GetCppArrayInt: call napi_get_element fail.");
            return std::vector<int32_t>();
        }

        napi_valuetype valuetype0;
        if (napi_typeof(env, napiElement, &valuetype0) != napi_ok) {
            HILOG_ERROR("GetCppArrayInt: call napi_typeof fail.");
            return std::vector<int32_t>();
        }
        if (valuetype0 != napi_number) {
            HILOG_ERROR("GetCppArrayInt %{public}s Wrong argument type,Numbers expected.", __func__);
            return std::vector<int32_t>();
        }
        int32_t value0 = 0;
        if (napi_get_value_int32(env, napiElement, &value0) != napi_ok) {
            HILOG_ERROR("GetCppArrayInt: call napi_get_value_int32 fail.");
            return std::vector<int32_t>();
        }
        HILOG_DEBUG("GetCppArrayInt in number: %{public}d", value0);
        paramArrays.push_back(value0);
    }
    HILOG_DEBUG("leave");
    return paramArrays;
}

int32_t AddEventCallback(const napi_env &env, OHOS::MMI::CallbackMaps &callbackMaps,
    OHOS::MMI::KeyEventMonitorInfo *event, int32_t &preSubscribeId)
{
    HILOG_DEBUG("%{public}s begin", __func__);
    if (callbackMaps.find(event->eventType) == callbackMaps.end()) {
        HILOG_DEBUG("%{public}s has no callback function..", event->eventType.c_str());
        callbackMaps[event->eventType] = {};
    }
    auto iter = callbackMaps.find(event->eventType);
    auto it = iter->second.begin();
    while (it != iter->second.end()) {
        bool isEquals = false;
        napi_value handlerTemp = nullptr;
        napi_get_reference_value(env, (*it)->callback[0], &handlerTemp);
        napi_value handlerParam = nullptr;
        napi_get_reference_value(env, event->callback[0], &handlerParam);
        napi_strict_equals(env, handlerTemp, handlerParam, &isEquals);
        if (isEquals) {
            HILOG_DEBUG("%{public}s callback already exists.", event->eventType.c_str());
            return JS_CALLBACK_EVENT_EXIST;
        }
        it++;
    }
    if (iter->second.size() > 0) {
        preSubscribeId = iter->second.front()->subscribeId;
    }
    iter->second.push_back(event);
    HILOG_DEBUG("%{public}s end", __func__);
    return JS_CALLBACK_EVENT_SUCCESS;
}

int32_t DelEventCallback(const napi_env &env, OHOS::MMI::CallbackMaps &callbackMaps,
    OHOS::MMI::KeyEventMonitorInfo *event, int32_t &subscribeId)
{
    HILOG_DEBUG("enter");
    auto iter = callbackMaps.find(event->eventType);
    if (iter == callbackMaps.end()) {
        HILOG_DEBUG("DelEventCallback: %{public}s has no callback function.", event->eventType.c_str());
        return JS_CALLBACK_EVENT_FAILED;
    }
    HILOG_DEBUG("DelEventCallback: event=%{public}s, callbackMaps second size:%{public}d", event->eventType.c_str(),
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
            if (iter->second.size() <= 0) {
                subscribeId = monitorInfo->subscribeId;
            }
            delete monitorInfo;
            monitorInfo = nullptr;
            HILOG_DEBUG("DelCallback: success. callback exists. size=%{public}d",
                static_cast<int32_t>(iter->second.size()));
            return JS_CALLBACK_EVENT_SUCCESS;
        }
        it++;
    }
    HILOG_DEBUG("DelEventCallback: callback size=%{public}d", static_cast<int32_t>(iter->second.size()));
    return JS_CALLBACK_EVENT_NOT_EXIST;
}

void EmitAsyncCallbackWork(OHOS::MMI::KeyEventMonitorInfo *reportEvent)
{
    HILOG_DEBUG("%{public}s begin", __func__);
    if (reportEvent == nullptr) {
        HILOG_ERROR("%{public}s event is null!", __func__);
        return;
    }

    napi_value resourceName;
    if (napi_create_string_utf8(reportEvent->env, "AsyncCallback", NAPI_AUTO_LENGTH, &resourceName) != napi_ok) {
        HILOG_ERROR("%{public}s create string utf8 failed", __func__);
        return;
    }
    napi_create_async_work(
        reportEvent->env, nullptr, resourceName, [](napi_env env, void *data) {},
        [](napi_env env, napi_status status, void *data) {
            HILOG_DEBUG("%{public}s napi_create_async_work in", __func__);
            OHOS::MMI::KeyEventMonitorInfo *event = (OHOS::MMI::KeyEventMonitorInfo *)data;
            napi_value callback = nullptr;
            if (napi_get_reference_value(env, event->callback[0], &callback) != napi_ok) {
                HILOG_ERROR("%{public}s call napi_get_reference_value fail", __func__);
                return;
            }
            napi_value callResult = nullptr;
            napi_value result[2] = { 0 };
            if (event->status < 0) {
                HILOG_DEBUG("%{public}s status < 0 in", __func__);
                napi_value code = nullptr;
                napi_value message = nullptr;
                napi_create_string_utf8(env, "-1", NAPI_AUTO_LENGTH, &code);
                napi_create_string_utf8(env, "failed", NAPI_AUTO_LENGTH, &message);
                napi_create_error(env, code, message, &result[0]);
                napi_get_undefined(env, &result[1]);
            } else if (event->status == 0) {
                HILOG_DEBUG("%{public}s status = 0 in", __func__);
                napi_get_undefined(env, &result[0]);
                napi_get_undefined(env, &result[1]);
            } else {
                HILOG_DEBUG("%{public}s status > 0 in", __func__);
                if (napi_create_object(env, &result[1]) != napi_ok) {
                    HILOG_ERROR("%{public}s call napi_create_object fail", __func__);
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
                    HILOG_ERROR("%{public}s call napi_get_undefined fail", __func__);
                    return;
                }
            }

            auto callFunResult = napi_call_function(env, nullptr, callback, 2, result, &callResult);
            HILOG_DEBUG("call result:%{public}d", static_cast<int32_t>(callFunResult));
            if (callFunResult != napi_ok) {
                HILOG_ERROR("%{public}s call napi_call_function fail, call result:%{public}d", __func__, callFunResult);
                return;
            }
            if (event->status <= 0) {
                napi_delete_reference(env, event->callback[0]);
                napi_delete_async_work(env, event->asyncWork);
                delete event;
                event = nullptr;
            }
            HILOG_DEBUG("%{public}s napi_create_async_work left", __func__);
        },
        reportEvent, &reportEvent->asyncWork);
    napi_queue_async_work(reportEvent->env, reportEvent->asyncWork);
    HILOG_DEBUG("%{public}s end", __func__);
}
}
}
