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

#include "js_event_target.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsEventTarget" };
JsEventTarget::DeviceType g_deviceType[] = {
    {"keyboard", JsEventTarget::EVDEV_UDEV_TAG_KEYBOARD},
    {"mouse", JsEventTarget::EVDEV_UDEV_TAG_MOUSE},
    {"touchpad", JsEventTarget::EVDEV_UDEV_TAG_TOUCHPAD},
    {"touchscreen", JsEventTarget::EVDEV_UDEV_TAG_TOUCHSCREEN},
    {"joystick", JsEventTarget::EVDEV_UDEV_TAG_JOYSTICK},
    {"trackball", JsEventTarget::EVDEV_UDEV_TAG_TRACKBALL},
};
} // namespace

napi_env JsEventTarget::env_ = nullptr;
static std::map<int32_t, JsEventTarget::CallbackInfo*> callback_ {};
int32_t JsEventTarget::userData_ = 0;

void JsEventTarget::CallIdsAsyncWork(napi_env env, napi_status status, void* data)
{
    CALL_LOG_ENTER;
    CHKPV(data);
    napi_handle_scope scope = nullptr;
    napi_status status_ = napi_open_handle_scope(env, &scope);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: failed to open scope");
        MMI_LOGE("failed to open scope");
        return;
    }
    napi_value arr = nullptr;
    status_ = napi_create_array(env, &arr);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_create_array failed");
        MMI_LOGE("call to napi_create_array failed");
        return;
    }
    uint32_t index = 0;
    napi_value value = nullptr;
    struct CallbackInfo *cb = static_cast<struct CallbackInfo*>(data);
    CallbackInfo cbTemp = *cb;
    delete cb;
    cb = nullptr;

    for (const auto &item : cbTemp.ids) {
        status_ = napi_create_int64(env, item, &value);
        if (status_ != napi_ok) {
            napi_throw_error(env, nullptr, "JsEventTarget: call to napi_create_int64 failed");
            MMI_LOGE("call to napi_create_int64 failed");
            return;
        }
        status_ = napi_set_element(env, arr, index, value);
        if (status_ != napi_ok) {
            napi_throw_error(env, nullptr, "JsEventTarget: call to napi_set_element failed");
            MMI_LOGE("call to napi_set_element failed");
            return;
        }
        index++;
    }

    napi_value handlerTemp = nullptr;
    status_ = napi_get_reference_value(env, cbTemp.ref, &handlerTemp);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_get_reference_value failed");
        MMI_LOGE("call to napi_get_reference_value failed");
        return;
    }
    napi_value result = nullptr;
    status_ = napi_call_function(env, nullptr, handlerTemp, 1, &arr, &result);
    if (status_ != napi_ok) {
        napi_delete_reference(env, cbTemp.ref);
        napi_delete_async_work(env, cbTemp.asyncWork);
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_call_function failed");
        MMI_LOGE("call to napi_call_function failed");
        return;
    }
    status_ = napi_delete_reference(env, cbTemp.ref);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_delete_reference failed");
        MMI_LOGE("call to napi_delete_reference failed");
        return;
    }
    status_ = napi_delete_async_work(env, cbTemp.asyncWork);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_delete_async_work failed");
        MMI_LOGE("call to napi_delete_async_work failed");
        return;
    }

    status_ = napi_close_handle_scope(env, scope);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: failed to close scope");
        MMI_LOGE("failed to close scope");
        return;
    }
}

void JsEventTarget::EmitJsIdsAsync(int32_t userData, std::vector<int32_t> ids)
{
    CALL_LOG_ENTER;
    if (CheckEnv(env_)) {
        MMI_LOGE("env_ is nullptr");
        return;
    }
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_LOGE("Failed to search for userData");
        return;
    }
    CHKPV(iter->second);
    iter->second->ids = ids;

    napi_value resourceName = nullptr;
    napi_status status = napi_create_string_latin1(env_, "InputDeviceIdsAsync", NAPI_AUTO_LENGTH, &resourceName);
    if (status != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_string_latin1 failed");
        MMI_LOGE("call to napi_create_string_latin1 failed");
        return;
    }
    status = napi_create_async_work(env_, nullptr, resourceName, [](napi_env env, void *data) {},
                                    CallIdsAsyncWork, iter->second, &(iter->second->asyncWork));
    if (status != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_async_work failed");
        MMI_LOGE("call to napi_create_async_work failed");
        return;
    }
    status = napi_queue_async_work(env_, iter->second->asyncWork);
    if (status != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_queue_async_work failed");
        MMI_LOGE("call to napi_queue_async_work failed");
        return;
    }
}

void JsEventTarget::CallDevAsyncWork(napi_env env, napi_status status, void* data)
{
    CALL_LOG_ENTER;
    CHKPV(data);
    napi_handle_scope scope = nullptr;
    napi_status status_ = napi_open_handle_scope(env, &scope);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: failed to open scope");
        MMI_LOGE("failed to open scope");
        return;
    }
    struct CallbackInfo *cb = static_cast<struct CallbackInfo*>(data);
    CallbackInfo cbTemp = *cb;
    delete cb;
    cb = nullptr;

    napi_value id = nullptr;
    status_ = napi_create_int64(env, cbTemp.device->id, &id);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_create_int64 failed");
        MMI_LOGE("call to napi_create_int64 failed");
        return;
    }
    napi_value name = nullptr;
    status_ = napi_create_string_utf8(env, (cbTemp.device->name).c_str(), NAPI_AUTO_LENGTH, &name);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_create_string_utf8 failed");
        MMI_LOGE("call to napi_create_string_utf8 failed");
        return;
    }

    napi_value object = nullptr;
    status_ = napi_create_object(env, &object);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_create_object failed");
        MMI_LOGE("call to napi_create_object failed");
        return;
    }

    status_ = napi_set_named_property(env, object, "id", id);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_set_named_property failed");
        MMI_LOGE("call to napi_set_named_property failed");
        return;
    }
    status_ = napi_set_named_property(env, object, "name", name);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_set_named_property failed");
        MMI_LOGE("call to napi_set_named_property failed");
        return;
    }

    uint32_t types = cbTemp.device->devcieType;
    std::vector<std::string> sources;
    for (const auto & item : g_deviceType) {
        if (types & item.typeBit) {
            sources.push_back(item.deviceTypeName);
        }
    }
    napi_value devSources = nullptr;
    status_ = napi_create_array(env, &devSources);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_create_array failed");
        MMI_LOGE("call to napi_create_array failed");
        return;
    }
    uint32_t index = 0;
    napi_value value = nullptr;
    for (const auto &item : sources) {
        status_ = napi_create_string_utf8(env, item.c_str(), NAPI_AUTO_LENGTH, &value);
        if (status_ != napi_ok) {
            napi_throw_error(env, nullptr, "JsEventTarget: call to napi_create_string_utf8 failed");
            MMI_LOGE("call to napi_create_string_utf8 failed");
            return;
        }
        status_ = napi_set_element(env, devSources, index, value);
        if (status_ != napi_ok) {
            napi_throw_error(env, nullptr, "JsEventTarget: call to napi_set_element failed");
            MMI_LOGE("call to napi_set_element failed");
        }
    }
    status_ = napi_set_named_property(env, object, "sources", devSources);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_set_named_property failed");
        MMI_LOGE("call to napi_set_named_property failed");
        return;
    }

    napi_value axisRanges = nullptr;
    status_ = napi_create_array(env, &axisRanges);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_create_array failed");
        MMI_LOGE("call to napi_create_array failed");
        return;
    }
    status_ = napi_set_named_property(env, object, "axisRanges", axisRanges);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_set_named_property failed");
        MMI_LOGE("call to napi_set_named_property failed");
        return;
    }

    napi_value handlerTemp = nullptr;
    status_ = napi_get_reference_value(env, cbTemp.ref, &handlerTemp);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_get_reference_value failed");
        MMI_LOGE("call to napi_get_reference_value failed");
        return;
    }
    napi_value result = nullptr;
    status_ = napi_call_function(env, nullptr, handlerTemp, 1, &object, &result);
    if (status_ != napi_ok) {
        napi_delete_reference(env, cbTemp.ref);
        napi_delete_async_work(env, cbTemp.asyncWork);
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_call_function failed");
        MMI_LOGE("call to napi_call_function failed");
        return;
    }
    status_ = napi_delete_reference(env, cbTemp.ref);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_delete_reference failed");
        MMI_LOGE("call to napi_delete_reference failed");
        return;
    }
    status_ = napi_delete_async_work(env, cbTemp.asyncWork);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_delete_async_work failed");
        MMI_LOGE("call to napi_delete_async_work failed");
        return;
    }

    status_ = napi_close_handle_scope(env, scope);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: failed to close scope");
        MMI_LOGE("failed to close scope");
        return;
    }
}

void JsEventTarget::EmitJsDevAsync(int32_t userData, std::shared_ptr<InputDeviceImpl::InputDeviceInfo> device)
{
    CALL_LOG_ENTER;
    CHKPV(device);
    if (CheckEnv(env_)) {
        MMI_LOGE("env_ is nullptr");
        return;
    }
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_LOGE("Failed to search for userData");
        return;
    }
    CHKPV(iter->second);
    iter->second->device = device;

    napi_value resourceName = nullptr;
    napi_status status = napi_create_string_latin1(env_, "InputDeviceAsync", NAPI_AUTO_LENGTH, &resourceName);
    if (status != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_string_latin1 failed");
        MMI_LOGE("call to napi_create_string_latin1 failed");
        return;
    }

    status = napi_create_async_work(env_, nullptr, resourceName, [](napi_env env, void *data) {},
                                    CallDevAsyncWork, iter->second, &(iter->second->asyncWork));
    if (status != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_async_work failed");
        MMI_LOGE("call to napi_create_async_work failed");
        return;
    }
    status = napi_queue_async_work(env_, iter->second->asyncWork);
    if (status != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_queue_async_work failed");
        MMI_LOGE("call to napi_queue_async_work failed");
        return;
    }
}

void JsEventTarget::CallIdsPromiseWork(napi_env env, napi_status status, void* data)
{
    CALL_LOG_ENTER;
    CHKPV(data);
    napi_handle_scope scope = nullptr;
    napi_status status_ = napi_open_handle_scope(env, &scope);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: failed to open scope");
        MMI_LOGE("failed to open scope");
        return;
    }
    napi_value arr = nullptr;
    status_ = napi_create_array(env, &arr);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_create_array failed");
        MMI_LOGE("call to napi_create_array failed");
        return;
    }
    uint32_t index = 0;
    napi_value value = nullptr;
    struct CallbackInfo *cb = static_cast<struct CallbackInfo*>(data);
    CallbackInfo cbTemp = *cb;
    delete cb;
    cb = nullptr;

    for (const auto &item : cbTemp.ids) {
        status_ = napi_create_int64(env, item, &value);
        if (status_ != napi_ok) {
            napi_throw_error(env, nullptr, "JsEventTarget: call to napi_create_int64 failed");
            MMI_LOGE("call to napi_create_int64 failed");
            return;
        }
        status_ = napi_set_element(env, arr, index, value);
        if (status_ != napi_ok) {
            napi_throw_error(env, nullptr, "JsEventTarget: call to napi_set_element failed");
            MMI_LOGE("call to napi_set_element failed");
            return;
        }
        index++;
    }

    status_ = napi_resolve_deferred(env, cbTemp.deferred, arr);
    if (status_ != napi_ok) {
        napi_delete_async_work(env, cbTemp.asyncWork);
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_call_function failed");
        MMI_LOGE("call to napi_call_function failed");
        return;
    }
    status_ = napi_delete_async_work(env, cbTemp.asyncWork);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_delete_async_work failed");
        MMI_LOGE("call to napi_delete_async_work failed");
        return;
    }

    status_ = napi_close_handle_scope(env, scope);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: failed to close scope");
        MMI_LOGE("failed to close scope");
        return;
    }
}

void JsEventTarget::EmitJsIdsPromise(int32_t userData, std::vector<int32_t> ids)
{
    CALL_LOG_ENTER;
    if (CheckEnv(env_)) {
        MMI_LOGE("env_ is nullptr");
        return;
    }

    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_LOGE("Failed to search for userData");
        return;
    }
    CHKPV(iter->second);
    iter->second->ids = ids;

    napi_value resourceName = nullptr;
    napi_status status = napi_create_string_latin1(env_, "InputDeviceIdsPromis", NAPI_AUTO_LENGTH, &resourceName);
    if (status != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_string_latin1 failed");
        MMI_LOGE("call to napi_create_string_latin1 failed");
        return;
    }

    status = napi_create_async_work(env_, nullptr, resourceName, [](napi_env env, void *data) {},
                                    CallIdsPromiseWork, iter->second, &(iter->second->asyncWork));
    if (status != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_async_work failed");
        MMI_LOGE("call to napi_create_async_work failed");
        return;
    }

    status = napi_queue_async_work(env_, iter->second->asyncWork);
    if (status != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_queue_async_work failed");
        MMI_LOGE("call to napi_queue_async_work failed");
        return;
    }
}

void JsEventTarget::CallDevPromiseWork(napi_env env, napi_status status, void* data)
{
    CALL_LOG_ENTER;
    CHKPV(data);
    napi_handle_scope scope = nullptr;
    napi_status status_ = napi_open_handle_scope(env, &scope);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: failed to open scope");
        MMI_LOGE("failed to open scope");
        return;
    }

    struct CallbackInfo *cb = static_cast<struct CallbackInfo*>(data);
    CallbackInfo cbTemp = *cb;
    delete cb;
    cb = nullptr;

    napi_value id = nullptr;
    status_ = napi_create_int64(env, cbTemp.device->id, &id);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "napi_create_int64 failed");
        MMI_LOGE("napi_create_int64 failed");
        return;
    }
    napi_value name = nullptr;
    status_ = napi_create_string_utf8(env, (cbTemp.device->name).c_str(), NAPI_AUTO_LENGTH, &name);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "napi_create_string_utf8 failed");
        MMI_LOGE("napi_create_string_utf8 failed");
        return;
    }
    napi_value object = nullptr;
    status_ = napi_create_object(env, &object);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "napi_create_object failed");
        MMI_LOGE("napi_create_object failed");
        return;
    }

    status_ = napi_set_named_property(env, object, "id", id);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "napi_set_named_property set id failed");
        MMI_LOGE("napi_set_named_property set id failed");
        return;
    }
    status_ = napi_set_named_property(env, object, "name", name);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "napi_set_named_property set name failed");
        MMI_LOGE("napi_set_named_property set name failed");
        return;
    }

    uint32_t types = cbTemp.device->devcieType;
    if (types <= 0) {
        napi_throw_error(env, nullptr, "devcieType is less than zero");
        MMI_LOGE("devcieType is less than zero");
    }
    std::vector<std::string> sources;
    for (const auto & item : g_deviceType) {
        if (static_cast<uint32_t>(types) & item.typeBit) {
            sources.push_back(item.deviceTypeName);
        }
    }
    napi_value devSources = nullptr;
    status_ = napi_create_array(env, &devSources);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "napi_create_array failed");
        MMI_LOGE("napi_create_array failed");
        return;
    }

    uint32_t index = 0;
    napi_value value = nullptr;
    for (const auto &item : sources) {
        status_ = napi_create_string_utf8(env, item.c_str(), NAPI_AUTO_LENGTH, &value);
        if (status_ != napi_ok) {
            napi_throw_error(env, nullptr, "napi_create_string_utf8 failed");
            MMI_LOGE("napi_create_string_utf8 failed");
            return;
        }
        status_ = napi_set_element(env, devSources, index, value);
        if (status_ != napi_ok) {
            napi_throw_error(env, nullptr, "napi_set_element failed");
            MMI_LOGE("napi_set_element failed");
        }
    }
    status_ = napi_set_named_property(env, object, "sources", devSources);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_set_named_property failed");
        MMI_LOGE("call to napi_set_named_property failed");
        return;
    }

    napi_value axisRanges = nullptr;
    status_ = napi_create_array(env, &axisRanges);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_create_array failed");
        MMI_LOGE("call to napi_create_array failed");
        return;
    }
    status_ = napi_set_named_property(env, object, "axisRanges", axisRanges);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_set_named_property failed");
        MMI_LOGE("call to napi_set_named_property failed");
        return;
    }

    status_ = napi_resolve_deferred(env, cbTemp.deferred, object);
    if (status_ != napi_ok) {
        napi_delete_async_work(env, cbTemp.asyncWork);
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_call_function failed");
        MMI_LOGE("call to napi_call_function failed");
        return;
    }
    status_ = napi_delete_async_work(env, cbTemp.asyncWork);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_delete_async_work failed");
        MMI_LOGE("call to napi_delete_async_work failed");
        return;
    }

    status_ = napi_close_handle_scope(env, scope);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: failed to close scope");
        MMI_LOGE("failed to close scope");
        return;
    }
}

void JsEventTarget::EmitJsDevPromise(int32_t userData, std::shared_ptr<InputDeviceImpl::InputDeviceInfo> device)
{
    CALL_LOG_ENTER;
    CHKPV(device);
    if (CheckEnv(env_)) {
        MMI_LOGE("env_ is nullptr");
        return;
    }
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_LOGE("Failed to search for userData");
        return;
    }
    CHKPV(iter->second);
    iter->second->device = device;

    napi_value resourceName = nullptr;
    napi_status status = napi_create_string_latin1(env_, "InputDevicePromis", NAPI_AUTO_LENGTH, &resourceName);
    if (status != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: napi_create_string_latin1 failed");
        MMI_LOGE("napi create string failed");
        return;
    }

    status = napi_create_async_work(env_, nullptr, resourceName, [](napi_env env, void *data) {},
                                    CallDevPromiseWork, iter->second, &(iter->second->asyncWork));
    if (status != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_async_work failed");
        MMI_LOGE("call to napi_create_async_work failed");
        return;
    }

    status = napi_queue_async_work(env_, iter->second->asyncWork);
    if (status != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_queue_async_work failed");
        MMI_LOGE("call to napi_queue_async_work failed");
        return;
    }
}

napi_value JsEventTarget::CreateCallbackInfo(napi_env env, napi_value handle)
{
    env_ = env;
    CallbackInfo* cb = new (std::nothrow) CallbackInfo;
    CHKPP(cb);

    napi_status status = napi_generic_failure;
    if (handle == nullptr) {
        status = napi_create_promise(env_, &cb->deferred, &cb->promise);
        if (status != napi_ok) {
            delete cb;
            cb = nullptr;
            napi_throw_error(env_, nullptr, "JsEventTarget: failed to create promise");
            MMI_LOGE("failed to create promise");
            return nullptr;
        }
        callback_[userData_] = cb;
        if (userData_ == INT32_MAX) {
            MMI_LOGE("userData_ exceeds the maximum");
            return nullptr;
        }
        ++userData_;
        return cb->promise;
    }

    status = napi_create_reference(env_, handle, 1, &cb->ref);
    if (status != napi_ok) {
        delete cb;
        cb = nullptr;
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_reference failed");
        MMI_LOGE("call to napi_create_reference failed");
        return nullptr;
    }
    callback_[userData_] = cb;
    if (userData_ == INT32_MAX) {
        MMI_LOGE("userData_ exceeds the maximum");
        return nullptr;
    }
    ++userData_;
    return nullptr;
}

void JsEventTarget::ResetEnv()
{
    env_ = nullptr;
}

bool JsEventTarget::CheckEnv(napi_env env)
{
    if (env != nullptr) {
        return false;
    }

    for (auto &item : callback_) {
        if (item.second == nullptr) {
            continue;
        }
        delete item.second;
        item.second = nullptr;
    }
    return true;
}
} // namespace MMI
} // namespace OHOS