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

void JsEventTarget::CallIdsAsyncWork(uv_work_t *work, int32_t status)
{
    CHKPV(work);
    CHKPV(work->data);
    CallbackInfo *cb = static_cast<CallbackInfo*>(work->data);
    CallbackInfo cbTemp = *cb;
    delete cb;
    cb = nullptr;
    delete work;
    work = nullptr;

    if (CheckEnv(env_)) {
        MMI_LOGE("env_ is nullptr");
        return;
    }
    napi_handle_scope scope = nullptr;
    napi_status status_ = napi_open_handle_scope(env_, &scope);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: failed to open scope");
        MMI_LOGE("failed to open scope");
        return;
    }
    napi_value arr = nullptr;
    status_ = napi_create_array(env_, &arr);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_array failed");
        MMI_LOGE("call to napi_create_array failed");
        return;
    }

    uint32_t index = 0;
    napi_value value = nullptr;
    for (const auto &item : cbTemp.ids) {
        status_ = napi_create_int64(env_, item, &value);
        if (status_ != napi_ok) {
            napi_delete_reference(env_, cbTemp.ref);
            napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_int64 failed");
            MMI_LOGE("call to napi_create_int64 failed");
            return;
        }
        status_ = napi_set_element(env_, arr, index, value);
        if (status_ != napi_ok) {
            napi_delete_reference(env_, cbTemp.ref);
            napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_set_element failed");
            MMI_LOGE("call to napi_set_element failed");
            return;
        }
        index++;
    }

    napi_value handlerTemp = nullptr;
    status_ = napi_get_reference_value(env_, cbTemp.ref, &handlerTemp);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_get_reference_value failed");
        MMI_LOGE("call to napi_get_reference_value failed");
        return;
    }
    napi_value result = nullptr;
    status_ = napi_call_function(env_, nullptr, handlerTemp, 1, &arr, &result);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_call_function failed");
        MMI_LOGE("call to napi_call_function failed");
        return;
    }
    status_ = napi_delete_reference(env_, cbTemp.ref);
    if (status_ != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_delete_reference failed");
        MMI_LOGE("call to napi_delete_reference failed");
        return;
    }

    status_ = napi_close_handle_scope(env_, scope);
    if (status_ != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: failed to close scope");
        MMI_LOGE("failed to close scope");
        return;
    }
}

void JsEventTarget::EmitJsIdsAsync(int32_t userData, std::vector<int32_t> ids)
{
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
    uv_loop_s *loop = nullptr;
    napi_status status = napi_get_uv_event_loop(env_, &loop);
    if (status != napi_ok) {
        MMI_LOGE("napi_get_uv_event_loop failed");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    work->data = static_cast<void*>(iter->second);
    int32_t ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallIdsAsyncWork);
    if (ret != 0) {
        MMI_LOGE("uv_queue_work failed");
        return;
    }
}

void JsEventTarget::CallDevAsyncWork(uv_work_t *work, int32_t status)
{
    CHKPV(work);
    CHKPV(work->data);
    CallbackInfo *cb = static_cast<CallbackInfo*>(work->data);
    CallbackInfo cbTemp = *cb;
    delete cb;
    cb = nullptr;
    delete work;
    work = nullptr;

    if (CheckEnv(env_)) {
        MMI_LOGE("env_ is nullptr");
        return;
    }
    napi_handle_scope scope = nullptr;
    napi_status status_ = napi_open_handle_scope(env_, &scope);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: failed to open scope");
        MMI_LOGE("failed to open scope");
        return;
    }

    napi_value id = nullptr;
    status_ = napi_create_int64(env_, cbTemp.device->id, &id);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_int64 failed");
        MMI_LOGE("call to napi_create_int64 failed");
        return;
    }
    napi_value name = nullptr;
    status_ = napi_create_string_utf8(env_, (cbTemp.device->name).c_str(), NAPI_AUTO_LENGTH, &name);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_string_utf8 failed");
        MMI_LOGE("call to napi_create_string_utf8 failed");
        return;
    }

    napi_value object = nullptr;
    status_ = napi_create_object(env_, &object);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_object failed");
        MMI_LOGE("call to napi_create_object failed");
        return;
    }

    status_ = napi_set_named_property(env_, object, "id", id);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_set_named_property failed");
        MMI_LOGE("call to napi_set_named_property failed");
        return;
    }
    status_ = napi_set_named_property(env_, object, "name", name);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_set_named_property failed");
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
    status_ = napi_create_array(env_, &devSources);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_array failed");
        MMI_LOGE("call to napi_create_array failed");
        return;
    }
    uint32_t index = 0;
    napi_value value = nullptr;
    for (const auto &item : sources) {
        status_ = napi_create_string_utf8(env_, item.c_str(), NAPI_AUTO_LENGTH, &value);
        if (status_ != napi_ok) {
            napi_delete_reference(env_, cbTemp.ref);
            napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_string_utf8 failed");
            MMI_LOGE("call to napi_create_string_utf8 failed");
            return;
        }
        status_ = napi_set_element(env_, devSources, index, value);
        if (status_ != napi_ok) {
            napi_delete_reference(env_, cbTemp.ref);
            napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_set_element failed");
            MMI_LOGE("call to napi_set_element failed");
            return;
        }
    }
    status_ = napi_set_named_property(env_, object, "sources", devSources);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_set_named_property failed");
        MMI_LOGE("call to napi_set_named_property failed");
        return;
    }

    napi_value axisRanges = nullptr;
    status_ = napi_create_array(env_, &axisRanges);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_array failed");
        MMI_LOGE("call to napi_create_array failed");
        return;
    }
    status_ = napi_set_named_property(env_, object, "axisRanges", axisRanges);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_set_named_property failed");
        MMI_LOGE("call to napi_set_named_property failed");
        return;
    }

    napi_value handlerTemp = nullptr;
    status_ = napi_get_reference_value(env_, cbTemp.ref, &handlerTemp);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_get_reference_value failed");
        MMI_LOGE("call to napi_get_reference_value failed");
        return;
    }
    napi_value result = nullptr;
    status_ = napi_call_function(env_, nullptr, handlerTemp, 1, &object, &result);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_call_function failed");
        MMI_LOGE("call to napi_call_function failed");
        return;
    }
    status_ = napi_delete_reference(env_, cbTemp.ref);
    if (status_ != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_delete_reference failed");
        MMI_LOGE("call to napi_delete_reference failed");
        return;
    }

    status_ = napi_close_handle_scope(env_, scope);
    if (status_ != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: failed to close scope");
        MMI_LOGE("failed to close scope");
        return;
    }
}

void JsEventTarget::EmitJsDevAsync(int32_t userData, std::shared_ptr<InputDeviceImpl::InputDeviceInfo> device)
{
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
    uv_loop_s *loop = nullptr;
    napi_status status = napi_get_uv_event_loop(env_, &loop);
    if (status != napi_ok) {
        MMI_LOGE("napi_get_uv_event_loop failed");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    work->data = static_cast<void*>(iter->second);
    int32_t ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallDevAsyncWork);
    if (ret != 0) {
        MMI_LOGE("uv_queue_work failed");
        return;
    }
}

void JsEventTarget::CallIdsPromiseWork(uv_work_t *work, int32_t status)
{
    CHKPV(work);
    CHKPV(work->data);
    CallbackInfo *cb = static_cast<CallbackInfo*>(work->data);
    CallbackInfo cbTemp = *cb;
    delete cb;
    cb = nullptr;
    delete work;
    work = nullptr;
    if (CheckEnv(env_)) {
        MMI_LOGE("env_ is nullptr");
        return;
    }

    napi_handle_scope scope = nullptr;
    napi_status status_ = napi_open_handle_scope(env_, &scope);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: failed to open scope");
        MMI_LOGE("failed to open scope");
        return;
    }
    napi_value arr = nullptr;
    status_ = napi_create_array(env_, &arr);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_array failed");
        MMI_LOGE("call to napi_create_array failed");
        return;
    }
    uint32_t index = 0;
    napi_value value = nullptr;
    for (const auto &item : cbTemp.ids) {
        status_ = napi_create_int64(env_, item, &value);
        if (status_ != napi_ok) {
            napi_delete_reference(env_, cbTemp.ref);
            napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_int64 failed");
            MMI_LOGE("call to napi_create_int64 failed");
            return;
        }
        status_ = napi_set_element(env_, arr, index, value);
        if (status_ != napi_ok) {
            napi_delete_reference(env_, cbTemp.ref);
            napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_set_element failed");
            MMI_LOGE("call to napi_set_element failed");
            return;
        }
        index++;
    }

    status_ = napi_resolve_deferred(env_, cbTemp.deferred, arr);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_call_function failed");
        MMI_LOGE("call to napi_call_function failed");
        return;
    }

    status_ = napi_close_handle_scope(env_, scope);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: failed to close scope");
        MMI_LOGE("failed to close scope");
        return;
    }
}

void JsEventTarget::EmitJsIdsPromise(int32_t userData, std::vector<int32_t> ids)
{
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
    uv_loop_s *loop = nullptr;
    napi_status status = napi_get_uv_event_loop(env_, &loop);
    if (status != napi_ok) {
        MMI_LOGE("napi_get_uv_event_loop failed");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    work->data = static_cast<void*>(iter->second);
    int32_t ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallIdsPromiseWork);
    if (ret != 0) {
        MMI_LOGE("uv_queue_work failed");
        return;
    }
}

void JsEventTarget::CallDevPromiseWork(uv_work_t *work, int32_t status)
{
    CHKPV(work);
    CHKPV(work->data);
    CallbackInfo *cb = static_cast<CallbackInfo*>(work->data);
    CallbackInfo cbTemp = *cb;
    delete cb;
    cb = nullptr;
    delete work;
    work = nullptr;

    if (CheckEnv(env_)) {
        MMI_LOGE("env_ is nullptr");
        return;
    }
    napi_handle_scope scope = nullptr;
    napi_status status_ = napi_open_handle_scope(env_, &scope);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: failed to open scope");
        MMI_LOGE("failed to open scope");
        return;
    }

    napi_value id = nullptr;
    status_ = napi_create_int64(env_, cbTemp.device->id, &id);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "napi_create_int64 failed");
        MMI_LOGE("napi_create_int64 failed");
        return;
    }
    napi_value name = nullptr;
    status_ = napi_create_string_utf8(env_, (cbTemp.device->name).c_str(), NAPI_AUTO_LENGTH, &name);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "napi_create_string_utf8 failed");
        MMI_LOGE("napi_create_string_utf8 failed");
        return;
    }
    napi_value object = nullptr;
    status_ = napi_create_object(env_, &object);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "napi_create_object failed");
        MMI_LOGE("napi_create_object failed");
        return;
    }

    status_ = napi_set_named_property(env_, object, "id", id);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "napi_set_named_property set id failed");
        MMI_LOGE("napi_set_named_property set id failed");
        return;
    }
    status_ = napi_set_named_property(env_, object, "name", name);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "napi_set_named_property set name failed");
        MMI_LOGE("napi_set_named_property set name failed");
        return;
    }

    uint32_t types = cbTemp.device->devcieType;
    if (types <= 0) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "devcieType is less than zero");
        MMI_LOGE("devcieType is less than zero");
    }
    std::vector<std::string> sources;
    for (const auto & item : g_deviceType) {
        if (static_cast<uint32_t>(types) & item.typeBit) {
            sources.push_back(item.deviceTypeName);
        }
    }
    napi_value devSources = nullptr;
    status_ = napi_create_array(env_, &devSources);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "napi_create_array failed");
        MMI_LOGE("napi_create_array failed");
        return;
    }

    uint32_t index = 0;
    napi_value value = nullptr;
    for (const auto &item : sources) {
        status_ = napi_create_string_utf8(env_, item.c_str(), NAPI_AUTO_LENGTH, &value);
        if (status_ != napi_ok) {
            napi_delete_reference(env_, cbTemp.ref);
            napi_throw_error(env_, nullptr, "napi_create_string_utf8 failed");
            MMI_LOGE("napi_create_string_utf8 failed");
            return;
        }
        status_ = napi_set_element(env_, devSources, index, value);
        if (status_ != napi_ok) {
            napi_delete_reference(env_, cbTemp.ref);
            napi_throw_error(env_, nullptr, "napi_set_element failed");
            MMI_LOGE("napi_set_element failed");
        }
    }
    status_ = napi_set_named_property(env_, object, "sources", devSources);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_set_named_property failed");
        MMI_LOGE("call to napi_set_named_property failed");
        return;
    }

    napi_value axisRanges = nullptr;
    status_ = napi_create_array(env_, &axisRanges);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_array failed");
        MMI_LOGE("call to napi_create_array failed");
        return;
    }
    status_ = napi_set_named_property(env_, object, "axisRanges", axisRanges);
    if (status_ != napi_ok) {
        napi_delete_reference(env_, cbTemp.ref);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_set_named_property failed");
        MMI_LOGE("call to napi_set_named_property failed");
        return;
    }

    status_ = napi_resolve_deferred(env_, cbTemp.deferred, object);
    if (status_ != napi_ok) {
        napi_delete_async_work(env_, cbTemp.asyncWork);
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_call_function failed");
        MMI_LOGE("call to napi_call_function failed");
        return;
    }

    status_ = napi_close_handle_scope(env_, scope);
    if (status_ != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: failed to close scope");
        MMI_LOGE("failed to close scope");
        return;
    }
}

void JsEventTarget::EmitJsDevPromise(int32_t userData, std::shared_ptr<InputDeviceImpl::InputDeviceInfo> device)
{
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
    uv_loop_s *loop = nullptr;
    napi_status status = napi_get_uv_event_loop(env_, &loop);
    if (status != napi_ok) {
        MMI_LOGE("napi_get_uv_event_loop failed");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    work->data = static_cast<void*>(iter->second);
    int32_t ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallDevPromiseWork);
    if (ret != 0) {
        MMI_LOGE("uv_queue_work failed");
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
    if (env_ != nullptr) {
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