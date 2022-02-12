/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsEventTarget" };
    JsEventTarget::DeviceType g_deviceType[] = {
        {"keyboard", JsEventTarget::EVDEV_UDEV_TAG_KEYBOARD},
        {"mouse", JsEventTarget::EVDEV_UDEV_TAG_MOUSE},
        {"touchpad", JsEventTarget::EVDEV_UDEV_TAG_TOUCHPAD},
        {"touchscreen", JsEventTarget::EVDEV_UDEV_TAG_TOUCHSCREEN},
        {"joystick", JsEventTarget::EVDEV_UDEV_TAG_JOYSTICK},
        {"trackball", JsEventTarget::EVDEV_UDEV_TAG_TRACKBALL},
    };
}

napi_ref JsEventTarget::ref_ = nullptr;
napi_env JsEventTarget::env_ = nullptr;
napi_async_work JsEventTarget::asyncWork_ = nullptr;

void JsEventTarget::CallIdsAsyncWork(napi_env env, napi_status status, void* data)
{
    MMI_LOGD("begin");
    CHKP(env_);
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
    struct IdsCallbackInfo *cb = (struct IdsCallbackInfo*)data;
    for (const auto &item : cb->idsTemp) {
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
        ++index;
    }
    delete cb;
    cb = nullptr;

    napi_value handlerTemp = nullptr;
    status_ = napi_get_reference_value(env, ref_, &handlerTemp);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_get_reference_value failed");
        MMI_LOGE("call to napi_get_reference_value failed");
        return;
    }
    napi_value result = nullptr;
    status_ = napi_call_function(env, nullptr, handlerTemp, 1, &arr, &result);
    if (status_ != napi_ok) {
        napi_delete_reference(env, ref_);
        napi_delete_async_work(env, asyncWork_);
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_call_function failed");
        MMI_LOGE("call to napi_call_function failed");
        return;
    }
    status_ = napi_delete_reference(env, ref_);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_delete_reference failed");
        MMI_LOGE("call to napi_delete_reference failed");
        return;
    }
    status_ = napi_delete_async_work(env, asyncWork_);
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
    MMI_LOGD("end");
}

void JsEventTarget::EmitJsIdsAsync(std::vector<int32_t> ids)
{
    MMI_LOGD("begin");
    CHKP(env_);
    IdsCallbackInfo *cb = new IdsCallbackInfo;
    cb->idsTemp = ids;
    napi_value resourceName = nullptr;
    napi_status status = napi_create_string_latin1(env_, "InputDeviceIdsAsync", NAPI_AUTO_LENGTH, &resourceName);
    if (status != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_string_latin1 failed");
        MMI_LOGE("call to napi_create_string_latin1 failed");
        return;
    }
    status = napi_create_async_work(env_, nullptr, resourceName, [](napi_env env, void *data) {},
                                    CallIdsAsyncWork, cb, &asyncWork_);
    if (status != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_async_work failed");
        MMI_LOGE("call to napi_create_async_work failed");
        return;
    }
    status = napi_queue_async_work(env_, asyncWork_);
    if (status != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_queue_async_work failed");
        MMI_LOGE("call to napi_queue_async_work failed");
        return;
    }
    MMI_LOGD("end");
}

void JsEventTarget::CallDevAsyncWork(napi_env env, napi_status status, void* data)
{
    MMI_LOGD("begin");
    CHKP(env_);
    napi_handle_scope scope = nullptr;
    napi_status status_ = napi_open_handle_scope(env, &scope);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: failed to open scope");
        MMI_LOGE("failed to open scope");
        return;
    }
    struct DevCallbackInfo *cb = (struct DevCallbackInfo*)data;
    auto device = cb->deviceTemp;
    delete cb;
    cb = nullptr;

    napi_value id = nullptr;
    status_ = napi_create_int64(env, device->id, &id);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_create_int64 failed");
        MMI_LOGE("call to napi_create_int64 failed");
        return;
    }
    napi_value name = nullptr;
    status_ = napi_create_string_utf8(env, (device->name).c_str(), NAPI_AUTO_LENGTH, &name);
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

    int32_t types = device->devcieType;
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
    status_ = napi_get_reference_value(env, ref_, &handlerTemp);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_get_reference_value failed");
        MMI_LOGE("call to napi_get_reference_value failed");
        return;
    }
    napi_value result = nullptr;
    status_ = napi_call_function(env, nullptr, handlerTemp, 1, &object, &result);
    if (status_ != napi_ok) {
        napi_delete_reference(env, ref_);
        napi_delete_async_work(env, asyncWork_);
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_call_function failed");
        MMI_LOGE("call to napi_call_function failed");
        return;
    }
    status_ = napi_delete_reference(env, ref_);
    if (status_ != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_delete_reference failed");
        MMI_LOGE("call to napi_delete_reference failed");
        return;
    }
    status_ = napi_delete_async_work(env, asyncWork_);
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
    MMI_LOGD("end");
}

void JsEventTarget::EmitJsDevAsync(std::shared_ptr<InputDeviceImpl::InputDeviceInfo> device)
{
    MMI_LOGD("begin");
    CHKP(env_);
    DevCallbackInfo *cb = new DevCallbackInfo;
    cb->deviceTemp = device;
    napi_value resourceName = nullptr;
    napi_status status = napi_create_string_latin1(env_, "InputDeviceAsync", NAPI_AUTO_LENGTH, &resourceName);
    if (status != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_string_latin1 failed");
        MMI_LOGE("call to napi_create_string_latin1 failed");
        return;
    }

    status = napi_create_async_work(env_, nullptr, resourceName, [](napi_env env, void *data) {},
                                    CallDevAsyncWork, cb, &asyncWork_);
    if (status != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_create_async_work failed");
        MMI_LOGE("call to napi_create_async_work failed");
        return;
    }
    status = napi_queue_async_work(env_, asyncWork_);
    if (status != napi_ok) {
        napi_throw_error(env_, nullptr, "JsEventTarget: call to napi_queue_async_work failed");
        MMI_LOGE("call to napi_queue_async_work failed");
        return;
    }
    MMI_LOGD("end");
}

void JsEventTarget::SetContext(napi_env env, napi_value handle)
{
    env_ = env;
    napi_ref handlerRef = nullptr;
    napi_status status = napi_create_reference(env_, handle, 1, &handlerRef);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "JsEventTarget: call to napi_create_reference failed");
        MMI_LOGE("call to napi_create_reference failed");
        return;
    }
    ref_ = handlerRef;
}

void JsEventTarget::ResetEnv()
{
    env_ = nullptr;
    ref_ = nullptr;
}
} // namespace MMI
} // namespace OHOS