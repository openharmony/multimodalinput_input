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

#include <map>

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsEventTarget" };
constexpr uint32_t EVDEV_UDEV_TAG_KEYBOARD = (1 << 1);
constexpr uint32_t EVDEV_UDEV_TAG_MOUSE = (1 << 2);
constexpr uint32_t EVDEV_UDEV_TAG_TOUCHPAD = (1 << 3);
constexpr uint32_t EVDEV_UDEV_TAG_TOUCHSCREEN = (1 << 4);
constexpr uint32_t EVDEV_UDEV_TAG_JOYSTICK = (1 << 6);
constexpr uint32_t EVDEV_UDEV_TAG_TRACKBALL = (1 << 10);

JsEventTarget::DeviceType g_deviceType[] = {
    {"keyboard", EVDEV_UDEV_TAG_KEYBOARD},
    {"mouse", EVDEV_UDEV_TAG_MOUSE},
    {"touchpad", EVDEV_UDEV_TAG_TOUCHPAD},
    {"touchscreen", EVDEV_UDEV_TAG_TOUCHSCREEN},
    {"joystick", EVDEV_UDEV_TAG_JOYSTICK},
    {"trackball", EVDEV_UDEV_TAG_TRACKBALL},
};
} // namespace

napi_env JsEventTarget::env_ = nullptr;
static std::map<int32_t, JsUtil::CallbackInfo*> callback_ {};
int32_t JsEventTarget::userData_ = 0;

void JsEventTarget::CallIdsAsyncWork(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    JsUtil::CallbackTemp cbTemp(env_);
    JsUtil jsUtil;
    jsUtil.GetCallbackInfo(work, cbTemp);

    napi_value arr = nullptr;
    CHKRV(env_, napi_create_array(env_, &arr), "napi_create_array");
    uint32_t index = 0;
    napi_value value = nullptr;
    for (const auto &item : cbTemp.data.ids) {
        CHKRV(env_, napi_create_int32(env_, item, &value), "napi_create_int32");
        CHKRV(env_, napi_set_element(env_, arr, index, value), "napi_set_element");
        ++index;
    }

    napi_value handlerTemp = nullptr;
    CHKRV(env_, napi_get_reference_value(env_, cbTemp.ref, &handlerTemp), "napi_get_reference_value");
    napi_value result = nullptr;
    CHKRV(env_, napi_call_function(env_, nullptr, handlerTemp, 1, &arr, &result), "napi_call_function");
}

void JsEventTarget::CallIdsPromiseWork(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    JsUtil::CallbackTemp cbTemp(env_);
    JsUtil jsUtil;
    jsUtil.GetCallbackInfo(work, cbTemp);

    napi_value arr = nullptr;
    CHKRV(env_, napi_create_array(env_, &arr), "napi_create_array");

    napi_value value = nullptr;
    uint32_t index = 0;
    for (const auto &item : cbTemp.data.ids) {
        CHKRV(env_, napi_create_int32(env_, item, &value), "napi_create_int32");
        CHKRV(env_, napi_set_element(env_, arr, index, value), "napi_set_element");
        index++;
    }
    CHKRV(env_, napi_resolve_deferred(env_, cbTemp.deferred, arr), "napi_resolve_deferred");
}

void JsEventTarget::EmitJsIds(int32_t userData, std::vector<int32_t> ids)
{
    CALL_LOG_ENTER;
    if (CheckEnv(env_)) {
        MMI_HILOGE("env_ is nullptr");
        return;
    }
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("Failed to search for userData");
        return;
    }
    iter->second->data.ids = ids;
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    work->data = static_cast<void*>(iter->second);
    uv_loop_s *loop = nullptr;
    napi_status status = napi_get_uv_event_loop(env_, &loop);
    if (status != napi_ok) {
        MMI_HILOGE("napi_get_uv_event_loop failed");
        return;
    }
    if (iter->second->ref == nullptr) {
        uv_queue_work(loop, work, [](uv_work_t *work) {}, CallIdsPromiseWork);
    } else {
        uv_queue_work(loop, work, [](uv_work_t *work) {}, CallIdsAsyncWork);
    }
}

void JsEventTarget::CallDevAsyncWork(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    JsUtil::CallbackTemp cbTemp(env_);
    JsUtil jsUtil;
    jsUtil.GetCallbackInfo(work, cbTemp);
    CHKPV(cbTemp.data.device);

    napi_value id = nullptr;
    CHKRV(env_, napi_create_int32(env_, cbTemp.data.device->id, &id), "napi_create_int32");
    napi_value name = nullptr;
    CHKRV(env_, napi_create_string_utf8(env_, (cbTemp.data.device->name).c_str(), NAPI_AUTO_LENGTH, &name),
        "napi_create_string_utf8");

    napi_value object = nullptr;
    CHKRV(env_, napi_create_object(env_, &object), "napi_create_object");
    CHKRV(env_, napi_set_named_property(env_, object, "id", id), "napi_set_named_property");
    CHKRV(env_, napi_set_named_property(env_, object, "name", name), "napi_set_named_property");

    uint32_t types = cbTemp.data.device->devcieType;
    std::vector<std::string> sources;
    for (const auto & item : g_deviceType) {
        if (types & item.typeBit) {
            sources.push_back(item.deviceTypeName);
        }
    }
    napi_value devSources = nullptr;
    CHKRV(env_, napi_create_array(env_, &devSources), "napi_create_array");
    uint32_t index = 0;
    napi_value value = nullptr;
    for (const auto &item : sources) {
        CHKRV(env_, napi_create_string_utf8(env_, item.c_str(), NAPI_AUTO_LENGTH, &value), "napi_create_string_utf8");
        CHKRV(env_, napi_set_element(env_, devSources, index, value), "napi_set_element");
    }
    CHKRV(env_, napi_set_named_property(env_, object, "sources", devSources), "napi_set_named_property");

    napi_value axisRanges = nullptr;
    CHKRV(env_, napi_create_array(env_, &axisRanges), "napi_create_array");
    CHKRV(env_, napi_set_named_property(env_, object, "axisRanges", axisRanges), "napi_set_named_property");

    napi_value handlerTemp = nullptr;
    CHKRV(env_, napi_get_reference_value(env_, cbTemp.ref, &handlerTemp), "napi_get_reference_value");
    napi_value result = nullptr;
    CHKRV(env_, napi_call_function(env_, nullptr, handlerTemp, 1, &object, &result), "napi_call_function");
}

void JsEventTarget::CallDevPromiseWork(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    JsUtil::CallbackTemp cbTemp(env_);
    JsUtil jsUtil;
    jsUtil.GetCallbackInfo(work, cbTemp);
    CHKPV(cbTemp.data.device);

    napi_value id = nullptr;
    CHKRV(env_, napi_create_int32(env_, cbTemp.data.device->id, &id), "napi_create_int32");
    napi_value name = nullptr;
    CHKRV(env_, napi_create_string_utf8(env_, (cbTemp.data.device->name).c_str(), NAPI_AUTO_LENGTH, &name),
          "napi_create_string_utf8");
    napi_value object = nullptr;
    CHKRV(env_, napi_create_object(env_, &object), "napi_create_object");
    CHKRV(env_, napi_set_named_property(env_, object, "id", id), "napi_set_named_property");
    CHKRV(env_, napi_set_named_property(env_, object, "name", name), "napi_set_named_property");

    uint32_t types = cbTemp.data.device->devcieType;
    if (types <= 0) {
        napi_throw_error(env_, nullptr, "devcieType is less than zero");
        MMI_HILOGE("devcieType is less than zero");
    }
    std::vector<std::string> sources;
    for (const auto & item : g_deviceType) {
        if (static_cast<uint32_t>(types) & item.typeBit) {
            sources.push_back(item.deviceTypeName);
        }
    }
    napi_value devSources = nullptr;
    CHKRV(env_, napi_create_array(env_, &devSources), "napi_create_array");

    uint32_t index = 0;
    napi_value value = nullptr;
    for (const auto &item : sources) {
        CHKRV(env_, napi_create_string_utf8(env_, item.c_str(), NAPI_AUTO_LENGTH, &value), "napi_create_string_utf8");
        CHKRV(env_, napi_set_element(env_, devSources, index, value), "napi_set_element");
    }
    CHKRV(env_, napi_set_named_property(env_, object, "sources", devSources), "napi_set_named_property");

    napi_value axisRanges = nullptr;
    CHKRV(env_, napi_create_array(env_, &axisRanges), "napi_create_array");
    CHKRV(env_, napi_set_named_property(env_, object, "axisRanges", axisRanges), "napi_set_named_property");
    CHKRV(env_, napi_resolve_deferred(env_, cbTemp.deferred, object), "napi_resolve_deferred");
}

void JsEventTarget::EmitJsDev(int32_t userData, std::shared_ptr<InputDeviceImpl::InputDeviceInfo> device)
{
    CALL_LOG_ENTER;
    CHKPV(device);
    if (CheckEnv(env_)) {
        MMI_HILOGE("env_ is nullptr");
        return;
    }
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("failed to search for userData");
        return;
    }
    iter->second->data.device = device;
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    work->data = static_cast<void*>(iter->second);
    uv_loop_s *loop = nullptr;
    napi_status status = napi_get_uv_event_loop(env_, &loop);
    if (status != napi_ok) {
        MMI_HILOGE("napi_get_uv_event_loop failed");
        return;
    }
    if (iter->second->ref == nullptr) {
        uv_queue_work(loop, work, [](uv_work_t *work){}, CallDevPromiseWork);
    } else {
        uv_queue_work(loop, work, [](uv_work_t *work){}, CallDevAsyncWork);
    }
}

void JsEventTarget::CallKeystrokeAbilityPromise(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    JsUtil::CallbackTemp cbTemp(env_);
    JsUtil jsUtil;
    jsUtil.GetCallbackInfo(work, cbTemp);

    for (auto it : cbTemp.data.keystrokeAbility) {
        MMI_HILOGE("MMMMMM %{public}d", it);
    }

    napi_value keyAbility = nullptr;
    CHKRV(env_, napi_create_array(env_, &keyAbility), "napi_create_array");
    napi_value keyCode = nullptr;
    napi_value ret = nullptr;
    napi_value isBool = nullptr;
    uint32_t index1 = 0;
    for (auto it = cbTemp.data.keystrokeAbility.begin(); it != cbTemp.data.keystrokeAbility.end(); ++it) {
        napi_value abilityRet = nullptr;
        CHKRV(env_, napi_create_array(env_, &abilityRet), "napi_create_array");
        uint32_t index2 = 0;
        CHKRV(env_, napi_create_int32(env_, *it, &keyCode), "napi_create_int32");
        CHKRV(env_, napi_set_element(env_, abilityRet, index2, keyCode), "napi_set_element");
        ++index2;
        CHKRV(env_, napi_create_int32(env_, *(++it), &ret), "napi_create_int32");
        CHKRV(env_, napi_coerce_to_bool(env_, ret, &isBool), "napi_create_int32");
        CHKRV(env_, napi_set_element(env_, abilityRet, index2, isBool), "napi_set_element");
        CHKRV(env_, napi_set_element(env_, keyAbility, index1, abilityRet), "napi_set_element");
        ++index1;
    }
    CHKRV(env_, napi_resolve_deferred(env_, cbTemp.deferred, keyAbility), "napi_resolve_deferred");
}

void JsEventTarget::CallKeystrokeAbilityAsync(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    JsUtil::CallbackTemp cbTemp(env_);
    JsUtil jsUtil;
    jsUtil.GetCallbackInfo(work, cbTemp);

    napi_value keyAbility = nullptr;
    CHKRV(env_, napi_create_array(env_, &keyAbility), "napi_create_array");
    napi_value keyCode = nullptr;
    napi_value ret = nullptr;
    napi_value isBool = nullptr;
    uint32_t index1 = 0;
    for (auto it = cbTemp.data.keystrokeAbility.begin(); it != cbTemp.data.keystrokeAbility.end(); ++it) {
        napi_value abilityRet = nullptr;
        CHKRV(env_, napi_create_array(env_, &abilityRet), "napi_create_array");
        uint32_t index2 = 0;
        CHKRV(env_, napi_create_int32(env_, *it, &keyCode), "napi_create_int32");
        CHKRV(env_, napi_set_element(env_, abilityRet, index2, keyCode), "napi_set_element");
        ++index2;
        CHKRV(env_, napi_create_int32(env_, *(++it), &ret), "napi_create_int32");
        CHKRV(env_, napi_coerce_to_bool(env_, ret, &isBool), "napi_create_int32");
        CHKRV(env_, napi_set_element(env_, abilityRet, index2, isBool), "napi_set_element");
        CHKRV(env_, napi_set_element(env_, keyAbility, index1, abilityRet), "napi_set_element");
        ++index1;
    }

    napi_value handlerTemp = nullptr;
    CHKRV(env_, napi_get_reference_value(env_, cbTemp.ref, &handlerTemp), "napi_get_reference_value");
    napi_value result = nullptr;
    CHKRV(env_, napi_call_function(env_, nullptr, handlerTemp, 1, &keyAbility, &result), "napi_call_function");
}

void JsEventTarget::EmitJsKeystrokeAbility(int32_t userData, std::vector<int32_t> keystrokeAbility)
{
    CALL_LOG_ENTER;
    if (CheckEnv(env_)) {
        MMI_HILOGE("env_ is nullptr");
        return;
    }
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("Failed to search for userData");
        return;
    }
    iter->second->data.keystrokeAbility = keystrokeAbility;

    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    work->data = static_cast<void*>(iter->second);
    uv_loop_s *loop = nullptr;
    napi_status status = napi_get_uv_event_loop(env_, &loop);
    if (status != napi_ok) {
        MMI_HILOGE("napi_get_uv_event_loop failed");
        return;
    }
    if (iter->second->ref == nullptr) {
        uv_queue_work(loop, work, [](uv_work_t *work){}, CallKeystrokeAbilityPromise);
    } else {
        uv_queue_work(loop, work, [](uv_work_t *work){}, CallKeystrokeAbilityAsync);
    }
}

napi_value JsEventTarget::CreateCallbackInfo(napi_env env, napi_value handle)
{
    CALL_LOG_ENTER;
    env_ = env;
    JsUtil::CallbackInfo* cb = new (std::nothrow) JsUtil::CallbackInfo;
    CHKPP(cb);

    napi_status state = napi_generic_failure;
    if (handle == nullptr) {
        state = napi_create_promise(env_, &cb->deferred, &cb->promise);
        if (state != napi_ok) {
            delete cb;
            cb = nullptr;
            CHKRP(env_, state, "napi_create_reference");
        }
        if (userData_ == INT32_MAX) {
            MMI_HILOGE("userData_ exceeds the maximum");
            return nullptr;
        }
        callback_[userData_] = cb;
        ++userData_;
        return cb->promise;
    }

    state = napi_create_reference(env_, handle, 1, &cb->ref);
    if (state != napi_ok) {
        delete cb;
        cb = nullptr;
        CHKRP(env_, state, "napi_create_reference");
    }
    if (userData_ == INT32_MAX) {
        MMI_HILOGE("userData_ exceeds the maximum");
        return nullptr;
    }
    callback_[userData_] = cb;
    ++userData_;
    return nullptr;
}

void JsEventTarget::ResetEnv()
{
    CALL_LOG_ENTER;
    env_ = nullptr;

    for (auto& item : callback_) {
        if (item.second == nullptr) {
            continue;
        }
        delete item.second;
        item.second = nullptr;
    }
    std::map<int32_t, JsUtil::CallbackInfo*> empty_map;
    callback_.swap(empty_map);
    callback_.clear();
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