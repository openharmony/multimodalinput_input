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
constexpr uint32_t EVDEV_UDEV_TAG_KEYBOARD = (1 << 1);
constexpr uint32_t EVDEV_UDEV_TAG_MOUSE = (1 << 2);
constexpr uint32_t EVDEV_UDEV_TAG_TOUCHPAD = (1 << 3);
constexpr uint32_t EVDEV_UDEV_TAG_TOUCHSCREEN = (1 << 4);
constexpr uint32_t EVDEV_UDEV_TAG_JOYSTICK = (1 << 6);
constexpr uint32_t EVDEV_UDEV_TAG_TRACKBALL = (1 << 10);

const std::string CREATE_ARRAY = "napi_create_array";
const std::string CREATE_INT32 = "napi_create_int32";
const std::string SET_ELEMENT = "napi_set_element";
const std::string SET_NAMED_PROPERTY = "napi_set_named_property";
const std::string CREATE_REFERENCE = "napi_create_reference";
const std::string GET_REFERENCE = "napi_get_reference_value";
const std::string CALL_FUNCTION = "napi_call_function";
const std::string RESOLVE_DEFERRED = "napi_resolve_deferred";
const std::string GET_UV_LOOP = "napi_get_uv_event_loop";
const std::string CREATE_STRING_UTF8 = "napi_create_string_utf8";
const std::string CREATE_OBJECT = "napi_create_object";
const std::string COERCE_TO_BOOL = "napi_coerce_to_bool";
const std::string CREATE_PROMISE = "napi_create_promise";

JsEventTarget::DeviceType g_deviceType[] = {
    {"keyboard", EVDEV_UDEV_TAG_KEYBOARD},
    {"mouse", EVDEV_UDEV_TAG_MOUSE},
    {"touchpad", EVDEV_UDEV_TAG_TOUCHPAD},
    {"touchscreen", EVDEV_UDEV_TAG_TOUCHSCREEN},
    {"joystick", EVDEV_UDEV_TAG_JOYSTICK},
    {"trackball", EVDEV_UDEV_TAG_TRACKBALL},
};

std::mutex mutex_;
} // namespace

void JsEventTarget::CallIdsAsyncWork(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    JsUtil jsUtil;
    int32_t userData = jsUtil.GetUserData(work);
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("find userData failed");
        return;
    }
    auto cbTemp = std::move(iter->second);
    callback_.erase(iter);
    CHKPV(cbTemp->env);

    napi_value arr = nullptr;

    CHKRV(cbTemp->env, napi_create_array(cbTemp->env, &arr), CREATE_ARRAY);
    uint32_t index = 0;
    napi_value value = nullptr;
    for (const auto &item : cbTemp->data.ids) {
        CHKRV(cbTemp->env, napi_create_int32(cbTemp->env, item, &value), CREATE_INT32);
        CHKRV(cbTemp->env, napi_set_element(cbTemp->env, arr, index, value), SET_ELEMENT);
        ++index;
    }

    napi_value handlerTemp = nullptr;
    CHKRV(cbTemp->env, napi_get_reference_value(cbTemp->env, cbTemp->ref, &handlerTemp), GET_REFERENCE);
    napi_value result = nullptr;
    CHKRV(cbTemp->env, napi_call_function(cbTemp->env, nullptr, handlerTemp, 1, &arr, &result), CALL_FUNCTION);
}

void JsEventTarget::CallIdsPromiseWork(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    JsUtil jsUtil;
    int32_t userData = jsUtil.GetUserData(work);
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("find userData failed");
        return;
    }
    auto cbTemp = std::move(iter->second);
    callback_.erase(iter);
    CHKPV(cbTemp->env);

    napi_value arr = nullptr;
    CHKRV(cbTemp->env, napi_create_array(cbTemp->env, &arr), CREATE_ARRAY);
    uint32_t index = 0;
    napi_value value = nullptr;
    for (const auto &item : cbTemp->data.ids) {
        CHKRV(cbTemp->env, napi_create_int32(cbTemp->env, item, &value), CREATE_INT32);
        CHKRV(cbTemp->env, napi_set_element(cbTemp->env, arr, index, value), SET_ELEMENT);
        ++index;
    }
    CHKRV(cbTemp->env, napi_resolve_deferred(cbTemp->env, cbTemp->deferred, arr), RESOLVE_DEFERRED);
}

void JsEventTarget::EmitJsIds(int32_t userData, std::vector<int32_t> ids)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("Failed to search for userData");
        return;
    }
    CHKPV(iter->second);
    if (iter->second->env == nullptr) {
        callback_.erase(iter);
        MMI_HILOGE("env is nullptr");
    }

    iter->second->data.ids = ids;
    uv_loop_s *loop = nullptr;
    CHKRV(iter->second->env, napi_get_uv_event_loop(iter->second->env, &loop), GET_UV_LOOP);
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    int32_t *uData = new (std::nothrow) int32_t(userData);
    CHKPV(uData);
    work->data = static_cast<void*>(uData);
    int32_t ret;
    if (iter->second->ref == nullptr) {
        ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallIdsPromiseWork);
    } else {
        ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallIdsAsyncWork);
    }
    if (ret != 0) {
        delete work;
        work = nullptr;
        delete uData;
        uData = nullptr;
        MMI_HILOGE("uv_queue_work failed");
        return;
    }
}

void JsEventTarget::CallDevAsyncWork(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    JsUtil jsUtil;
    int32_t userData = jsUtil.GetUserData(work);
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("find userData failed");
        return;
    }
    auto cbTemp = std::move(iter->second);
    callback_.erase(iter);
    CHKPV(cbTemp->env);

    napi_value id = nullptr;
    CHKRV(cbTemp->env, napi_create_int32(cbTemp->env, cbTemp->data.device->id, &id), CREATE_INT32);
    napi_value name = nullptr;
    CHKRV(cbTemp->env, napi_create_string_utf8(cbTemp->env, (cbTemp->data.device->name).c_str(),
        NAPI_AUTO_LENGTH, &name), CREATE_STRING_UTF8);

    napi_value object = nullptr;
    CHKRV(cbTemp->env, napi_create_object(cbTemp->env, &object), CREATE_OBJECT);
    CHKRV(cbTemp->env, napi_set_named_property(cbTemp->env, object, "id", id), SET_NAMED_PROPERTY);
    CHKRV(cbTemp->env, napi_set_named_property(cbTemp->env, object, "name", name), SET_NAMED_PROPERTY);

    uint32_t types = cbTemp->data.device->devcieType;
    std::vector<std::string> sources;
    for (const auto & item : g_deviceType) {
        if (types & item.typeBit) {
            sources.push_back(item.deviceTypeName);
        }
    }
    napi_value devSources = nullptr;
    CHKRV(cbTemp->env, napi_create_array(cbTemp->env, &devSources), CREATE_ARRAY);
    uint32_t index = 0;
    napi_value value = nullptr;
    for (const auto &item : sources) {
        CHKRV(cbTemp->env, napi_create_string_utf8(cbTemp->env, item.c_str(), NAPI_AUTO_LENGTH, &value),
            CREATE_STRING_UTF8);
        CHKRV(cbTemp->env, napi_set_element(cbTemp->env, devSources, index, value), SET_ELEMENT);
    }
    CHKRV(cbTemp->env, napi_set_named_property(cbTemp->env, object, "sources", devSources), SET_NAMED_PROPERTY);

    napi_value axisRanges = nullptr;
    CHKRV(cbTemp->env, napi_create_array(cbTemp->env, &axisRanges), CREATE_ARRAY);
    CHKRV(cbTemp->env, napi_set_named_property(cbTemp->env, object, "axisRanges", axisRanges), SET_NAMED_PROPERTY);

    napi_value handlerTemp = nullptr;
    CHKRV(cbTemp->env, napi_get_reference_value(cbTemp->env, cbTemp->ref, &handlerTemp), GET_REFERENCE);
    napi_value result = nullptr;
    CHKRV(cbTemp->env, napi_call_function(cbTemp->env, nullptr, handlerTemp, 1, &object, &result), CALL_FUNCTION);
}

void JsEventTarget::CallDevPromiseWork(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    JsUtil jsUtil;
    int32_t userData = jsUtil.GetUserData(work);
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("find userData failed");
        return;
    }
    auto cbTemp = std::move(iter->second);
    callback_.erase(iter);
    CHKPV(cbTemp->env);

    napi_value id = nullptr;
    CHKRV(cbTemp->env, napi_create_int32(cbTemp->env, cbTemp->data.device->id, &id), CREATE_INT32);
    napi_value name = nullptr;
    CHKRV(cbTemp->env, napi_create_string_utf8(cbTemp->env, (cbTemp->data.device->name).c_str(),
        NAPI_AUTO_LENGTH, &name), CREATE_STRING_UTF8);
    napi_value object = nullptr;
    CHKRV(cbTemp->env, napi_create_object(cbTemp->env, &object), CREATE_OBJECT);
    CHKRV(cbTemp->env, napi_set_named_property(cbTemp->env, object, "id", id), SET_NAMED_PROPERTY);
    CHKRV(cbTemp->env, napi_set_named_property(cbTemp->env, object, "name", name), SET_NAMED_PROPERTY);

    uint32_t types = cbTemp->data.device->devcieType;
    if (types == 0) {
        MMI_HILOGE("types is wrong");
        return;
    }
    std::vector<std::string> sources;
    for (const auto & item : g_deviceType) {
        if (types & item.typeBit) {
            sources.push_back(item.deviceTypeName);
        }
    }
    napi_value devSources = nullptr;
    CHKRV(cbTemp->env, napi_create_array(cbTemp->env, &devSources), CREATE_ARRAY);

    uint32_t index = 0;
    napi_value value = nullptr;
    for (const auto &item : sources) {
        CHKRV(cbTemp->env, napi_create_string_utf8(cbTemp->env, item.c_str(), NAPI_AUTO_LENGTH, &value),
              CREATE_STRING_UTF8);
        CHKRV(cbTemp->env, napi_set_element(cbTemp->env, devSources, index, value), SET_ELEMENT);
    }
    CHKRV(cbTemp->env, napi_set_named_property(cbTemp->env, object, "sources", devSources), SET_NAMED_PROPERTY);

    napi_value axisRanges = nullptr;
    CHKRV(cbTemp->env, napi_create_array(cbTemp->env, &axisRanges), CREATE_ARRAY);
    CHKRV(cbTemp->env, napi_set_named_property(cbTemp->env, object, "axisRanges", axisRanges), SET_NAMED_PROPERTY);
    CHKRV(cbTemp->env, napi_resolve_deferred(cbTemp->env, cbTemp->deferred, object), RESOLVE_DEFERRED);
}

void JsEventTarget::EmitJsDev(int32_t userData, std::shared_ptr<InputDeviceImpl::InputDeviceInfo> device)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    CHKPV(device);
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("failed to search for userData");
        return;
    }
    CHKPV(iter->second);
    if (iter->second->env == nullptr) {
        callback_.erase(iter);
        MMI_HILOGE("env is nullptr");
    }

    iter->second->data.device = device;
    uv_loop_s *loop = nullptr;
    CHKRV(iter->second->env, napi_get_uv_event_loop(iter->second->env, &loop), GET_UV_LOOP);
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    int32_t *uData = new (std::nothrow) int32_t(userData);
    work->data = static_cast<void*>(uData);
    int32_t ret;
    if (iter->second->ref == nullptr) {
        ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallDevPromiseWork);
    } else {
        ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallDevAsyncWork);
    }
    if (ret != 0) {
        delete work;
        work = nullptr;
        delete uData;
        uData = nullptr;
        MMI_HILOGE("uv_queue_work failed");
        return;
    }
}

void JsEventTarget::CallKeystrokeAbilityPromise(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    JsUtil jsUtil;
    int32_t userData = jsUtil.GetUserData(work);
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("find userData failed");
        return;
    }
    auto cbTemp = std::move(iter->second);
    callback_.erase(iter);
    CHKPV(cbTemp->env);

    napi_value keyAbility = nullptr;
    CHKRV(cbTemp->env, napi_create_array(cbTemp->env, &keyAbility), CREATE_ARRAY);
    napi_value keyCode = nullptr;
    napi_value ret = nullptr;
    napi_value isSupport = nullptr;
    uint32_t i = 0;
    for (auto it = cbTemp->data.keystrokeAbility.begin(); it != cbTemp->data.keystrokeAbility.end(); ++it) {
        napi_value abilityRet = nullptr;
        CHKRV(cbTemp->env, napi_create_array(cbTemp->env, &abilityRet), CREATE_ARRAY);
        uint32_t j = 0;
        CHKRV(cbTemp->env, napi_create_int32(cbTemp->env, *it, &keyCode), CREATE_INT32);
        CHKRV(cbTemp->env, napi_set_element(cbTemp->env, abilityRet, j, keyCode), SET_ELEMENT);
        ++j;
        CHKRV(cbTemp->env, napi_create_int32(cbTemp->env, *(++it), &ret), CREATE_INT32);
        CHKRV(cbTemp->env, napi_coerce_to_bool(cbTemp->env, ret, &isSupport), COERCE_TO_BOOL);
        CHKRV(cbTemp->env, napi_set_element(cbTemp->env, abilityRet, j, isSupport), SET_ELEMENT);
        CHKRV(cbTemp->env, napi_set_element(cbTemp->env, keyAbility, i, abilityRet), SET_ELEMENT);
        ++i;
    }
    CHKRV(cbTemp->env, napi_resolve_deferred(cbTemp->env, cbTemp->deferred, keyAbility), RESOLVE_DEFERRED);
}

void JsEventTarget::CallKeystrokeAbilityAsync(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    JsUtil jsUtil;
    int32_t userData = jsUtil.GetUserData(work);
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("find userData failed");
        return;
    }
    auto cbTemp = std::move(iter->second);
    callback_.erase(iter);
    CHKPV(cbTemp->env);

    napi_value keyAbility = nullptr;
    CHKRV(cbTemp->env, napi_create_array(cbTemp->env, &keyAbility), CREATE_ARRAY);
    napi_value keyCode = nullptr;
    napi_value ret = nullptr;
    napi_value isSupport = nullptr;
    uint32_t i = 0;
    for (auto it = cbTemp->data.keystrokeAbility.begin(); it != cbTemp->data.keystrokeAbility.end(); ++it) {
        napi_value abilityRet = nullptr;
        CHKRV(cbTemp->env, napi_create_array(cbTemp->env, &abilityRet), CREATE_ARRAY);
        uint32_t j = 0;
        CHKRV(cbTemp->env, napi_create_int32(cbTemp->env, *it, &keyCode), CREATE_INT32);
        CHKRV(cbTemp->env, napi_set_element(cbTemp->env, abilityRet, j, keyCode), SET_ELEMENT);
        ++j;
        CHKRV(cbTemp->env, napi_create_int32(cbTemp->env, *(++it), &ret), CREATE_INT32);
        CHKRV(cbTemp->env, napi_coerce_to_bool(cbTemp->env, ret, &isSupport), COERCE_TO_BOOL);
        CHKRV(cbTemp->env, napi_set_element(cbTemp->env, abilityRet, j, isSupport), SET_ELEMENT);
        CHKRV(cbTemp->env, napi_set_element(cbTemp->env, keyAbility, i, abilityRet), SET_ELEMENT);
        ++i;
    }

    napi_value handlerTemp = nullptr;
    CHKRV(cbTemp->env, napi_get_reference_value(cbTemp->env, cbTemp->ref, &handlerTemp),
          GET_REFERENCE);
    napi_value result = nullptr;
    CHKRV(cbTemp->env, napi_call_function(cbTemp->env, nullptr, handlerTemp, 1, &keyAbility, &result),
          CALL_FUNCTION);
}

void JsEventTarget::EmitJsKeystrokeAbility(int32_t userData, std::vector<int32_t> keystrokeAbility)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("Failed to search for userData");
        return;
    }
    CHKPV(iter->second);
    if (iter->second->env == nullptr) {
        callback_.erase(iter);
        MMI_HILOGE("env is nullptr");
    }

    iter->second->data.keystrokeAbility = keystrokeAbility;
    uv_loop_s *loop = nullptr;
    CHKRV(iter->second->env, napi_get_uv_event_loop(iter->second->env, &loop), GET_UV_LOOP);
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    int32_t *uData = new (std::nothrow) int32_t(userData);
    work->data = static_cast<void*>(uData);
    int32_t ret;
    if (iter->second->ref == nullptr) {
        ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallKeystrokeAbilityPromise);
    } else {
        ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallKeystrokeAbilityAsync);
    }
    if (ret != 0) {
        delete work;
        work = nullptr;
        delete uData;
        uData = nullptr;
        MMI_HILOGE("uv_queue_work failed");
        return;
    }
}

napi_value JsEventTarget::CreateCallbackInfo(napi_env env, napi_value handle)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto cb = std::make_unique<JsUtil::CallbackInfo>();
    CHKPP(cb);
    cb->env = env;
    if (handle == nullptr) {
        napi_value promise = nullptr;
        CHKRP(env, napi_create_promise(env, &cb->deferred, &promise), CREATE_PROMISE);
        if (userData_ == INT32_MAX) {
            MMI_HILOGE("userData_ exceeds the maximum");
            return nullptr;
        }
        callback_.emplace(userData_, std::move(cb));
        ++userData_;
        return promise;
    }

    CHKRP(env, napi_create_reference(env, handle, 1, &cb->ref), CREATE_REFERENCE);
    if (userData_ == INT32_MAX) {
        MMI_HILOGE("userData_ exceeds the maximum");
        return nullptr;
    }
    callback_.emplace(userData_, std::move(cb));
    ++userData_;
    return nullptr;
}

void JsEventTarget::ResetEnv()
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    for (auto &item : callback_) {
        CHKPC(item.second);
        CHKPC(item.second->env);
        item.second->env = nullptr;
    }
    callback_.clear();
}
} // namespace MMI
} // namespace OHOS