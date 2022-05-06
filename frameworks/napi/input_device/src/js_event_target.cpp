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

std::mutex mutex_;
const std::string CHANGED_TYPE = "changed";
const std::string ADD_EVENT = "add";
const std::string REMOVE_EVENT = "remove";
} // namespace

JsEventTarget::JsEventTarget()
{
    CALL_LOG_ENTER;
    auto ret = devMonitor_.insert({ CHANGED_TYPE, std::vector<std::unique_ptr<JsUtil::CallbackInfo>>() });
    CK(ret.second, VAL_NOT_EXP);
}

JsEventTarget::~JsEventTarget() {}

void JsEventTarget::EmitAddedDeviceEvent(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    CHKPV(work);
    CHKPV(work->data);
    auto temp = static_cast<std::unique_ptr<JsUtil::CallbackInfo>*>(work->data);
    delete work;
    
    auto addEvent = devMonitor_.find(CHANGED_TYPE);
    if (addEvent == devMonitor_.end()) {
        MMI_HILOGE("find changed event failed");
        return;
    }

    for (const auto &item : addEvent->second) {
        CHKPC(item->env);
        if (item->ref != (*temp)->ref) {
            continue;
        }
        napi_value eventType = nullptr;
        CHKRV(item->env, napi_create_string_utf8(item->env, ADD_EVENT.c_str(), NAPI_AUTO_LENGTH, &eventType),
             CREATE_STRING_UTF8);
        napi_value deviceId = nullptr;
        CHKRV(item->env, napi_create_int32(item->env, item->data.deviceId, &deviceId), CREATE_INT32);
        napi_value object = nullptr;
        CHKRV(item->env, napi_create_object(item->env, &object), CREATE_OBJECT);
        CHKRV(item->env, napi_set_named_property(item->env, object, "type", eventType), SET_NAMED_PROPERTY);
        CHKRV(item->env, napi_set_named_property(item->env, object, "deviceId", deviceId), SET_NAMED_PROPERTY);

        napi_value handler = nullptr;
        CHKRV(item->env, napi_get_reference_value(item->env, item->ref, &handler), GET_REFERENCE);
        napi_value ret = nullptr;
        CHKRV(item->env, napi_call_function(item->env, nullptr, handler, 1, &object, &ret), CALL_FUNCTION);
    }
}

void JsEventTarget::EmitRemoveDeviceEvent(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    CHKPV(work);
    CHKPV(work->data);
    auto temp = static_cast<std::unique_ptr<JsUtil::CallbackInfo>*>(work->data);
    delete work;
    
    auto removeEvent = devMonitor_.find(CHANGED_TYPE);
    if (removeEvent == devMonitor_.end()) {
        MMI_HILOGE("find changed event failed");
        return;
    }

    for (const auto &item : removeEvent->second) {
        CHKPC(item->env);
        if (item->ref != (*temp)->ref) {
            continue;
        }
        napi_value eventType = nullptr;
        CHKRV(item->env, napi_create_string_utf8(item->env, REMOVE_EVENT.c_str(), NAPI_AUTO_LENGTH, &eventType),
             CREATE_STRING_UTF8);
        napi_value deviceId = nullptr;
        CHKRV(item->env, napi_create_int32(item->env, item->data.deviceId, &deviceId), CREATE_INT32);
        napi_value object = nullptr;
        CHKRV(item->env, napi_create_object(item->env, &object), CREATE_OBJECT);
        CHKRV(item->env, napi_set_named_property(item->env, object, "type", eventType), SET_NAMED_PROPERTY);
        CHKRV(item->env, napi_set_named_property(item->env, object, "deviceId", deviceId), SET_NAMED_PROPERTY);

        napi_value handler = nullptr;
        CHKRV(item->env, napi_get_reference_value(item->env, item->ref, &handler), GET_REFERENCE);
        napi_value ret = nullptr;
        CHKRV(item->env, napi_call_function(item->env, nullptr, handler, 1, &object, &ret), CALL_FUNCTION);
    }
}

void JsEventTarget::TargetOn(std::string type, int32_t deviceId)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = devMonitor_.find(CHANGED_TYPE);
    if (iter == devMonitor_.end()) {
        MMI_HILOGE("find %{public}s failed", CHANGED_TYPE.c_str());
        return;
    }

    for (auto & item : iter->second) {
        CHKPC(item);
        CHKPC(item->env);
        uv_loop_s *loop = nullptr;
        CHKRV(item->env, napi_get_uv_event_loop(item->env, &loop), GET_UV_LOOP);
        uv_work_t *work = new (std::nothrow) uv_work_t;
        CHKPV(work);
        item->data.deviceId = deviceId;
        work->data = static_cast<void*>(&item);
        int32_t ret = 0;
        if (type == ADD_EVENT) {
            ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, EmitAddedDeviceEvent);
        } else if (type == REMOVE_EVENT) {
            ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, EmitRemoveDeviceEvent);
        } else {
            MMI_HILOGE("%{public}s is wrong", type.c_str());
        }
        if (ret != 0) {
            delete work;
            MMI_HILOGE("uv_queue_work failed");
            return;
        }
    }
}

void JsEventTarget::CallIdsAsyncWork(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);

    napi_value arr = nullptr;
    CHKRV(cb->env, napi_create_array(cb->env, &arr), CREATE_ARRAY);
    uint32_t index = 0;
    napi_value value = nullptr;
    for (const auto &item : cb->data.ids) {
        CHKRV(cb->env, napi_create_int32(cb->env, item, &value), CREATE_INT32);
        CHKRV(cb->env, napi_set_element(cb->env, arr, index, value), SET_ELEMENT);
        ++index;
    }

    napi_value handler = nullptr;
    CHKRV(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE);
    napi_value result = nullptr;
    CHKRV(cb->env, napi_call_function(cb->env, nullptr, handler, 1, &arr, &result), CALL_FUNCTION);
}

void JsEventTarget::CallIdsPromiseWork(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);

    napi_value arr = nullptr;
    CHKRV(cb->env, napi_create_array(cb->env, &arr), CREATE_ARRAY);
    uint32_t index = 0;
    napi_value value = nullptr;
    for (const auto &item : cb->data.ids) {
        CHKRV(cb->env, napi_create_int32(cb->env, item, &value), CREATE_INT32);
        CHKRV(cb->env, napi_set_element(cb->env, arr, index, value), SET_ELEMENT);
        ++index;
    }
    CHKRV(cb->env, napi_resolve_deferred(cb->env, cb->deferred, arr), RESOLVE_DEFERRED);
}

void JsEventTarget::EmitJsIds(int32_t userData, std::vector<int32_t> &ids)
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
        return;
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
        delete uData;
        MMI_HILOGE("uv_queue_work failed");
        return;
    }
}

void JsEventTarget::CallDevAsyncWork(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);

    napi_value object = JsUtil::GetDeviceInfo(cb);
    CHKPV(object);
    napi_value handler = nullptr;
    CHKRV(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE);
    napi_value result = nullptr;
    CHKRV(cb->env, napi_call_function(cb->env, nullptr, handler, 1, &object, &result), CALL_FUNCTION);
}

void JsEventTarget::CallDevPromiseWork(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);

    napi_value object = JsUtil::GetDeviceInfo(cb);
    CHKPV(object);
    CHKRV(cb->env, napi_resolve_deferred(cb->env, cb->deferred, object), RESOLVE_DEFERRED);
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
        return;
    }

    iter->second->data.device = device;
    uv_loop_s *loop = nullptr;
    CHKRV(iter->second->env, napi_get_uv_event_loop(iter->second->env, &loop), GET_UV_LOOP);
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    int32_t *uData = new (std::nothrow) int32_t(userData);
    CHKPV(uData);
    work->data = static_cast<void*>(uData);
    int32_t ret;
    if (iter->second->ref == nullptr) {
        ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallDevPromiseWork);
    } else {
        ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallDevAsyncWork);
    }
    if (ret != 0) {
        delete work;
        delete uData;
        MMI_HILOGE("uv_queue_work failed");
        return;
    }
}

void JsEventTarget::CallKeystrokeAbilityPromise(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);

    napi_value keyAbility = nullptr;
    CHKRV(cb->env, napi_create_array(cb->env, &keyAbility), CREATE_ARRAY);
    for (size_t i = 0; i < cb->data.keystrokeAbility.size(); ++i) {
        napi_value ret = nullptr;
        napi_value isSupport = nullptr;
        CHKRV(cb->env, napi_create_int32(cb->env, cb->data.keystrokeAbility[i] ? 1 : 0, &ret),
            CREATE_INT32);
        CHKRV(cb->env, napi_coerce_to_bool(cb->env, ret, &isSupport), COERCE_TO_BOOL);
        CHKRV(cb->env, napi_set_element(cb->env, keyAbility, static_cast<uint32_t>(i), isSupport),
            SET_ELEMENT);
    }
    CHKRV(cb->env, napi_resolve_deferred(cb->env, cb->deferred, keyAbility), RESOLVE_DEFERRED);
}

void JsEventTarget::CallKeystrokeAbilityAsync(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);

    napi_value keyAbility = nullptr;
    CHKRV(cb->env, napi_create_array(cb->env, &keyAbility), CREATE_ARRAY);
    for (size_t i = 0; i < cb->data.keystrokeAbility.size(); ++i) {
        napi_value ret = nullptr;
        napi_value isSupport = nullptr;
        CHKRV(cb->env, napi_create_int32(cb->env, cb->data.keystrokeAbility[i] ? 1 : 0, &ret),
            CREATE_INT32);
        CHKRV(cb->env, napi_coerce_to_bool(cb->env, ret, &isSupport), COERCE_TO_BOOL);
        CHKRV(cb->env, napi_set_element(cb->env, keyAbility, static_cast<uint32_t>(i), isSupport),
            SET_ELEMENT);
    }

    napi_value handler = nullptr;
    CHKRV(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler),
          GET_REFERENCE);
    napi_value result = nullptr;
    CHKRV(cb->env, napi_call_function(cb->env, nullptr, handler, 1, &keyAbility, &result),
          CALL_FUNCTION);
}

void JsEventTarget::EmitJsKeystrokeAbility(int32_t userData, std::vector<bool> &keystrokeAbility)
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
        return;
    }

    iter->second->data.keystrokeAbility = keystrokeAbility;
    uv_loop_s *loop = nullptr;
    CHKRV(iter->second->env, napi_get_uv_event_loop(iter->second->env, &loop), GET_UV_LOOP);
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    int32_t *uData = new (std::nothrow) int32_t(userData);
    CHKPV(uData);
    work->data = static_cast<void*>(uData);
    int32_t ret;
    if (iter->second->ref == nullptr) {
        ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallKeystrokeAbilityPromise);
    } else {
        ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallKeystrokeAbilityAsync);
    }
    if (ret != 0) {
        delete work;
        delete uData;
        MMI_HILOGE("uv_queue_work failed");
        return;
    }
}

void JsEventTarget::EmitJsKeyboardType(int32_t userData, int32_t keyboardType)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("failed to search for userData");
        return;
    }
    CHKPV(iter->second);
    if (iter->second->env == nullptr) {
        callback_.erase(iter);
        MMI_HILOGE("env is nullptr");
        return;
    }
    iter->second->data.keyboardType = keyboardType;

    uv_loop_s *loop = nullptr;
    CHKRV(iter->second->env, napi_get_uv_event_loop(iter->second->env, &loop), GET_UV_LOOP);

    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    int32_t *uData = new (std::nothrow) int32_t(userData);
    CHKPV(uData);
    work->data = static_cast<void*>(uData);
    int32_t ret = 0;
    if (iter->second->ref == nullptr) {
        ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallKeyboardTypePromise);
    } else {
        ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallKeyboardTypeAsync);
    }
    if (ret != 0) {
        delete work;
        delete uData;
        MMI_HILOGE("uv_queue_work failed");
        return;
    }
}

void JsEventTarget::CallKeyboardTypeAsync(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);

    napi_value keyboardType = nullptr;
    CHKRV(cb->env, napi_create_int32(cb->env, cb->data.keyboardType, &keyboardType), CREATE_INT32);
    napi_value handler = nullptr;
    CHKRV(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE);
    napi_value result = nullptr;
    CHKRV(cb->env, napi_call_function(cb->env, nullptr, handler, 1, &keyboardType, &result), CALL_FUNCTION);
}

void JsEventTarget::CallKeyboardTypePromise(uv_work_t *work, int32_t status)
{
    CALL_LOG_ENTER;
    CHKPV(work);
    CHKPV(work->data);
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);

    napi_value keyboardType = nullptr;
    CHKRV(cb->env, napi_create_int32(cb->env, cb->data.keyboardType, &keyboardType), CREATE_INT32);
    CHKRV(cb->env, napi_resolve_deferred(cb->env, cb->deferred, keyboardType), RESOLVE_DEFERRED);
}

void JsEventTarget::AddMonitor(napi_env env, std::string type, napi_value handle)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = devMonitor_.find(type);
    if (iter == devMonitor_.end()) {
        MMI_HILOGE("find %{public}s failed", type.c_str());
        return;
    }

    for (const auto &temp : iter->second) {
        CHKPC(temp);
        if (JsUtil::IsSameHandle(env, handle, temp->ref)) {
            MMI_HILOGW("handle already exists");
            return;
        }
    }
    napi_ref ref = nullptr;
    CHKRV(env, napi_create_reference(env, handle, 1, &ref), CREATE_REFERENCE);
    auto monitor = std::make_unique<JsUtil::CallbackInfo>();
    CHKPV(monitor);
    monitor->env = env;
    monitor->ref = ref;
    iter->second.push_back(std::move(monitor));
    if (!isMonitorProcess_) {
        isMonitorProcess_ = true;
        InputDevImpl.RegisterInputDeviceMonitor(TargetOn);
    }
}

void JsEventTarget::RemoveMonitor(napi_env env, std::string type, napi_value handle)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = devMonitor_.find(type);
    if (iter == devMonitor_.end()) {
        MMI_HILOGE("find %{public}s failed", type.c_str());
        return;
    }
    if (handle == nullptr) {
        iter->second.clear();
        goto monitorLabel;
    }
    for (auto it = iter->second.begin(); it != iter->second.end(); ++it) {
        if (JsUtil::IsSameHandle(env, handle, (*it)->ref)) {
            MMI_HILOGD("succeeded in removing monitor");
            iter->second.erase(it);
            goto monitorLabel;
        }
    }

monitorLabel:
    if (isMonitorProcess_ && iter->second.empty()) {
        isMonitorProcess_ = false;
        InputDevImpl.UnRegisterInputDeviceMonitor();
    }
}

napi_value JsEventTarget::CreateCallbackInfo(napi_env env, napi_value handle, const int32_t userData)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto cb = std::make_unique<JsUtil::CallbackInfo>();
    CHKPP(cb);
    cb->env = env;
    if (handle == nullptr) {
        napi_value promise = nullptr;
        CHKRP(env, napi_create_promise(env, &cb->deferred, &promise), CREATE_PROMISE);
        callback_.emplace(userData, std::move(cb));
        return promise;
    }

    CHKRP(env, napi_create_reference(env, handle, 1, &cb->ref), CREATE_REFERENCE);
    callback_.emplace(userData, std::move(cb));
    return nullptr;
}

std::unique_ptr<JsUtil::CallbackInfo> JsEventTarget::GetCallbackInfo(uv_work_t *work)
{
    std::lock_guard<std::mutex> guard(mutex_);
    int32_t *uData = static_cast<int32_t*>(work->data);
    int32_t userData = *uData;
    delete uData;
    delete work;

    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("find userData failed");
        return nullptr;
    }
    auto cb = std::move(iter->second);
    callback_.erase(iter);
    return cb;
}

void JsEventTarget::ResetEnv()
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    callback_.clear();
    devMonitor_.clear();
    InputDevImpl.UnRegisterInputDeviceMonitor();
}
} // namespace MMI
} // namespace OHOS