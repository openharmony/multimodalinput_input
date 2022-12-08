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

#include "napi_constants.h"
#include "util_napi_error.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsEventTarget" };

std::mutex mutex_;
const std::string ADD_EVENT = "add";
const std::string REMOVE_EVENT = "remove";
} // namespace

JsEventTarget::JsEventTarget()
{
    CALL_DEBUG_ENTER;
    auto ret = devListener_.insert({ CHANGED_TYPE, std::vector<std::unique_ptr<JsUtil::CallbackInfo>>() });
    CK(ret.second, VAL_NOT_EXP);
}

JsEventTarget::~JsEventTarget() {}

void JsEventTarget::EmitAddedDeviceEvent(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is null");
        return;
    }
    auto temp = static_cast<std::unique_ptr<JsUtil::CallbackInfo>*>(work->data);
    JsUtil::DeletePtr<uv_work_t*>(work);
    auto addEvent = devListener_.find(CHANGED_TYPE);
    if (addEvent == devListener_.end()) {
        MMI_HILOGE("Find change event failed");
        return;
    }

    for (const auto &item : addEvent->second) {
        CHKPC(item->env);
        if (item->ref != (*temp)->ref) {
            continue;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(item->env, &scope);
        if (scope == nullptr) {
            MMI_HILOGE("scope is nullptr");
            return;
        }
        napi_value eventType = nullptr;
        CHKRV_SCOPE(item->env, napi_create_string_utf8(item->env, ADD_EVENT.c_str(), NAPI_AUTO_LENGTH, &eventType),
                CREATE_STRING_UTF8, scope);
        napi_value deviceId = nullptr;
        CHKRV_SCOPE(item->env, napi_create_int32(item->env, item->data.deviceId, &deviceId), CREATE_INT32, scope);
        napi_value object = nullptr;
        CHKRV_SCOPE(item->env, napi_create_object(item->env, &object), CREATE_OBJECT, scope);
        CHKRV_SCOPE(item->env, napi_set_named_property(item->env, object, "type", eventType),
                SET_NAMED_PROPERTY, scope);
        CHKRV_SCOPE(item->env, napi_set_named_property(item->env, object, "deviceId", deviceId),
                SET_NAMED_PROPERTY, scope);
        napi_value handler = nullptr;
        CHKRV_SCOPE(item->env, napi_get_reference_value(item->env, item->ref, &handler), GET_REFERENCE, scope);
        napi_value ret = nullptr;
        CHKRV_SCOPE(item->env, napi_call_function(item->env, nullptr, handler, 1, &object, &ret),
                CALL_FUNCTION, scope);
        napi_close_handle_scope(item->env, scope);
    }
}

void JsEventTarget::EmitRemoveDeviceEvent(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is null");
        return;
    }
    auto temp = static_cast<std::unique_ptr<JsUtil::CallbackInfo>*>(work->data);
    JsUtil::DeletePtr<uv_work_t*>(work);
    auto removeEvent = devListener_.find(CHANGED_TYPE);
    if (removeEvent == devListener_.end()) {
        MMI_HILOGE("Find change event failed");
        return;
    }

    for (const auto &item : removeEvent->second) {
        CHKPC(item->env);
        if (item->ref != (*temp)->ref) {
            continue;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(item->env, &scope);
        if (scope == nullptr) {
            MMI_HILOGE("scope is nullptr");
            return;
        }
        napi_value eventType = nullptr;
        CHKRV_SCOPE(item->env, napi_create_string_utf8(item->env, REMOVE_EVENT.c_str(), NAPI_AUTO_LENGTH,
             &eventType),
             CREATE_STRING_UTF8, scope);

        napi_value deviceId = nullptr;
        CHKRV_SCOPE(item->env, napi_create_int32(item->env, item->data.deviceId, &deviceId),
             CREATE_INT32, scope);
        
        napi_value object = nullptr;
        CHKRV_SCOPE(item->env, napi_create_object(item->env, &object), CREATE_OBJECT, scope);
        CHKRV_SCOPE(item->env, napi_set_named_property(item->env, object, "type", eventType),
             SET_NAMED_PROPERTY, scope);
        CHKRV_SCOPE(item->env, napi_set_named_property(item->env, object, "deviceId", deviceId),
             SET_NAMED_PROPERTY, scope);

        napi_value handler = nullptr;
        CHKRV_SCOPE(item->env, napi_get_reference_value(item->env, item->ref, &handler), GET_REFERENCE, scope);

        napi_value ret = nullptr;
        CHKRV_SCOPE(item->env, napi_call_function(item->env, nullptr, handler, 1, &object, &ret),
             CALL_FUNCTION, scope);
        napi_close_handle_scope(item->env, scope);
    }
}

void JsEventTarget::OnDeviceAdded(int32_t deviceId, const std::string &type)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto changeEvent = devListener_.find(CHANGED_TYPE);
    if (changeEvent == devListener_.end()) {
        MMI_HILOGE("Find %{public}s failed", CHANGED_TYPE.c_str());
        return;
    }

    for (auto &item : changeEvent->second) {
        CHKPC(item);
        CHKPC(item->env);
        uv_loop_s *loop = nullptr;
        CHKRV(item->env, napi_get_uv_event_loop(item->env, &loop), GET_UV_LOOP);
        uv_work_t *work = new (std::nothrow) uv_work_t;
        CHKPV(work);
        item->data.deviceId = deviceId;
        work->data = static_cast<void*>(&item);
        int32_t ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, EmitAddedDeviceEvent);
        if (ret != 0) {
            MMI_HILOGE("uv_queue_work failed");
            JsUtil::DeletePtr<uv_work_t*>(work);
            return;
        }
    }
}

void JsEventTarget::OnDeviceRemoved(int32_t deviceId, const std::string &type)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto changeEvent = devListener_.find(CHANGED_TYPE);
    if (changeEvent == devListener_.end()) {
        MMI_HILOGE("Find %{public}s failed", CHANGED_TYPE.c_str());
        return;
    }
    for (auto &item : changeEvent->second) {
        CHKPC(item);
        CHKPC(item->env);
        uv_loop_s *loop = nullptr;
        CHKRV(item->env, napi_get_uv_event_loop(item->env, &loop), GET_UV_LOOP);
        uv_work_t *work = new (std::nothrow) uv_work_t;
        CHKPV(work);
        item->data.deviceId = deviceId;
        work->data = static_cast<void*>(&item);
        int32_t ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, EmitRemoveDeviceEvent);
        if (ret != 0) {
            MMI_HILOGE("uv_queue_work failed");
            JsUtil::DeletePtr<uv_work_t*>(work);
            return;
        }
    }
}

void JsEventTarget::CallIdsAsyncWork(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is null");
        return;
    }
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        MMI_HILOGE("scope is nullptr");
        return;
    }
    napi_value arr[2];
    CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &arr[0]), GET_UNDEFINED, scope);
    CHKRV_SCOPE(cb->env, napi_create_array(cb->env, &arr[1]), CREATE_ARRAY, scope);
    uint32_t index = 0;
    napi_value value = nullptr;
    for (const auto &item : cb->data.ids) {
        CHKRV_SCOPE(cb->env, napi_create_int32(cb->env, item, &value), CREATE_INT32, scope);
        CHKRV_SCOPE(cb->env, napi_set_element(cb->env, arr[1], index, value), SET_ELEMENT, scope);
        ++index;
    }

    napi_value handler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, handler, 2, arr, &result), CALL_FUNCTION, scope);
    napi_close_handle_scope(cb->env, scope);
    JsUtil::DeleteCallbackInfo(std::move(cb));
}

void JsEventTarget::CallIdsPromiseWork(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is null");
        return;
    }
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        MMI_HILOGE("scope is nullptr");
        return;
    }
    napi_value arr = nullptr;
    CHKRV_SCOPE(cb->env, napi_create_array(cb->env, &arr), CREATE_ARRAY, scope);
    uint32_t index = 0;
    napi_value value = nullptr;
    for (const auto &item : cb->data.ids) {
        CHKRV_SCOPE(cb->env, napi_create_int32(cb->env, item, &value), CREATE_INT32, scope);
        CHKRV_SCOPE(cb->env, napi_set_element(cb->env, arr, index, value), SET_ELEMENT, scope);
        ++index;
    }
    CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, arr), RESOLVE_DEFERRED, scope);
    napi_close_handle_scope(cb->env, scope);
    JsUtil::DeleteCallbackInfo(std::move(cb));
}

void JsEventTarget::EmitJsIds(int32_t userData, std::vector<int32_t> &ids)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("Failed to search for userData");
        return;
    }
    CHKPV(iter->second);
    if (iter->second->env == nullptr) {
        callback_.erase(iter);
        MMI_HILOGE("The env is nullptr");
        return;
    }

    iter->second->data.ids = ids;
    iter->second->errCode = RET_OK;
    uv_loop_s *loop = nullptr;
    CHKRV(iter->second->env, napi_get_uv_event_loop(iter->second->env, &loop), GET_UV_LOOP);
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    int32_t *uData = new (std::nothrow) int32_t(userData);
    if ((uData) == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check uData is null");
        return;
    }
    work->data = static_cast<void*>(uData);
    int32_t ret;
    if (iter->second->isApi9) {
        if (iter->second->ref == nullptr) {
            ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallDevListPromiseWork);
        } else {
            ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallDevListAsyncWork);
        }
    } else {
        if (iter->second->ref == nullptr) {
            ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallIdsPromiseWork);
        } else {
            ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallIdsAsyncWork);
        }
    }
    if (ret != 0) {
        MMI_HILOGE("uv_queue_work failed");
        JsUtil::DeletePtr<uv_work_t*>(work);
        JsUtil::DeletePtr<int32_t*>(uData);
    }
}

void JsEventTarget::CallDevAsyncWork(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is null");
        return;
    }
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        MMI_HILOGE("scope is nullptr");
        return;
    }
    napi_value object[2];
    CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &object[0]), GET_UNDEFINED, scope);
    object[1] = JsUtil::GetDeviceInfo(cb);
    napi_value handler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, handler, 2, object, &result), CALL_FUNCTION,
        scope);
    napi_close_handle_scope(cb->env, scope);
    JsUtil::DeleteCallbackInfo(std::move(cb));
}

void JsEventTarget::CallDevPromiseWork(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is null");
        return;
    }
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        MMI_HILOGE("scope is nullptr");
        return;
    }
    napi_value object = JsUtil::GetDeviceInfo(cb);
    if (object == nullptr) {
        MMI_HILOGE("Check object is null");
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, object), RESOLVE_DEFERRED, scope);
    napi_close_handle_scope(cb->env, scope);
    JsUtil::DeleteCallbackInfo(std::move(cb));
}

void JsEventTarget::EmitJsDev(int32_t userData, std::shared_ptr<InputDevice> device)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    CHKPV(device);
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("Failed to search for userData");
        return;
    }
    CHKPV(iter->second);
    if (iter->second->env == nullptr) {
        callback_.erase(iter);
        MMI_HILOGE("The env is nullptr");
        return;
    }

    iter->second->data.device = device;
    iter->second->errCode = RET_OK;
    uv_loop_s *loop = nullptr;
    CHKRV(iter->second->env, napi_get_uv_event_loop(iter->second->env, &loop), GET_UV_LOOP);
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    int32_t *uData = new (std::nothrow) int32_t(userData);
    CHKPV(uData);
    work->data = static_cast<void*>(uData);
    int32_t ret;
    if (iter->second->isApi9) {
        if (iter->second->ref == nullptr) {
            ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallDevInfoPromiseWork);
        } else {
            ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallDevInfoAsyncWork);
        }
    } else {
        if (iter->second->ref == nullptr) {
            ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallDevPromiseWork);
        } else {
            ret = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallDevAsyncWork);
        }
    }
    if (ret != 0) {
        MMI_HILOGE("uv_queue_work failed");
        JsUtil::DeletePtr<uv_work_t*>(work);
        JsUtil::DeletePtr<int32_t*>(uData);
        return;
    }
}

void JsEventTarget::CallKeystrokeAbilityPromise(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is null");
        return;
    }
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    CHKPV(scope);
    napi_value callResult = nullptr;
    if (cb->errCode != RET_OK) {
        if (cb->errCode == RET_ERR) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("Other errors");
            return;
        }
        NapiError codeMsg;
        if (!UtilNapiError::GetApiError(cb->errCode, codeMsg)) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("Error code %{public}d not found", cb->errCode);
            return;
        }
        callResult = GreateBusinessError(cb->env, cb->errCode, codeMsg.msg);
        CHKRV_SCOPE(cb->env, napi_reject_deferred(cb->env, cb->deferred, callResult), REJECT_DEFERRED, scope);
    } else {
        CHKRV_SCOPE(cb->env, napi_create_array(cb->env, &callResult), CREATE_ARRAY, scope);
        for (size_t i = 0; i < cb->data.keystrokeAbility.size(); ++i) {
            napi_value ret = nullptr;
            napi_value isSupport = nullptr;
            CHKRV_SCOPE(cb->env, napi_create_int32(cb->env, cb->data.keystrokeAbility[i] ? 1 : 0, &ret),
                CREATE_INT32, scope);
            CHKRV_SCOPE(cb->env, napi_coerce_to_bool(cb->env, ret, &isSupport), COERCE_TO_BOOL, scope);
            CHKRV_SCOPE(cb->env, napi_set_element(cb->env, callResult, static_cast<uint32_t>(i), isSupport),
                SET_ELEMENT, scope);
        }
        CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, callResult), RESOLVE_DEFERRED, scope);
    }
    napi_close_handle_scope(cb->env, scope);
    JsUtil::DeleteCallbackInfo(std::move(cb));
}

void JsEventTarget::CallKeystrokeAbilityAsync(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is null");
        return;
    }
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    CHKPV(scope);
    napi_value callResult[2] = { 0 };
    if (cb->errCode != RET_OK) {
        if (cb->errCode == RET_ERR) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("Other errors");
            return;
        }
        NapiError codeMsg;
        if (!UtilNapiError::GetApiError(cb->errCode, codeMsg)) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("Error code %{public}d not found", cb->errCode);
            return;
        }
        callResult[0] = GreateBusinessError(cb->env, cb->errCode, codeMsg.msg);
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[1]), GET_UNDEFINED, scope);
    } else {
        CHKRV_SCOPE(cb->env, napi_create_array(cb->env, &callResult[1]), CREATE_ARRAY, scope);
        for (size_t i = 0; i < cb->data.keystrokeAbility.size(); ++i) {
            napi_value ret = nullptr;
            napi_value isSupport = nullptr;
            CHKRV_SCOPE(cb->env, napi_create_int32(cb->env, cb->data.keystrokeAbility[i] ? 1 : 0, &ret),
                CREATE_INT32, scope);
            CHKRV_SCOPE(cb->env, napi_coerce_to_bool(cb->env, ret, &isSupport), COERCE_TO_BOOL, scope);
            CHKRV_SCOPE(cb->env, napi_set_element(cb->env, callResult[1], static_cast<uint32_t>(i), isSupport),
                SET_ELEMENT, scope);
        }
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[0]), GET_UNDEFINED, scope);
    }
    napi_value handler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler),
        GET_REFERENCE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, handler, 2, callResult, &result),
        CALL_FUNCTION, scope);
    napi_close_handle_scope(cb->env, scope);
    JsUtil::DeleteCallbackInfo(std::move(cb));
}

void JsEventTarget::EmitSupportKeys(int32_t userData, std::vector<bool> &keystrokeAbility)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("Failed to search for userData");
        return;
    }
    CHKPV(iter->second);
    if (iter->second->env == nullptr) {
        callback_.erase(iter);
        MMI_HILOGE("The env is nullptr");
        return;
    }

    iter->second->data.keystrokeAbility = keystrokeAbility;
    iter->second->errCode = RET_OK;
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
        MMI_HILOGE("uv_queue_work failed");
        JsUtil::DeletePtr<uv_work_t*>(work);
        JsUtil::DeletePtr<int32_t*>(uData);
        return;
    }
}

void JsEventTarget::EmitJsKeyboardType(int32_t userData, int32_t keyboardType)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("Failed to search for userData");
        return;
    }
    CHKPV(iter->second);
    if (iter->second->env == nullptr) {
        callback_.erase(iter);
        MMI_HILOGE("The env is nullptr");
        return;
    }
    iter->second->data.keyboardType = keyboardType;
    iter->second->errCode = RET_OK;
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
        MMI_HILOGE("uv_queue_work failed");
        JsUtil::DeletePtr<uv_work_t*>(work);
        JsUtil::DeletePtr<int32_t*>(uData);
        return;
    }
}

void JsEventTarget::CallKeyboardTypeAsync(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is null");
        return;
    }
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    CHKPV(scope);

    napi_value callResult[2] = { 0 };
    if (cb->errCode != RET_OK) {
        if (cb->errCode == RET_ERR) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("Other errors");
            return;
        }
        NapiError codeMsg;
        if (!UtilNapiError::GetApiError(cb->errCode, codeMsg)) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("Error code %{public}d not found", cb->errCode);
            return;
        }
        callResult[0] = GreateBusinessError(cb->env, cb->errCode, codeMsg.msg);
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[1]), GET_UNDEFINED, scope);
    } else {
        CHKRV_SCOPE(cb->env, napi_create_int32(cb->env, cb->data.keyboardType, &callResult[1]), CREATE_INT32, scope);
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[0]), GET_UNDEFINED, scope);
    }
    napi_value handler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, handler, 2, callResult, &result),
	    CALL_FUNCTION, scope);
    napi_close_handle_scope(cb->env, scope);
    JsUtil::DeleteCallbackInfo(std::move(cb));
}

void JsEventTarget::CallKeyboardTypePromise(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is null");
        return;
    }
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    CHKPV(scope);

    napi_value callResult;
    if (cb->errCode != RET_OK) {
        if (cb->errCode == RET_ERR) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("Other errors");
            return;
        }
        NapiError codeMsg;
        if (!UtilNapiError::GetApiError(cb->errCode, codeMsg)) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("Error code %{public}d not found", cb->errCode);
            return;
        }
        callResult = GreateBusinessError(cb->env, cb->errCode, codeMsg.msg);
        CHKRV_SCOPE(cb->env, napi_reject_deferred(cb->env, cb->deferred, callResult), REJECT_DEFERRED, scope);
    } else {
        CHKRV_SCOPE(cb->env, napi_create_int32(cb->env, cb->data.keyboardType, &callResult), CREATE_INT32, scope);
        CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, callResult), RESOLVE_DEFERRED, scope);
    }
    napi_close_handle_scope(cb->env, scope);
    JsUtil::DeleteCallbackInfo(std::move(cb));
}

void JsEventTarget::CallDevListAsyncWork(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is null");
        return;
    }
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    CHKPV(scope);

    napi_value callResult[2] = { 0 };
    if (cb->errCode != RET_OK) {
        if (cb->errCode == RET_ERR) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("Other errors");
            return;
        }
        NapiError codeMsg;
        if (!UtilNapiError::GetApiError(cb->errCode, codeMsg)) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("Error code %{public}d not found", cb->errCode);
            return;
        }
        callResult[0] = GreateBusinessError(cb->env, cb->errCode, codeMsg.msg);
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[1]), GET_UNDEFINED, scope);
    } else {
        CHKRV_SCOPE(cb->env, napi_create_array(cb->env, &callResult[1]), CREATE_ARRAY, scope);
        uint32_t index = 0;
        napi_value value = nullptr;
        for (const auto &item : cb->data.ids) {
            CHKRV_SCOPE(cb->env, napi_create_int32(cb->env, item, &value), CREATE_INT32, scope);
            CHKRV_SCOPE(cb->env, napi_set_element(cb->env, callResult[1], index, value), SET_ELEMENT, scope);
            ++index;
        }
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[0]), GET_UNDEFINED, scope);
    }
    napi_value handler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, handler, 2, callResult, &result),
        CALL_FUNCTION, scope);
    napi_close_handle_scope(cb->env, scope);
    JsUtil::DeleteCallbackInfo(std::move(cb));
}

void JsEventTarget::CallDevListPromiseWork(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is null");
        return;
    }
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    CHKPV(scope);
    napi_value callResult = nullptr;
    if (cb->errCode != RET_OK) {
        if (cb->errCode == RET_ERR) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("Other errors");
            return;
        }
        NapiError codeMsg;
        if (!UtilNapiError::GetApiError(cb->errCode, codeMsg)) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("Error code %{public}d not found", cb->errCode);
            return;
        }
        callResult = GreateBusinessError(cb->env, cb->errCode, codeMsg.msg);
        CHKRV_SCOPE(cb->env, napi_reject_deferred(cb->env, cb->deferred, callResult), REJECT_DEFERRED, scope);
    } else {
        CHKRV_SCOPE(cb->env, napi_create_array(cb->env, &callResult), CREATE_ARRAY, scope);
        uint32_t index = 0;
        napi_value value = nullptr;
        for (const auto &item : cb->data.ids) {
            CHKRV_SCOPE(cb->env, napi_create_int32(cb->env, item, &value), CREATE_INT32, scope);
            CHKRV_SCOPE(cb->env, napi_set_element(cb->env, callResult, index, value), SET_ELEMENT, scope);
            ++index;
        }
        CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, callResult), RESOLVE_DEFERRED, scope);
    }
    napi_close_handle_scope(cb->env, scope);
    JsUtil::DeleteCallbackInfo(std::move(cb));
}

void JsEventTarget::CallDevInfoPromiseWork(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is null");
        return;
    }
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    CHKPV(scope);
    napi_value callResult = nullptr;
    if (cb->errCode != RET_OK) {
        if (cb->errCode == RET_ERR) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("Other errors");
            return;
        }
        NapiError codeMsg;
        if (!UtilNapiError::GetApiError(cb->errCode, codeMsg)) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("Error code %{public}d not found", cb->errCode);
            return;
        }
        callResult = GreateBusinessError(cb->env, cb->errCode, codeMsg.msg);
        CHKRV_SCOPE(cb->env, napi_reject_deferred(cb->env, cb->deferred, callResult), REJECT_DEFERRED, scope);
    } else {
        callResult = JsUtil::GetDeviceInfo(cb);
        if (callResult == nullptr) {
            MMI_HILOGE("Check callResult is null");
            napi_close_handle_scope(cb->env, scope);
            return;
        }
        CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, callResult), RESOLVE_DEFERRED, scope);
    }
    napi_close_handle_scope(cb->env, scope);
    JsUtil::DeleteCallbackInfo(std::move(cb));
}

void JsEventTarget::CallDevInfoAsyncWork(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is null");
        return;
    }
    std::unique_ptr<JsUtil::CallbackInfo> cb = GetCallbackInfo(work);
    CHKPV(cb);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    CHKPV(scope);
    napi_value callResult[2] = { 0 };
    if (cb->errCode != RET_OK) {
        if (cb->errCode == RET_ERR) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("Other errors");
            return;
        }
        NapiError codeMsg;
        if (!UtilNapiError::GetApiError(cb->errCode, codeMsg)) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("Error code %{public}d not found", cb->errCode);
            return;
        }
        callResult[0] = GreateBusinessError(cb->env, cb->errCode, codeMsg.msg);
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[1]), GET_UNDEFINED, scope);
    } else {
        callResult[1] = JsUtil::GetDeviceInfo(cb);
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[0]), GET_UNDEFINED, scope);
    }
    napi_value handler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, handler, 2, callResult, &result), CALL_FUNCTION,
        scope);
    napi_close_handle_scope(cb->env, scope);
    JsUtil::DeleteCallbackInfo(std::move(cb));
}

void JsEventTarget::AddListener(napi_env env, const std::string &type, napi_value handle)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = devListener_.find(type);
    if (iter == devListener_.end()) {
        MMI_HILOGE("Find %{public}s failed", type.c_str());
        return;
    }

    for (const auto &temp : iter->second) {
        CHKPC(temp);
        if (temp->env != env) {
            continue;
        }
        if (JsUtil::IsSameHandle(env, handle, temp->ref)) {
            MMI_HILOGW("The handle already exists");
            return;
        }
    }
    napi_ref ref = nullptr;
    CHKRV(env, napi_create_reference(env, handle, 1, &ref), CREATE_REFERENCE);
    auto monitor = std::make_unique<JsUtil::CallbackInfo>();
    monitor->env = env;
    monitor->ref = ref;
    iter->second.push_back(std::move(monitor));
    if (!isListeningProcess_) {
        isListeningProcess_ = true;
        InputMgr->RegisterDevListener("change", shared_from_this());
    }
}

void JsEventTarget::RemoveListener(napi_env env, const std::string &type, napi_value handle)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = devListener_.find(type);
    if (iter == devListener_.end()) {
        MMI_HILOGE("Find %{public}s failed", type.c_str());
        return;
    }
    if (handle == nullptr) {
        iter->second.clear();
        goto monitorLabel;
    }
    for (auto it = iter->second.begin(); it != iter->second.end(); ++it) {
        if ((*it)->env != env) {
            continue;
        }
        if (JsUtil::IsSameHandle(env, handle, (*it)->ref)) {
            MMI_HILOGD("Succeeded in removing monitor");
            JsUtil::DeleteCallbackInfo(std::move(*it));
            iter->second.erase(it);
            goto monitorLabel;
        }
    }

monitorLabel:
    if (isListeningProcess_ && iter->second.empty()) {
        isListeningProcess_ = false;
        InputMgr->UnregisterDevListener("change", shared_from_this());
    }
}

napi_value JsEventTarget::CreateCallbackInfo(napi_env env, napi_value handle, const int32_t userData, bool isApi9)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto cb = std::make_unique<JsUtil::CallbackInfo>();
    cb->env = env;
    cb->isApi9 = isApi9;
    napi_value promise = nullptr;
    if (handle == nullptr) {
        CHKRP(env, napi_create_promise(env, &cb->deferred, &promise), CREATE_PROMISE);
    } else {
        CHKRP(env, napi_create_reference(env, handle, 1, &cb->ref), CREATE_REFERENCE);
    }
    callback_.emplace(userData, std::move(cb));
    return promise;
}

napi_value JsEventTarget::GreateBusinessError(napi_env env, int32_t errCode, std::string errMessage)
{
    CALL_DEBUG_ENTER;
    napi_value result = nullptr;
    napi_value resultCode = nullptr;
    napi_value resultMessage = nullptr;
    CHKRP(env, napi_create_int32(env, errCode, &resultCode), CREATE_INT32);
    CHKRP(env, napi_create_string_utf8(env, errMessage.data(), NAPI_AUTO_LENGTH, &resultMessage), CREATE_STRING_UTF8);
    CHKRP(env, napi_create_error(env, nullptr, resultMessage, &result), CREATE_ERROR);
    CHKRP(env, napi_set_named_property(env, result, ERR_CODE.c_str(), resultCode), SET_NAMED_PROPERTY);
    return result;
}

std::unique_ptr<JsUtil::CallbackInfo> JsEventTarget::GetCallbackInfo(uv_work_t *work)
{
    std::lock_guard<std::mutex> guard(mutex_);
    int32_t *uData = static_cast<int32_t*>(work->data);
    int32_t userData = *uData;
    JsUtil::DeletePtr<uv_work_t*>(work);
    JsUtil::DeletePtr<int32_t*>(uData);

    auto iter = callback_.find(userData);
    if (iter == callback_.end()) {
        MMI_HILOGE("Find userData failed");
        return nullptr;
    }
    auto cb = std::move(iter->second);
    callback_.erase(iter);
    return cb;
}

void JsEventTarget::RemoveCallbackInfo(napi_env env, napi_value handle, int32_t userData)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = callback_.find(userData);
    if (iter != callback_.end()) {
        auto cb = std::move(iter->second);
        JsUtil::DeleteCallbackInfo(std::move(cb));
        callback_.erase(iter);
    }
}

void JsEventTarget::ResetEnv()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    callback_.clear();
    devListener_.clear();
    InputMgr->UnregisterDevListener("change", shared_from_this());
}
} // namespace MMI
} // namespace OHOS