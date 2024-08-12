/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "js_event_target.h"
#include "js_util.h"
#include "napi_constants.h"
#include "util_napi_error.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsEventTarget"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t INPUT_PARAMETER_MIDDLE { 2 };

std::mutex mutex_;
const std::string ADD_EVENT = "add";
const std::string REMOVE_EVENT = "remove";

struct DeviceItem {
    int32_t deviceId;
    void *item;
};

} // namespace

JsEventTarget::JsEventTarget()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> lock(mutex_);
    auto ret = devListener_.insert({ CHANGED_TYPE, std::vector<std::unique_ptr<JsUtil::CallbackInfo>>() });
    CK(ret.second, VAL_NOT_EXP);
}

void JsEventTarget::EmitAddedDeviceEvent(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::ReportData> reportData(static_cast<JsUtil::ReportData *>(work->data));
    reportData->DecStrongRef(nullptr);
    JsUtil::DeletePtr<uv_work_t *>(work);
    auto addEvent = devListener_.find(CHANGED_TYPE);
    if (addEvent == devListener_.end()) {
        MMI_HILOGE("Find change event failed");
        return;
    }
    for (const auto &item : addEvent->second) {
        CHKPC(item->env);
        if (item->ref != reportData->ref) {
            continue;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(item->env, &scope);
        CHKPV(scope);
        napi_value eventType = nullptr;
        CHKRV_SCOPE_DEL(item->env, napi_create_string_utf8(item->env, ADD_EVENT.c_str(), NAPI_AUTO_LENGTH, &eventType),
            CREATE_STRING_UTF8, scope);
        napi_value object = nullptr;
        CHKRV_SCOPE_DEL(item->env, napi_create_object(item->env, &object), CREATE_OBJECT, scope);
        CHKRV_SCOPE_DEL(item->env, napi_set_named_property(item->env, object, "type", eventType), SET_NAMED_PROPERTY,
            scope);
        napi_value handler = nullptr;
        CHKRV_SCOPE_DEL(item->env, napi_get_reference_value(item->env, item->ref, &handler), GET_REFERENCE_VALUE,
            scope);
        napi_value deviceId = nullptr;
        CHKRV_SCOPE_DEL(item->env, napi_create_int32(item->env, reportData->deviceId, &deviceId), CREATE_INT32, scope);
        CHKRV_SCOPE_DEL(item->env, napi_set_named_property(item->env, object, "deviceId", deviceId), SET_NAMED_PROPERTY,
            scope);
        napi_value ret = nullptr;
        CHKRV_SCOPE_DEL(item->env, napi_call_function(item->env, nullptr, handler, 1, &object, &ret), CALL_FUNCTION,
            scope);
        napi_close_handle_scope(item->env, scope);
    }
}

void JsEventTarget::EmitRemoveDeviceEvent(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::ReportData> reportData(static_cast<JsUtil::ReportData *>(work->data));
    reportData->DecStrongRef(nullptr);
    JsUtil::DeletePtr<uv_work_t *>(work);
    auto removeEvent = devListener_.find(CHANGED_TYPE);
    if (removeEvent == devListener_.end()) {
        MMI_HILOGE("Find change event failed");
        return;
    }
    for (const auto &item : removeEvent->second) {
        CHKPC(item->env);
        if (item->ref != reportData->ref) {
            continue;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(item->env, &scope);
        CHKPV(scope);
        napi_value eventType = nullptr;
        CHKRV_SCOPE_DEL(item->env, napi_create_string_utf8(item->env, REMOVE_EVENT.c_str(), NAPI_AUTO_LENGTH,
            &eventType), CREATE_STRING_UTF8, scope);
        napi_value deviceId = nullptr;
        CHKRV_SCOPE_DEL(item->env, napi_create_int32(item->env, reportData->deviceId, &deviceId), CREATE_INT32, scope);
        napi_value object = nullptr;
        CHKRV_SCOPE_DEL(item->env, napi_create_object(item->env, &object), CREATE_OBJECT, scope);
        CHKRV_SCOPE_DEL(item->env, napi_set_named_property(item->env, object, "type", eventType), SET_NAMED_PROPERTY,
            scope);
        CHKRV_SCOPE_DEL(item->env, napi_set_named_property(item->env, object, "deviceId", deviceId), SET_NAMED_PROPERTY,
            scope);
        napi_value handler = nullptr;
        CHKRV_SCOPE_DEL(item->env, napi_get_reference_value(item->env, item->ref, &handler), GET_REFERENCE_VALUE,
            scope);
        napi_value ret = nullptr;
        CHKRV_SCOPE_DEL(item->env, napi_call_function(item->env, nullptr, handler, 1, &object, &ret), CALL_FUNCTION,
            scope);
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
        CHKRV(napi_get_uv_event_loop(item->env, &loop), GET_UV_EVENT_LOOP);
        uv_work_t *work = new (std::nothrow) uv_work_t;
        CHKPV(work);
        sptr<JsUtil::ReportData> reportData = new (std::nothrow) JsUtil::ReportData;
        if (reportData == nullptr) {
            MMI_HILOGE("Memory allocation failed");
            JsUtil::DeletePtr<uv_work_t *>(work);
            return;
        }
        reportData->deviceId = deviceId;
        reportData->ref = item->ref;
        reportData->IncStrongRef(nullptr);
        work->data = reportData.GetRefPtr();
        int32_t ret = uv_queue_work_with_qos(
            loop, work,
            [](uv_work_t *work) {
                MMI_HILOGD("uv_queue_work callback function is called");
            },
            EmitAddedDeviceEvent, uv_qos_user_initiated);
        if (ret != 0) {
            MMI_HILOGE("uv_queue_work_with_qos failed");
            JsUtil::DeletePtr<uv_work_t *>(work);
            reportData->DecStrongRef(nullptr);
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
        CHKRV(napi_get_uv_event_loop(item->env, &loop), GET_UV_EVENT_LOOP);
        uv_work_t *work = new (std::nothrow) uv_work_t;
        CHKPV(work);
        sptr<JsUtil::ReportData> reportData = new (std::nothrow) JsUtil::ReportData;
        if (reportData == nullptr) {
            MMI_HILOGE("Memory allocation failed");
            JsUtil::DeletePtr<uv_work_t *>(work);
            return;
        }
        reportData->deviceId = deviceId;
        reportData->ref = item->ref;
        reportData->IncStrongRef(nullptr);
        work->data = reportData.GetRefPtr();
        int32_t ret = uv_queue_work_with_qos(
            loop, work,
            [](uv_work_t *work) {
                MMI_HILOGD("uv_queue_work callback function is called");
            },
            EmitRemoveDeviceEvent, uv_qos_user_initiated);
        if (ret != 0) {
            MMI_HILOGE("uv_queue_work_with_qos failed");
            JsUtil::DeletePtr<uv_work_t *>(work);
            reportData->DecStrongRef(nullptr);
            return;
        }
    }
}

void JsEventTarget::CallIdsAsyncWork(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    CHKPV(scope);
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
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE_VALUE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, handler, INPUT_PARAMETER_MIDDLE, arr, &result),
        CALL_FUNCTION, scope);
    CHKRV_SCOPE(cb->env, napi_delete_reference(cb->env, cb->ref), DELETE_REFERENCE, scope);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::CallIdsPromiseWork(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    CHKPV(scope);
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
}

void JsEventTarget::EmitJsIds(sptr<JsUtil::CallbackInfo> cb, std::vector<int32_t> &ids)
{
    CALL_DEBUG_ENTER;
    CHKPV(cb);
    CHKPV(cb->env);
    cb->data.ids = ids;
    cb->errCode = RET_OK;
    uv_loop_s *loop = nullptr;
    CHKRV(napi_get_uv_event_loop(cb->env, &loop), GET_UV_EVENT_LOOP);
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    cb->IncStrongRef(nullptr);
    work->data = cb.GetRefPtr();
    int32_t ret = 0;
    if (cb->isApi9) {
        if (cb->ref == nullptr) {
            ret = uv_queue_work_with_qos(
                loop, work,
                [](uv_work_t *work) {
                    MMI_HILOGD("uv_queue_work callback function is called");
                }, CallDevListPromiseWork, uv_qos_user_initiated);
        } else {
            ret = uv_queue_work_with_qos(
                loop, work,
                [](uv_work_t *work) {
                    MMI_HILOGD("uv_queue_work callback function is called");
                }, CallDevListAsyncWork, uv_qos_user_initiated);
        }
    } else {
        if (cb->ref == nullptr) {
            ret = uv_queue_work_with_qos(
                loop, work,
                [](uv_work_t *work) {
                    MMI_HILOGD("uv_queue_work callback function is called");
                }, CallIdsPromiseWork, uv_qos_user_initiated);
        } else {
            ret = uv_queue_work_with_qos(
                loop, work,
                [](uv_work_t *work) {
                    MMI_HILOGD("uv_queue_work callback function is called");
                }, CallIdsAsyncWork, uv_qos_user_initiated);
        }
    }
    if (ret != 0) {
        MMI_HILOGE("uv_queue_work_with_qos failed");
        JsUtil::DeletePtr<uv_work_t *>(work);
    }
}

void JsEventTarget::CallDevAsyncWork(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    CHKPV(scope);
    napi_value object[2];
    CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &object[0]), GET_UNDEFINED, scope);
    object[1] = JsUtil::GetDeviceInfo(cb);
    napi_value handler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE_VALUE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, handler, INPUT_PARAMETER_MIDDLE, object, &result),
        CALL_FUNCTION, scope);
    CHKRV_SCOPE(cb->env, napi_delete_reference(cb->env, cb->ref), DELETE_REFERENCE, scope);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::CallDevPromiseWork(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    CHKPV(scope);
    napi_value object = JsUtil::GetDeviceInfo(cb);
    if (object == nullptr) {
        MMI_HILOGE("Check object is nullptr");
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, object), RESOLVE_DEFERRED, scope);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::EmitJsDev(sptr<JsUtil::CallbackInfo> cb, std::shared_ptr<InputDevice> device)
{
    CALL_DEBUG_ENTER;
    CHKPV(device);
    CHKPV(cb);
    CHKPV(cb->env);
    cb->data.device = device;
    cb->errCode = RET_OK;
    uv_loop_s *loop = nullptr;
    CHKRV(napi_get_uv_event_loop(cb->env, &loop), GET_UV_EVENT_LOOP);
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    cb->IncStrongRef(nullptr);
    work->data = cb.GetRefPtr();
    int32_t ret = 0;
    if (cb->isApi9) {
        if (cb->ref == nullptr) {
            ret = uv_queue_work_with_qos(
                loop, work,
                [](uv_work_t *work) {
                    MMI_HILOGD("uv_queue_work callback function is called");
                }, CallDevInfoPromiseWork, uv_qos_user_initiated);
        } else {
            ret = uv_queue_work_with_qos(
                loop, work,
                [](uv_work_t *work) {
                    MMI_HILOGD("uv_queue_work callback function is called");
                }, CallDevInfoAsyncWork, uv_qos_user_initiated);
        }
    } else {
        if (cb->ref == nullptr) {
            ret = uv_queue_work_with_qos(
                loop, work,
                [](uv_work_t *work) {
                    MMI_HILOGD("uv_queue_work callback function is called");
                }, CallDevPromiseWork, uv_qos_user_initiated);
        } else {
            ret = uv_queue_work_with_qos(
                loop, work,
                [](uv_work_t *work) {
                    MMI_HILOGD("uv_queue_work callback function is called");
                }, CallDevAsyncWork, uv_qos_user_initiated);
        }
    }
    if (ret != 0) {
        MMI_HILOGE("uv_queue_work_with_qos failed");
        JsUtil::DeletePtr<uv_work_t *>(work);
    }
}

void JsEventTarget::CallKeystrokeAbilityPromise(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
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
        if (callResult == nullptr) {
            MMI_HILOGE("callResult is nullptr");
            napi_close_handle_scope(cb->env, scope);
            return;
        }
        CHKRV_SCOPE(cb->env, napi_reject_deferred(cb->env, cb->deferred, callResult), REJECT_DEFERRED, scope);
    } else {
        CHKRV_SCOPE(cb->env, napi_create_array(cb->env, &callResult), CREATE_ARRAY, scope);
        for (size_t i = 0; i < cb->data.keystrokeAbility.size(); ++i) {
            napi_value ret = nullptr;
            napi_value isSupport = nullptr;
            CHKRV_SCOPE(cb->env, napi_create_int32(cb->env, cb->data.keystrokeAbility[i] ? 1 : 0, &ret), CREATE_INT32,
                scope);
            CHKRV_SCOPE(cb->env, napi_coerce_to_bool(cb->env, ret, &isSupport), COERCE_TO_BOOL, scope);
            CHKRV_SCOPE(cb->env, napi_set_element(cb->env, callResult, static_cast<uint32_t>(i), isSupport),
                SET_ELEMENT, scope);
        }
        CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, callResult), RESOLVE_DEFERRED, scope);
    }
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::CallKeystrokeAbilityAsync(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
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
        if (callResult[0] == nullptr) {
            MMI_HILOGE("callResult[0] is nullptr");
            napi_close_handle_scope(cb->env, scope);
            return;
        }
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[1]), GET_UNDEFINED, scope);
    } else {
        CHKRV_SCOPE(cb->env, napi_create_array(cb->env, &callResult[1]), CREATE_ARRAY, scope);
        for (size_t i = 0; i < cb->data.keystrokeAbility.size(); ++i) {
            napi_value ret = nullptr;
            napi_value isSupport = nullptr;
            CHKRV_SCOPE(cb->env, napi_create_int32(cb->env, cb->data.keystrokeAbility[i] ? 1 : 0, &ret), CREATE_INT32,
                scope);
            CHKRV_SCOPE(cb->env, napi_coerce_to_bool(cb->env, ret, &isSupport), COERCE_TO_BOOL, scope);
            CHKRV_SCOPE(cb->env, napi_set_element(cb->env, callResult[1], static_cast<uint32_t>(i), isSupport),
                SET_ELEMENT, scope);
        }
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[0]), GET_UNDEFINED, scope);
    }
    napi_value handler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE_VALUE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, handler, INPUT_PARAMETER_MIDDLE, callResult, &result),
        CALL_FUNCTION, scope);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::EmitSupportKeys(sptr<JsUtil::CallbackInfo> cb, std::vector<bool> &keystrokeAbility)
{
    CALL_DEBUG_ENTER;
    CHKPV(cb);
    CHKPV(cb->env);
    cb->data.keystrokeAbility = keystrokeAbility;
    cb->errCode = RET_OK;
    uv_loop_s *loop = nullptr;
    CHKRV(napi_get_uv_event_loop(cb->env, &loop), GET_UV_EVENT_LOOP);
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    cb->IncStrongRef(nullptr);
    work->data = cb.GetRefPtr();
    int32_t ret = 0;
    if (cb->ref == nullptr) {
        ret = uv_queue_work_with_qos(
            loop, work,
            [](uv_work_t *work) {
                MMI_HILOGD("uv_queue_work callback function is called");
            },
            CallKeystrokeAbilityPromise, uv_qos_user_initiated);
    } else {
        ret = uv_queue_work_with_qos(
            loop, work,
            [](uv_work_t *work) {
                MMI_HILOGD("uv_queue_work callback function is called");
            },
            CallKeystrokeAbilityAsync, uv_qos_user_initiated);
    }
    if (ret != 0) {
        MMI_HILOGE("uv_queue_work_with_qos failed");
        JsUtil::DeletePtr<uv_work_t *>(work);
    }
}

void JsEventTarget::EmitJsKeyboardType(sptr<JsUtil::CallbackInfo> cb, int32_t keyboardType)
{
    CALL_DEBUG_ENTER;
    CHKPV(cb);
    CHKPV(cb->env);
    cb->data.keyboardType = keyboardType;
    cb->errCode = RET_OK;
    uv_loop_s *loop = nullptr;
    CHKRV(napi_get_uv_event_loop(cb->env, &loop), GET_UV_EVENT_LOOP);

    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    cb->IncStrongRef(nullptr);
    work->data = cb.GetRefPtr();
    int32_t ret = 0;
    if (cb->ref == nullptr) {
        ret = uv_queue_work_with_qos(
            loop, work,
            [](uv_work_t *work) {
                MMI_HILOGD("uv_queue_work callback function is called");
            },
            CallKeyboardTypePromise, uv_qos_user_initiated);
    } else {
        ret = uv_queue_work_with_qos(
            loop, work,
            [](uv_work_t *work) {
                MMI_HILOGD("uv_queue_work callback function is called");
            },
            CallKeyboardTypeAsync, uv_qos_user_initiated);
    }
    if (ret != 0) {
        MMI_HILOGE("uv_queue_work_with_qos failed");
        JsUtil::DeletePtr<uv_work_t *>(work);
    }
}

void JsEventTarget::CallKeyboardTypeAsync(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
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
        if (callResult[0] == nullptr) {
            MMI_HILOGE("callResult[0] is nullptr");
            napi_close_handle_scope(cb->env, scope);
            return;
        }
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[1]), GET_UNDEFINED, scope);
    } else {
        CHKRV_SCOPE(cb->env, napi_create_int32(cb->env, cb->data.keyboardType, &callResult[1]), CREATE_INT32, scope);
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[0]), GET_UNDEFINED, scope);
    }
    napi_value handler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE_VALUE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, handler, INPUT_PARAMETER_MIDDLE, callResult, &result),
        CALL_FUNCTION, scope);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::CallKeyboardTypePromise(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
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
        if (callResult == nullptr) {
            MMI_HILOGE("callResult is nullptr");
            napi_close_handle_scope(cb->env, scope);
            return;
        }
        CHKRV_SCOPE(cb->env, napi_reject_deferred(cb->env, cb->deferred, callResult), REJECT_DEFERRED, scope);
    } else {
        CHKRV_SCOPE(cb->env, napi_create_int32(cb->env, cb->data.keyboardType, &callResult), CREATE_INT32, scope);
        CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, callResult), RESOLVE_DEFERRED, scope);
    }
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::CallDevListAsyncWork(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
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
        CHKNRV_SCOPE(cb->env, callResult[0], "callResult[0]", scope);
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
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE_VALUE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, handler, INPUT_PARAMETER_MIDDLE, callResult, &result),
        CALL_FUNCTION, scope);
    CHKRV_SCOPE(cb->env, napi_delete_reference(cb->env, cb->ref), DELETE_REFERENCE, scope);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::CallDevListPromiseWork(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
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
        if (callResult == nullptr) {
            MMI_HILOGE("callResult is nullptr");
            napi_close_handle_scope(cb->env, scope);
            return;
        }
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
}

void JsEventTarget::CallDevInfoPromiseWork(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
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
        if (callResult == nullptr) {
            MMI_HILOGE("callResult is nullptr");
            napi_close_handle_scope(cb->env, scope);
            return;
        }
        CHKRV_SCOPE(cb->env, napi_reject_deferred(cb->env, cb->deferred, callResult), REJECT_DEFERRED, scope);
    } else {
        callResult = JsUtil::GetDeviceInfo(cb);
        if (callResult == nullptr) {
            MMI_HILOGE("Check callResult is nullptr");
            napi_close_handle_scope(cb->env, scope);
            return;
        }
        CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, callResult), RESOLVE_DEFERRED, scope);
    }
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::CallDevInfoAsyncWork(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
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
        if (callResult[0] == nullptr) {
            MMI_HILOGE("callResult[0] is nullptr");
            napi_close_handle_scope(cb->env, scope);
            return;
        }
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[1]), GET_UNDEFINED, scope);
    } else {
        callResult[1] = JsUtil::GetDeviceInfo(cb);
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[0]), GET_UNDEFINED, scope);
    }
    napi_value handler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE_VALUE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, handler, INPUT_PARAMETER_MIDDLE, callResult, &result),
        CALL_FUNCTION, scope);
    CHKRV_SCOPE(cb->env, napi_delete_reference(cb->env, cb->ref), DELETE_REFERENCE, scope);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::EmitJsSetKeyboardRepeatDelay(sptr<JsUtil::CallbackInfo> cb, int32_t errCode)
{
    CALL_DEBUG_ENTER;
    CHKPV(cb);
    CHKPV(cb->env);
    cb->data.keyboardRepeatDelay = 0;
    cb->errCode = errCode;
    uv_loop_s *loop = nullptr;
    CHKRV(napi_get_uv_event_loop(cb->env, &loop), GET_UV_EVENT_LOOP);

    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    cb->IncStrongRef(nullptr);
    work->data = cb.GetRefPtr();
    int32_t ret = 0;
    if (cb->ref == nullptr) {
        ret = uv_queue_work_with_qos(
            loop, work,
            [](uv_work_t *work) {
                MMI_HILOGD("uv_queue_work callback function is called");
            },
            CallKeyboardRepeatDelayPromise, uv_qos_user_initiated);
    } else {
        ret = uv_queue_work_with_qos(
            loop, work,
            [](uv_work_t *work) {
                MMI_HILOGD("uv_queue_work callback function is called");
            },
            CallKeyboardRepeatDelayAsync, uv_qos_user_initiated);
    }
    if (ret != 0) {
        MMI_HILOGE("uv_queue_work_with_qos failed");
        JsUtil::DeletePtr<uv_work_t *>(work);
    }
}

void JsEventTarget::EmitJsKeyboardRepeatDelay(sptr<JsUtil::CallbackInfo> cb, int32_t delay)
{
    CALL_DEBUG_ENTER;
    CHKPV(cb);
    CHKPV(cb->env);
    cb->data.keyboardRepeatDelay = delay;
    cb->errCode = RET_OK;
    uv_loop_s *loop = nullptr;
    CHKRV(napi_get_uv_event_loop(cb->env, &loop), GET_UV_EVENT_LOOP);

    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    cb->IncStrongRef(nullptr);
    work->data = cb.GetRefPtr();
    int32_t ret = 0;
    if (cb->ref == nullptr) {
        ret = uv_queue_work_with_qos(
            loop, work,
            [](uv_work_t *work) {
                MMI_HILOGD("uv_queue_work callback function is called");
            },
            CallKeyboardRepeatDelayPromise, uv_qos_user_initiated);
    } else {
        ret = uv_queue_work_with_qos(
            loop, work,
            [](uv_work_t *work) {
                MMI_HILOGD("uv_queue_work callback function is called");
            },
            CallKeyboardRepeatDelayAsync, uv_qos_user_initiated);
    }
    if (ret != 0) {
        MMI_HILOGE("uv_queue_work_with_qos failed");
        JsUtil::DeletePtr<uv_work_t *>(work);
    }
}

void JsEventTarget::CallKeyboardRepeatDelayAsync(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
    CHKPV(cb->env);

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    CHKPV(scope);

    napi_value callResult[2] = {0};
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
        if (callResult[0] == nullptr) {
            MMI_HILOGE("callResult[0] is nullptr");
            napi_close_handle_scope(cb->env, scope);
            return;
        }
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[1]), GET_UNDEFINED, scope);
    } else {
        CHKRV_SCOPE(
            cb->env, napi_create_int32(cb->env, cb->data.keyboardRepeatDelay, &callResult[1]), CREATE_INT32, scope);
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[0]), GET_UNDEFINED, scope);
    }
    napi_value handler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE_VALUE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env,
        napi_call_function(cb->env, nullptr, handler, INPUT_PARAMETER_MIDDLE, callResult, &result),
        CALL_FUNCTION,
        scope);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::CallKeyboardRepeatDelayPromise(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
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
        if (callResult == nullptr) {
            MMI_HILOGE("callResult is nullptr");
            napi_close_handle_scope(cb->env, scope);
            return;
        }
        CHKRV_SCOPE(cb->env, napi_reject_deferred(cb->env, cb->deferred, callResult), REJECT_DEFERRED, scope);
    } else {
        CHKRV_SCOPE(
            cb->env, napi_create_int32(cb->env, cb->data.keyboardRepeatDelay, &callResult), CREATE_INT32, scope);
        CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, callResult), RESOLVE_DEFERRED, scope);
    }
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::EmitJsSetKeyboardRepeatRate(sptr<JsUtil::CallbackInfo> cb, int32_t errCode)
{
    CALL_DEBUG_ENTER;
    CHKPV(cb);
    CHKPV(cb->env);
    cb->data.keyboardRepeatRate = 0;
    cb->errCode = errCode;
    uv_loop_s *loop = nullptr;
    CHKRV(napi_get_uv_event_loop(cb->env, &loop), GET_UV_EVENT_LOOP);

    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    cb->IncStrongRef(nullptr);
    work->data = cb.GetRefPtr();
    int32_t ret = 0;
    if (cb->ref == nullptr) {
        ret = uv_queue_work_with_qos(
            loop, work,
            [](uv_work_t *work) {
                MMI_HILOGD("uv_queue_work callback function is called");
            },
            CallKeyboardRepeatRatePromise, uv_qos_user_initiated);
    } else {
        ret = uv_queue_work_with_qos(
            loop, work,
            [](uv_work_t *work) {
                MMI_HILOGD("uv_queue_work callback function is called");
            },
            CallKeyboardRepeatRateAsync, uv_qos_user_initiated);
    }
    if (ret != 0) {
        MMI_HILOGE("uv_queue_work_with_qos failed");
        JsUtil::DeletePtr<uv_work_t *>(work);
    }
}

void JsEventTarget::EmitJsKeyboardRepeatRate(sptr<JsUtil::CallbackInfo> cb, int32_t rate)
{
    CALL_DEBUG_ENTER;
    CHKPV(cb);
    CHKPV(cb->env);
    cb->data.keyboardRepeatRate = rate;
    cb->errCode = RET_OK;
    uv_loop_s *loop = nullptr;
    CHKRV(napi_get_uv_event_loop(cb->env, &loop), GET_UV_EVENT_LOOP);

    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    cb->IncStrongRef(nullptr);
    work->data = cb.GetRefPtr();
    int32_t ret = 0;
    if (cb->ref == nullptr) {
        ret = uv_queue_work_with_qos(
            loop, work,
            [](uv_work_t *work) {
                MMI_HILOGD("uv_queue_work callback function is called");
            },
            CallKeyboardRepeatRatePromise, uv_qos_user_initiated);
    } else {
        ret = uv_queue_work_with_qos(
            loop, work,
            [](uv_work_t *work) {
                MMI_HILOGD("uv_queue_work callback function is called");
            },
            CallKeyboardRepeatRateAsync, uv_qos_user_initiated);
    }
    if (ret != 0) {
        MMI_HILOGE("uv_queue_work_with_qos failed");
        JsUtil::DeletePtr<uv_work_t *>(work);
    }
}

void JsEventTarget::CallKeyboardRepeatRateAsync(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
    CHKPV(cb->env);

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    CHKPV(scope);

    napi_value callResult[2] = {0};
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
        if (callResult[0] == nullptr) {
            MMI_HILOGE("callResult[0] is nullptr");
            napi_close_handle_scope(cb->env, scope);
            return;
        }
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[1]), GET_UNDEFINED, scope);
    } else {
        CHKRV_SCOPE(
            cb->env, napi_create_int32(cb->env, cb->data.keyboardRepeatRate, &callResult[1]), CREATE_INT32, scope);
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[0]), GET_UNDEFINED, scope);
    }
    napi_value handler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE_VALUE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env,
        napi_call_function(cb->env, nullptr, handler, INPUT_PARAMETER_MIDDLE, callResult, &result),
        CALL_FUNCTION,
        scope);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::CallKeyboardRepeatRatePromise(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
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
        if (callResult == nullptr) {
            MMI_HILOGE("callResult is nullptr");
            napi_close_handle_scope(cb->env, scope);
            return;
        }
        CHKRV_SCOPE(cb->env, napi_reject_deferred(cb->env, cb->deferred, callResult), REJECT_DEFERRED, scope);
    } else {
        CHKRV_SCOPE(
            cb->env, napi_create_int32(cb->env, cb->data.keyboardRepeatRate, &callResult), CREATE_INT32, scope);
        CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, callResult), RESOLVE_DEFERRED, scope);
    }
    napi_close_handle_scope(cb->env, scope);
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
    CHKRV(napi_create_reference(env, handle, 1, &ref), CREATE_REFERENCE);
    auto monitor = std::make_unique<JsUtil::CallbackInfo>();
    monitor->env = env;
    monitor->ref = ref;
    iter->second.push_back(std::move(monitor));
    if (!isListeningProcess_) {
        isListeningProcess_ = true;
        InputManager::GetInstance()->RegisterDevListener("change", shared_from_this());
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
        InputManager::GetInstance()->UnregisterDevListener("change", shared_from_this());
    }
}

napi_value JsEventTarget::GreateBusinessError(napi_env env, int32_t errCode, std::string errMessage)
{
    CALL_DEBUG_ENTER;
    napi_value result = nullptr;
    napi_value resultCode = nullptr;
    napi_value resultMessage = nullptr;
    CHKRP(napi_create_int32(env, errCode, &resultCode), CREATE_INT32);
    CHKRP(napi_create_string_utf8(env, errMessage.data(), NAPI_AUTO_LENGTH, &resultMessage), CREATE_STRING_UTF8);
    CHKRP(napi_create_error(env, nullptr, resultMessage, &result), CREATE_ERROR);
    CHKRP(napi_set_named_property(env, result, ERR_CODE.c_str(), resultCode), SET_NAMED_PROPERTY);
    return result;
}

napi_value JsEventTarget::CreateCallbackInfo(napi_env env, napi_value handle, sptr<JsUtil::CallbackInfo> cb)
{
    CALL_DEBUG_ENTER;
    CHKPP(cb);
    cb->env = env;
    napi_value promise = nullptr;
    if (handle == nullptr) {
        CHKRP(napi_create_promise(env, &cb->deferred, &promise), CREATE_PROMISE);
    } else {
        CHKRP(napi_create_reference(env, handle, 1, &cb->ref), CREATE_REFERENCE);
    }
    return promise;
}

void JsEventTarget::EmitJsGetIntervalSinceLastInput(sptr<JsUtil::CallbackInfo> cb, int64_t timeInterval)
{
    CALL_DEBUG_ENTER;
    CHKPV(cb);
    CHKPV(cb->env);
    cb->data.IntervalSinceLastInput = timeInterval;
    cb->errCode = RET_OK;
    uv_loop_s *loop = nullptr;
    CHKRV(napi_get_uv_event_loop(cb->env, &loop), GET_UV_EVENT_LOOP);
    uv_work_t *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    cb->IncStrongRef(nullptr);
    work->data = cb.GetRefPtr();
    int32_t ret = 0;
    if (cb->ref == nullptr) {
        ret = uv_queue_work_with_qos(
            loop, work,
            [](uv_work_t *work) {
                MMI_HILOGD("uv_queue_work callback function is called");
            },
            CallIntervalSinceLastInputPromise, uv_qos_user_initiated);
    } else {
        ret = uv_queue_work_with_qos(
            loop, work,
            [](uv_work_t *work) {
                MMI_HILOGD("uv_queue_work callback function is called");
            },
            CallIntervalSinceLastInputAsync, uv_qos_user_initiated);
    }
    if (ret != 0) {
        MMI_HILOGE("uv_queue_work_with_qos failed");
        JsUtil::DeletePtr<uv_work_t *>(work);
    }
}

void JsEventTarget::CallIntervalSinceLastInputPromise(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
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
        if (callResult == nullptr) {
            MMI_HILOGE("callResult is nullptr");
            napi_close_handle_scope(cb->env, scope);
            return;
        }
        CHKRV_SCOPE(cb->env, napi_reject_deferred(cb->env, cb->deferred, callResult), REJECT_DEFERRED, scope);
    } else {
        CHKRV_SCOPE(cb->env, napi_create_int64(cb->env, cb->data.IntervalSinceLastInput, &callResult),
            CREATE_INT64, scope);
        CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, callResult), RESOLVE_DEFERRED, scope);
    }
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::CallIntervalSinceLastInputAsync(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t *>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t *>(work);
    cb->DecStrongRef(nullptr);
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
        if (callResult[0] == nullptr) {
            MMI_HILOGE("callResult[0] is nullptr");
            napi_close_handle_scope(cb->env, scope);
            return;
        }
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[1]), GET_UNDEFINED, scope);
    } else {
        CHKRV_SCOPE(cb->env, napi_create_int64(cb->env, cb->data.IntervalSinceLastInput, &callResult[1]),
            CREATE_INT64, scope);
        CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &callResult[0]), GET_UNDEFINED, scope);
    }
    napi_value handler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE_VALUE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, handler, INPUT_PARAMETER_MIDDLE, callResult, &result),
        CALL_FUNCTION, scope);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::ResetEnv()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    devListener_.clear();
    InputManager::GetInstance()->UnregisterDevListener("change", shared_from_this());
}
} // namespace MMI
} // namespace OHOS
