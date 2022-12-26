/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <new>

#include <uv.h>

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_manager_impl.h"
#include "mmi_log.h"
#include "napi_constants.h"
#include "util_napi.h"
#include "util_napi_error.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsEventTarget" };
constexpr std::string_view COOPERATION = "cooperation";
std::mutex mutex_;
} // namespace

JsEventTarget::JsEventTarget()
{
    CALL_DEBUG_ENTER;
    auto ret = cooperateListener_.insert({ COOPERATION, std::vector<std::unique_ptr<JsUtil::CallbackInfo>>() });
    CK(ret.second, VAL_NOT_EXP);
}

void JsEventTarget::EmitJsEnable(sptr<JsUtil::CallbackInfo> cb, const std::string &deviceId, const CooperationMessage &msg)
{
    CALL_INFO_TRACE;
    CHKPV(cb);
    CHKPV(cb->env);
    cb->data.enableResult = (msg == CooperationMessage::OPEN_SUCCESS || msg == CooperationMessage::CLOSE_SUCCESS);
    cb->data.errCode = static_cast<int32_t>(msg);
    uv_loop_s *loop = nullptr;
    CHKRV(napi_get_uv_event_loop(cb->env, &loop), GET_UV_EVENT_LOOP);
    uv_work_s *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    cb->IncStrongRef(nullptr);
    work->data = cb.GetRefPtr();
    int32_t result;
    if (cb->ref == nullptr) {
        result = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallEnablePromiseWork);
    } else {
        result = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallEnableAsyncWork);
    }

    if (result != 0) {
        MMI_HILOGE("uv_queue_work failed");
        JsUtil::DeletePtr<uv_work_t*>(work);
    }
}

void JsEventTarget::EmitJsStart(sptr<JsUtil::CallbackInfo> cb, const std::string &deviceId, const CooperationMessage &msg)
{
    CALL_INFO_TRACE;
    CHKPV(cb);
    CHKPV(cb->env);
    cb->data.startResult = (msg == CooperationMessage::INFO_SUCCESS);
    cb->data.errCode = static_cast<int32_t>(msg);
    uv_loop_s *loop = nullptr;
    CHKRV(napi_get_uv_event_loop(cb->env, &loop), GET_UV_EVENT_LOOP);
    uv_work_s *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    cb->IncStrongRef(nullptr);
    work->data = cb.GetRefPtr();
    int32_t result;
    if (cb->ref == nullptr) {
        result = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallStartPromiseWork);
    } else {
        result = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallStartAsyncWork);
    }

    if (result != 0) {
        MMI_HILOGE("uv_queue_work failed");
        JsUtil::DeletePtr<uv_work_t*>(work);
    }
}

void JsEventTarget::EmitJsStop(sptr<JsUtil::CallbackInfo> cb, const std::string &deviceId, const CooperationMessage &msg)
{
    CALL_INFO_TRACE;
    CHKPV(cb);
    CHKPV(cb->env);
    cb->data.stopResult = (msg == CooperationMessage::STOP_SUCCESS);
    cb->data.errCode = static_cast<int32_t>(msg);
    uv_loop_s *loop = nullptr;
    CHKRV(napi_get_uv_event_loop(cb->env, &loop), GET_UV_EVENT_LOOP);
    uv_work_s *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    cb->IncStrongRef(nullptr);
    work->data = cb.GetRefPtr();
    int32_t result;
    if (cb->ref == nullptr) {
        result = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallStopPromiseWork);
    } else {
        result = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallStopAsyncWork);
    }

    if (result != 0) {
        MMI_HILOGE("uv_queue_work failed");
        JsUtil::DeletePtr<uv_work_t*>(work);
    }
}

void JsEventTarget::EmitJsGetState(sptr<JsUtil::CallbackInfo> cb, bool state)
{
    CALL_INFO_TRACE;
    CHKPV(cb);
    CHKPV(cb->env);
    cb->data.cooperateOpened = state;
    uv_loop_s *loop = nullptr;
    CHKRV(napi_get_uv_event_loop(cb->env, &loop), GET_UV_EVENT_LOOP);
    uv_work_s *work = new (std::nothrow) uv_work_t;
    CHKPV(work);
    cb->IncStrongRef(nullptr);
    work->data = cb.GetRefPtr();
    int32_t result;
    if (cb->ref == nullptr) {
        result = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallGetStatePromiseWork);
    } else {
        result = uv_queue_work(loop, work, [](uv_work_t *work) {}, CallGetStateAsyncWork);
    }

    if (result != 0) {
        MMI_HILOGE("uv_queue_work failed");
        JsUtil::DeletePtr<uv_work_t*>(work);
    }
}

void JsEventTarget::AddListener(napi_env env, const std::string &type, napi_value handle)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = cooperateListener_.find(type);
    if (iter == cooperateListener_.end()) {
        MMI_HILOGE("Find %{public}s failed", type.c_str());
        return;
    }

    for (const auto &item : iter->second) {
        CHKPC(item);
        if (JsUtil::IsSameHandle(env, handle, item->ref)) {
            MMI_HILOGE("The handle already exists");
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
        InputMgrImpl.RegisterCooperateListener(shared_from_this());
    }
}

void JsEventTarget::RemoveListener(napi_env env, const std::string &type, napi_value handle)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = cooperateListener_.find(type);
    if (iter == cooperateListener_.end()) {
        MMI_HILOGE("Find %{public}s failed", type.c_str());
        return;
    }
    if (handle == nullptr) {
        iter->second.clear();
        goto monitorLabel;
    }
    for (auto it = iter->second.begin(); it != iter->second.end(); ++it) {
        if (JsUtil::IsSameHandle(env, handle, (*it)->ref)) {
            MMI_HILOGE("Success in removing monitor");
            iter->second.erase(it);
            goto monitorLabel;
        }
    }

monitorLabel:
    if (isListeningProcess_ && iter->second.empty()) {
        isListeningProcess_ = false;
        InputMgrImpl.UnregisterCooperateListener(shared_from_this());
    }
}

napi_value JsEventTarget::CreateCallbackInfo(napi_env env, napi_value handle, sptr<JsUtil::CallbackInfo> cb)
{
    CALL_INFO_TRACE;
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

void JsEventTarget::ResetEnv()
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    cooperateListener_.clear();
    InputMgrImpl.UnregisterCooperateListener(shared_from_this());
}

void JsEventTarget::OnCooperateMessage(const std::string &deviceId, CooperationMessage msg)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    auto changeEvent = cooperateListener_.find(COOPERATION);
    if (changeEvent == cooperateListener_.end()) {
        MMI_HILOGE("Find %{public}s failed", std::string(COOPERATION).c_str());
        return;
    }

    for (auto &item : changeEvent->second) {
        CHKPC(item);
        CHKPC(item->env);
        uv_loop_s *loop = nullptr;
        CHKRV(napi_get_uv_event_loop(item->env, &loop), GET_UV_EVENT_LOOP);
        uv_work_t *work = new (std::nothrow) uv_work_t;
        CHKPV(work);
        item->data.msg = msg;
        item->data.deviceDescriptor = deviceId;
        work->data = static_cast<void*>(&item);
        int32_t result = uv_queue_work(loop, work, [](uv_work_t *work) {}, EmitCooperateMessageEvent);
        if (result != 0) {
            MMI_HILOGE("uv_queue_work failed");
            JsUtil::DeletePtr<uv_work_t*>(work);
        }
    }
}

void JsEventTarget::CallEnablePromiseWork(uv_work_t *work, int32_t status)
{
    CALL_INFO_TRACE;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t*>(work);
    cb->DecStrongRef(nullptr);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        MMI_HILOGE("scope is nullptr");
        return;
    }
    napi_value object = JsUtil::GetEnableInfo(cb);
    if (object == nullptr) {
        MMI_HILOGE("object is nullptr");
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(cb->env, object, &valueType) != napi_ok) {
        MMI_HILOGE("napi typeof failed");
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    if (valueType != napi_undefined) {
        CHKRV_SCOPE(cb->env, napi_reject_deferred(cb->env, cb->deferred, object), REJECT_DEFERRED, scope);
    } else {
        CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, object), RESOLVE_DEFERRED, scope);
    }
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::CallEnableAsyncWork(uv_work_t *work, int32_t status)
{
    CALL_INFO_TRACE;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t*>(work);
    cb->DecStrongRef(nullptr);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        MMI_HILOGE("scope is nullptr");
        return;
    }
    napi_value object = JsUtil::GetEnableInfo(cb);
    if (object == nullptr) {
        MMI_HILOGE("object is nullptr");
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    napi_value handler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE_VALUE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, handler, 1, &object, &result), CALL_FUNCTION, scope);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::CallStartPromiseWork(uv_work_t *work, int32_t status)
{
    CALL_INFO_TRACE;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t*>(work);
    cb->DecStrongRef(nullptr);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        MMI_HILOGE("scope is nullptr");
        return;
    }
    napi_value object = JsUtil::GetStartInfo(cb);
    if (object == nullptr) {
        MMI_HILOGE("object is nullptr");
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(cb->env, object, &valueType) != napi_ok) {
        MMI_HILOGE("napi typeof failed");
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    if (valueType != napi_undefined) {
        CHKRV_SCOPE(cb->env, napi_reject_deferred(cb->env, cb->deferred, object), REJECT_DEFERRED, scope);
    } else {
        CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, object), RESOLVE_DEFERRED, scope);
    }
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::CallStartAsyncWork(uv_work_t *work, int32_t status)
{
    CALL_INFO_TRACE;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t*>(work);
    cb->DecStrongRef(nullptr);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        MMI_HILOGE("scope is nullptr");
        return;
    }
    napi_value object = JsUtil::GetStartInfo(cb);
    if (object == nullptr) {
        MMI_HILOGE("object is nullptr");
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    napi_value handler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE_VALUE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, handler, 1, &object, &result), CALL_FUNCTION, scope);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::CallStopPromiseWork(uv_work_t *work, int32_t status)
{
    CALL_INFO_TRACE;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t*>(work);
    cb->DecStrongRef(nullptr);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        MMI_HILOGE("scope is nullptr");
        return;
    }
    napi_value object = JsUtil::GetStopInfo(cb);
    if (object == nullptr) {
        MMI_HILOGE("object is nullptr");
        napi_close_handle_scope(cb->env, scope);
        return;
    }

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(cb->env, object, &valueType) != napi_ok) {
        MMI_HILOGE("napi typeof failed");
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    if (valueType != napi_undefined) {
        CHKRV_SCOPE(cb->env, napi_reject_deferred(cb->env, cb->deferred, object), REJECT_DEFERRED, scope);
    } else {
        CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, object), RESOLVE_DEFERRED, scope);
    }
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::CallStopAsyncWork(uv_work_t *work, int32_t status)
{
    CALL_INFO_TRACE;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t*>(work);
    cb->DecStrongRef(nullptr);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        MMI_HILOGE("scope is nullptr");
        return;
    }
    napi_value object = JsUtil::GetStopInfo(cb);
    if (object == nullptr) {
        MMI_HILOGE("object is nullptr");
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    napi_value handler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE_VALUE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, handler, 1, &object, &result), CALL_FUNCTION, scope);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::CallGetStatePromiseWork(uv_work_t *work, int32_t status)
{
    CALL_INFO_TRACE;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t*>(work);
    cb->DecStrongRef(nullptr);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        MMI_HILOGE("scope is nullptr");
        return;
    }
    napi_value object = JsUtil::GetStateInfo(cb);
    if (object == nullptr) {
        MMI_HILOGE("object is nullptr");
        napi_close_handle_scope(cb->env, scope);
        return;
    }
    CHKRV_SCOPE(cb->env, napi_resolve_deferred(cb->env, cb->deferred, object), RESOLVE_DEFERRED, scope);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::CallGetStateAsyncWork(uv_work_t *work, int32_t status)
{
    CALL_INFO_TRACE;
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }
    sptr<JsUtil::CallbackInfo> cb(static_cast<JsUtil::CallbackInfo *>(work->data));
    JsUtil::DeletePtr<uv_work_t*>(work);
    cb->DecStrongRef(nullptr);
    CHKPV(cb->env);
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        MMI_HILOGE("scope is nullptr");
        return;
    }
    napi_value resultObj[2];
    CHKRV_SCOPE(cb->env, napi_get_undefined(cb->env, &resultObj[0]), GET_UNDEFINED, scope);
    resultObj[1] = JsUtil::GetStateInfo(cb);
    if (resultObj[1] == nullptr) {
        MMI_HILOGE("Object is nullptr");
        napi_close_handle_scope(cb->env, scope);
    }
    napi_value handler = nullptr;
    CHKRV_SCOPE(cb->env, napi_get_reference_value(cb->env, cb->ref, &handler), GET_REFERENCE_VALUE, scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(cb->env, napi_call_function(cb->env, nullptr, handler, 2, resultObj, &result), CALL_FUNCTION, scope);
    napi_close_handle_scope(cb->env, scope);
}

void JsEventTarget::EmitCooperateMessageEvent(uv_work_t *work, int32_t status)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    CHKPV(work);
    if (work->data == nullptr) {
        JsUtil::DeletePtr<uv_work_t*>(work);
        MMI_HILOGE("Check data is nullptr");
        return;
    }

    auto temp = static_cast<std::unique_ptr<JsUtil::CallbackInfo>*>(work->data);
    JsUtil::DeletePtr<uv_work_t*>(work);

    auto messageEvent = cooperateListener_.find(COOPERATION);
    if (messageEvent == cooperateListener_.end()) {
        MMI_HILOGE("Find messageEvent failed");
        return;
    }

    for (const auto &item : messageEvent->second) {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(item->env, &scope);
        CHKPC(item->env);
        if (item->ref != (*temp)->ref) {
            continue;
        }
        napi_value deviceDescriptor = nullptr;
        CHKRV_SCOPE(item->env, napi_create_string_utf8(item->env, item->data.deviceDescriptor.c_str(),
            NAPI_AUTO_LENGTH, &deviceDescriptor), CREATE_STRING_UTF8, scope);
        napi_value eventMsg = nullptr;
        CHKRV_SCOPE(item->env, napi_create_int32(item->env, static_cast<int32_t>(item->data.msg), &eventMsg),
            CREATE_INT32, scope);
        napi_value object = nullptr;
        CHKRV_SCOPE(item->env, napi_create_object(item->env, &object), CREATE_OBJECT, scope);
        CHKRV_SCOPE(item->env, napi_set_named_property(item->env, object, "deviceDescriptor", deviceDescriptor),
            SET_NAMED_PROPERTY, scope);
        CHKRV_SCOPE(item->env, napi_set_named_property(item->env, object, "eventMsg", eventMsg),
            SET_NAMED_PROPERTY, scope);

        napi_value handler = nullptr;
        CHKRV_SCOPE(item->env, napi_get_reference_value(item->env, item->ref, &handler), GET_REFERENCE_VALUE, scope);
        napi_value ret = nullptr;
        CHKRV_SCOPE(item->env, napi_call_function(item->env, nullptr, handler, 1, &object, &ret), CALL_FUNCTION, scope);
        napi_close_handle_scope(item->env, scope);
    }
}

void JsEventTarget::HandleExecuteResult(napi_env env, int32_t errCode)
{
    if (errCode != OTHER_ERROR && errCode != RET_OK) {
        NapiError napiError;
        if (!UtilNapiError::GetApiError(errCode, napiError)) {
            MMI_HILOGE("This error code could not be found");
            return;
        }
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, napiError.msg.c_str());
    }
}
} // namespace MMI
} // namespace OHOS
