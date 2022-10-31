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

#include "js_util.h"

#include "mmi_log.h"
#include "napi_constants.h"
#include "util_napi_error.h"
#include "util_napi.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsUtil" };
} // namespace

JsUtil::CallbackInfo::~CallbackInfo()
{
    CALL_DEBUG_ENTER;
    if (ref != nullptr && env != nullptr) {
        CHKRV(env, napi_delete_reference(env, ref), DELETE_REFERENCE);
        env = nullptr;
    }
}

napi_value JsUtil::GetEnableInfo(const std::unique_ptr<CallbackInfo> &cb)
{
    CHKPP(cb);
    CHKPP(cb->env);
    return GetResult(cb->env, cb->data.enableResult, cb->data.errCode);
}

napi_value JsUtil::GetStartInfo(const std::unique_ptr<CallbackInfo> &cb)
{
    CHKPP(cb);
    CHKPP(cb->env);
    return GetResult(cb->env, cb->data.startResult, cb->data.errCode);
}

napi_value JsUtil::GetStopInfo(const std::unique_ptr<CallbackInfo> &cb)
{
    CHKPP(cb);
    CHKPP(cb->env);
    return GetResult(cb->env, cb->data.stopResult, cb->data.errCode);
}

napi_value JsUtil::GetStateInfo(const std::unique_ptr<CallbackInfo> &cb)
{
    CHKPP(cb);
    CHKPP(cb->env);
    napi_value ret = nullptr;
    napi_value state = nullptr;
    CHKRP(cb->env, napi_create_int32(cb->env, cb->data.cooperateOpened ? 1 : 0, &ret),
        CREATE_INT32);
    CHKRP(cb->env, napi_coerce_to_bool(cb->env, ret, &state), COERCE_TO_BOOL);
    return state;
}

napi_value JsUtil::GetResult(napi_env env, bool result, int32_t errCode)
{
    CHKPP(env);
    napi_value object = nullptr;
    if (result) {
        napi_get_undefined(env, &object);
    } else {
        NapiError napiError;
        if (!UtilNapiError::GetApiError(errCode, napiError)) {
            MMI_HILOGE("This error code could not be found");
            return nullptr;
        }
        napi_value resultCode = nullptr;
        CHKRP(env, napi_create_int32(env, errCode, &resultCode), CREATE_INT32);
        napi_value resultMessage = nullptr;
        CHKRP(env, napi_create_string_utf8(env, napiError.msg.data(), NAPI_AUTO_LENGTH, &resultMessage), CREATE_INT32);
        CHKRP(env, napi_create_error(env, nullptr, resultMessage, &object), CREATE_ERROR);
        CHKRP(env, napi_set_named_property(env, object, ERR_CODE.c_str(), resultCode), SET_NAMED_PROPERTY);
    }
    return object;
}

napi_value JsUtil::GetStateResult(napi_env env, bool result)
{
    CHKPP(env);
    napi_value state = nullptr;
    CHKRP(env, napi_get_boolean(env, result, &state), GET_BOOLEAN);
    napi_value object = nullptr;
    CHKRP(env, napi_create_object(env, &object), CREATE_OBJECT);
    CHKRP(env, napi_set_named_property(env,  object, "state", state), SET_NAMED_PROPERTY);
    return object;
}

bool JsUtil::IsSameHandle(napi_env env, napi_value handle, napi_ref ref)
{
    napi_value handlerTemp = nullptr;
    CHKRF(env, napi_get_reference_value(env, ref, &handlerTemp), GET_REFERENCE_VALUE);
    bool isEqual = false;
    CHKRF(env, napi_strict_equals(env, handle, handlerTemp, &isEqual), STRICT_EQUALS);
    return isEqual;
}
} // namespace MMI
} // namespace OHOS
