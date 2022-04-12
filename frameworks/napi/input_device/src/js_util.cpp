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
#include "util_napi.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsUtil" };
const std::string GET_REFERENCE = "napi_get_reference_value";
const std::string STRICT_EQUALS = "napi_strict_equals";
const std::string DELETE_REFERENCE = "napi_delete_reference";
} // namespace
int32_t JsUtil::GetInt32(uv_work_t *work)
{
    int32_t *uData = static_cast<int32_t*>(work->data);
    int32_t userData = *uData;
    delete uData;
    delete work;
    return userData;
}

bool JsUtil::IsHandleEquals(napi_env env, napi_value handle, napi_ref ref)
{
    napi_value handlerTemp = nullptr;
    CHKRB(env, napi_get_reference_value(env, ref, &handlerTemp), GET_REFERENCE);
    bool isEqual = false;
    CHKRB(env, napi_strict_equals(env, handle, handlerTemp, &isEqual), STRICT_EQUALS);
    return isEqual;
}

JsUtil::CallbackInfo::CallbackInfo() {}

JsUtil::CallbackInfo::~CallbackInfo()
{
    CALL_LOG_ENTER;
    if (ref != nullptr && env != nullptr) {
        CHKRV(env, napi_delete_reference(env, ref), DELETE_REFERENCE);
        env = nullptr;
    }
}
} // namespace MMI
} // namespace OHOS