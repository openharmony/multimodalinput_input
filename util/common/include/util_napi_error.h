/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef UTIL_NAPI_ERROR_H
#define UTIL_NAPI_ERROR_H

#include <map>
#include <string>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "securec.h"
#include "utils/log.h"

#include "util_napi.h"

namespace OHOS {
namespace MMI {
const std::string ERR_CODE = "code";
struct NapiError {
    int32_t errorCode;
    std::string msg;
};

enum NapiErrorCode : int32_t {
    OTHER_ERROR = -1,
    COMMON_PERMISSION_CHECK_ERROR = 201,
    COMMON_PARAMETER_ERROR = 401,
    COMMON_USE_SYSAPI_ERROR = 202,
    COMMON_CAPABILITY_NOT_SUPPORTED = 801,
};

const std::map<int32_t, NapiError> NAPI_ERRORS = {
    { COMMON_PERMISSION_CHECK_ERROR,
        { COMMON_PERMISSION_CHECK_ERROR, "Permission denied. An attempt was made to %s forbidden by permission:%s." } },
    { COMMON_PARAMETER_ERROR, { COMMON_PARAMETER_ERROR, "Parameter error. The type of %s must be %s." } },
};

#define THROWERR_CUSTOM(env, code, msg) \
    do { \
        napi_value businessError = nullptr; \
        napi_value errorCode = nullptr; \
        napi_value errorMsg = nullptr; \
        napi_create_int32(env, code, &errorCode); \
        napi_create_string_utf8(env, std::string(msg).c_str(), NAPI_AUTO_LENGTH, &errorMsg); \
        napi_create_error(env, nullptr, errorMsg, &businessError); \
        napi_set_named_property(env, businessError, ERR_CODE.c_str(), errorCode); \
        napi_throw(env, businessError); \
    } while (0)

#define THROWERR_API9(env, code, param1, param2) \
    do { \
        MMI_HILOGE("ErrorCode:%{public}s", (#code)); \
        NapiError codeMsg; \
        if (UtilNapiError::GetApiError(code, codeMsg)) { \
            char buf[300]; \
            if (sprintf_s(buf, sizeof(buf), codeMsg.msg.c_str(), param1, param2) > 0) { \
                THROWERR_CUSTOM(env, code, buf); \
            } else { \
                MMI_HILOGE("Failed to convert string type to char type"); \
            } \
        } \
    } while (0)
namespace UtilNapiError {
bool GetApiError(int32_t code, NapiError &codeMsg);
} // namespace UtilNapiError
} // namespace MMI
} // namespace OHOS
#endif // UTIL_NAPI_ERROR_H
