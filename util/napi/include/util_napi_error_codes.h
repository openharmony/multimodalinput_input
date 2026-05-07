/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef UTIL_NAPI_ERROR_CODES_H
#define UTIL_NAPI_ERROR_CODES_H

namespace OHOS {
namespace MMI {
enum NapiErrorCode : int32_t {
    OTHER_ERROR = -1,
    COMMON_PERMISSION_CHECK_ERROR = 201,
    COMMON_PARAMETER_ERROR = 401,
    COMMON_USE_SYSAPI_ERROR = 202,
    INPUT_DEVICE_NOT_SUPPORTED = 801,
    INPUT_OCCUPIED_BY_SYSTEM = 4200002,
    INPUT_OCCUPIED_BY_OTHER = 4200003,
    PRE_KEY_NOT_SUPPORTED = 4100001,
    COMMON_DEVICE_NOT_EXIST = 3900001,
    COMMON_KEYBOARD_DEVICE_NOT_EXIST = 3900002,
    COMMON_NON_INPUT_APPLICATION = 3900003,
    CONTROLLER_INPUT_SERVICE_EXCEPTION = 3800001,
    ERROR_CODE_STATE_ERROR = 4300001,
    CONTROLLER_DISPLAY_NOT_EXIST = 4300002,
    ERROR_WINDOW_ID_PERMISSION_DENIED = 26500001,
    INPUT_SERVICE_EXCEPTION = 3800001,
};
} // namespace MMI
} // namespace OHOS
#endif // UTIL_NAPI_ERROR_CODES_H
