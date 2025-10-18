/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ANI_INPUT_TAIHE_COMMON_H
#define ANI_INPUT_TAIHE_COMMON_H

#include <map>
#include <string>

namespace OHOS {
namespace MMI {

struct TaiheError {
    int32_t errorCode;
    std::string msg;
};

enum TaiheErrorCode : int32_t {
    OTHER_ERROR = -1,
    COMMON_PERMISSION_CHECK_ERROR = 201,
    COMMON_USE_SYSAPI_ERROR = 202,
    COMMON_PARAMETER_ERROR = 401,
    INPUT_DEVICE_NOT_SUPPORTED = 801,
    COMMON_DEVICE_NOT_EXIST = 3900001,
    COMMON_KEYBOARD_DEVICE_NOT_EXIST = 3900002,
    COMMON_NON_INPUT_APPLICATION = 3900003,
    PRE_KEY_NOT_SUPPORTED = 4100001,
    INPUT_OCCUPIED_BY_SYSTEM = 4200002,
    INPUT_OCCUPIED_BY_OTHER = 4200003,
    ERROR_WINDOW_ID_PERMISSION_DENIED = 26500001,
};

const std::map<int32_t, TaiheError> TAIHE_ERRORS = {
    { COMMON_PERMISSION_CHECK_ERROR,
        { COMMON_PERMISSION_CHECK_ERROR,
            "Permission denied. An attempt was made to %s forbidden by permission:%s." } },
    { COMMON_USE_SYSAPI_ERROR,
        { COMMON_USE_SYSAPI_ERROR, "Permission denied, non-system application called system api." } },
    { COMMON_PARAMETER_ERROR, { COMMON_PARAMETER_ERROR, "Parameter error. The type of %s must be %s." } },
    { COMMON_DEVICE_NOT_EXIST, { COMMON_DEVICE_NOT_EXIST, "The specified device does not exist." } },
    { COMMON_KEYBOARD_DEVICE_NOT_EXIST,
        { COMMON_KEYBOARD_DEVICE_NOT_EXIST, "The specified keyboard device does not exist." } },
    { COMMON_NON_INPUT_APPLICATION, { COMMON_NON_INPUT_APPLICATION, "it is prohibited for non-input applications." } },
    { INPUT_DEVICE_NOT_SUPPORTED, { INPUT_DEVICE_NOT_SUPPORTED, "Capability not supported.\n" } },
    { ERROR_WINDOW_ID_PERMISSION_DENIED, { ERROR_WINDOW_ID_PERMISSION_DENIED,
        "Invalid windowId. Possible causes: The window id does not belong to the current process.\n" } },
    { PRE_KEY_NOT_SUPPORTED, { PRE_KEY_NOT_SUPPORTED, "Invalid combination of keys." } },
    { INPUT_OCCUPIED_BY_SYSTEM, { INPUT_OCCUPIED_BY_SYSTEM, "The hotkey has been subscribed by system." } },
    { INPUT_OCCUPIED_BY_OTHER, { INPUT_OCCUPIED_BY_OTHER, "The hotkey has been subscribed by other one." } },
};

class TaiheConverter {
public:
    static bool GetApiError(int32_t code, TaiheError &codeMsg);
};
} // namespace MMI
} // namespace OHOS
#endif // ANI_INPUT_TAIHE_INPUT_MONITOR_COMMON_H