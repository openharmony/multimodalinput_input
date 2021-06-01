/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef MULTIMODAL_INPUT_ERRORS_H
#define MULTIMODAL_INPUT_ERRORS_H

#include <errors.h>

namespace OHOS {
enum {
    MODULE_COMMON = 0x00,
    MODULE_INPUT_READER = 0x01,
    MODULE_INPUT_ABILITY_AWARE = 0x02,
    MODULE_INTENT_DICTIONARY = 0x03,
    MODULE_FUSION_DISCRIMINATION = 0x04,
    MODULE_DISPATCHER = 0x05,
    MODULE_WINDOW_AWARE = 0x06,
};

// Error code for common
constexpr ErrCode COMMON_ERR_OFFSET = ErrCodeOffset(SUBSYS_MULTIMODAINPUT, MODULE_COMMON);

enum {
    MMI_NOT_IMPLEMENTED = COMMON_ERR_OFFSET,
    MMI_EVENT_MISMATCH,
    MMI_MEMCPY_FAIL,
    MMI_ARGUMENT_NULL,
    MMI_LOCAL_PTR_NULL,
    MMI_LOCAL_STORAGE_EMPTY,
    MMI_WINDOW_NOT_EXIST,
    MMI_BINDER_PID_MISMATCH,
    MMI_BINDER_UID_MISMATCH,
    MMI_SERIVCE_ABNORMAL,
    MMI_CHANNEL_NULL,
    MMI_SOCKET_ERR,
    MMI_PERMISSION_ERR,
    MMI_BAD_TYPE,
};

// Error code for input reader
constexpr ErrCode INPUT_READER_ERR_OFFSET = ErrCodeOffset(SUBSYS_MULTIMODAINPUT, MODULE_INPUT_READER);

enum {
    INPUT_READER_ERR = INPUT_READER_ERR_OFFSET,
};

// Error code for input ability aware
constexpr ErrCode INPUT_ABILITY_AWARE_ERR_OFFSET = ErrCodeOffset(SUBSYS_MULTIMODAINPUT, MODULE_INPUT_ABILITY_AWARE);

enum {
    INPUT_ABILITY_AWARE_NOT_SUPPORTTED = INPUT_ABILITY_AWARE_ERR_OFFSET,
    INPUT_ABILITY_AWARE_SOURCE_NOT_FOUND,
    INPUT_ABILITY_AWARE_INVALID_VALUE,
    INPUT_ABILITY_AWARE_INPUT_NOT_REGISTERED,
    INPUT_ABILITY_AWARE_INPUT_EMPTY,
    INPUT_INJECT_SERVICE_INVALID,
    INPUT_INJECT_COMMAND_INVALID,
    INPUT_INJECT_ARGUMENT_INVALID,
};

// Error code for window aware
constexpr ErrCode WINDOW_AWARE_ERR_OFFSET = ErrCodeOffset(SUBSYS_MULTIMODAINPUT, MODULE_WINDOW_AWARE);

enum {
    WINDOW_AWARE_ERR = WINDOW_AWARE_ERR_OFFSET,
};
} // namespace OHOS

#endif // MULTIMODAL_INPUT_ERRORS_H
