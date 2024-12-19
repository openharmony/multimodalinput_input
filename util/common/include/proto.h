/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef PROTO_H
#define PROTO_H

#include <sys/types.h>

enum class MmiMessageId : int32_t {
    INVALID,
    ADD_INPUT_DEVICE_LISTENER,
    DISPLAY_INFO,
    NOTICE_ANR,
    MARK_PROCESS,
    ON_SUBSCRIBE_KEY,
    ON_SUBSCRIBE_SWITCH,
    ON_KEY_EVENT,
    ON_POINTER_EVENT,
    REPORT_KEY_EVENT,
    REPORT_POINTER_EVENT,
    ON_DEVICE_ADDED,
    ON_DEVICE_REMOVED,
    SCINFO_CONFIG,
    WINDOW_AREA_INFO,
    NOTIFY_BUNDLE_NAME,
    WINDOW_INFO,
};

enum TokenType : int32_t {
    TOKEN_INVALID = -1,
    TOKEN_HAP = 0,
    TOKEN_NATIVE,
    TOKEN_SHELL,
    TOKEN_SYSTEM_HAP,
};

enum ANTTimeOutTime : int64_t {
    INPUT_UI_TIMEOUT_TIME = 5 * 1000000
};

enum ANREventType {
    ANR_DISPATCH,
    ANR_MONITOR,
    ANR_EVENT_TYPE_NUM,
};
#endif // PROTO_H
