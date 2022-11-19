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
#ifndef PROTO_H
#define PROTO_H

#include <sys/types.h>

enum class MmiMessageId : int32_t {
    INVALID,
    INPUT_DEVICE,
    INPUT_DEVICE_IDS,
    INPUT_DEVICE_SUPPORT_KEYS,
    ADD_INPUT_DEVICE_LISTENER,
    INPUT_DEVICE_KEYBOARD_TYPE,
    DISPLAY_INFO,
    NOTICE_ANR,
    MARK_PROCESS,
    ON_SUBSCRIBE_KEY,
    ON_KEY_EVENT,
    ON_POINTER_EVENT,
    REPORT_KEY_EVENT,
    REPORT_POINTER_EVENT,
    ON_DEVICE_ADDED,
    ON_DEVICE_REMOVED,

#ifdef OHOS_BUILD_ENABLE_COOPERATE
    COOPERATION_ADD_LISTENER,
    COOPERATION_MESSAGE,
    COOPERATION_GET_STATE,
#endif // OHOS_BUILD_ENABLE_COOPERATE
};

enum INPUT_DEVICE_TYPE {
    INPUT_DEVICE_CAP_KEYBOARD = 0,
    INPUT_DEVICE_CAP_POINTER = 1,
    INPUT_DEVICE_CAP_TOUCH = 2,
    INPUT_DEVICE_CAP_TABLET_TOOL = 3,
    INPUT_DEVICE_CAP_TABLET_PAD = 4,
    INPUT_DEVICE_CAP_GESTURE = 5,
    INPUT_DEVICE_CAP_SWITCH = 6,
    INPUT_DEVICE_CAP_JOYSTICK = 7,
    INPUT_DEVICE_CAP_AISENSOR = 8,
    INPUT_DEVICE_CAP_TOUCH_PAD = 9,
    INPUT_DEVICE_CAP_REMOTE_CONTROL = 10,
    INPUT_DEVICE_CAP_TRACK_BALL = 11,
    INPUT_DEVICE_CAP_KNUCKLE = 12,
    INPUT_DEVICE_CAP_TRACKPAD5 = 13,
    INPUT_DEVICE_CAP_GAMEPAD = 14,
};

enum KeyboardType {
    KEYBOARD_TYPE_NONE,
    KEYBOARD_TYPE_UNKNOWN,
    KEYBOARD_TYPE_ALPHABETICKEYBOARD,
    KEYBOARD_TYPE_DIGITALKEYBOARD,
    KEYBOARD_TYPE_HANDWRITINGPEN,
    KEYBOARD_TYPE_REMOTECONTROL,
};

enum TokenType : int32_t {
    TOKEN_INVALID = -1,
    TOKEN_HAP = 0,
    TOKEN_NATIVE,
    TOKEN_SHELL,
};

enum ANREventType {
    ANR_DISPATCH,
    ANR_MONITOR,
};
#endif // PROTO_H