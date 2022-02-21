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
#ifndef HDF_INJECT_INIT_H
#define HDF_INJECT_INIT_H
enum  DrvType {
    TOUCH = 0,
    MOUSE,
    KEYBOARD,
    PEN,    /* tag = 33 */
    PAD, /* tag = 289 */
    FINGER, /* tag = 2089 */
    JOYSTICK, /* 65 */
    SWITCH5,
    TRACKPAD5,
    GAMEPAD,
    TRACKBALL,
    INVALD = 100,
};
#endif // HDF_INJECT_INIT_H