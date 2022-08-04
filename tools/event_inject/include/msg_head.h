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

#ifndef MSG_HEAD_H
#define MSG_HEAD_H

#include <algorithm>
#include <ctime>
#include <cstdio>
#include <cstring>
#include <functional>
#include <fstream>
#include <iostream>
#include <vector>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/input.h>
#include <linux/uinput.h>

#include "define_multimodal.h"
#include "input_parse.h"

/*
 * Structure for docking libinput
 */
struct InputEvent {
    uint16_t code;
    int32_t target;
    int32_t type;
    int32_t value;
    int32_t x;
    int32_t y;
    int32_t fp;
    int32_t devType;
    int32_t track;
    int64_t blockTime;
    int32_t multiReprot;
};

/*
 * Click events on devices
 * such as mouse and keyboard
 */
enum PressEvent {
    EVENT_RELEASE = 0,
    EVENT_PRESS = 1,
    LONG_PRESS = 2,
    TOUCH_PAD_PRESS = 15
};

struct DeviceInformation {
    bool status;
    int32_t devIndex;
    int32_t devType;
    int16_t fd;
    char chipName[32];
};

struct InjectEvent {
    struct input_event event;
    int64_t blockTime;
};

struct InputEventArray {
    std::string deviceName;
    std::string target;
    std::vector<InjectEvent> events;
};

typedef std::function<int32_t (const InputEvent& inputEvent)> WriteDeviceFun;
#endif // MSG_HEAD_H