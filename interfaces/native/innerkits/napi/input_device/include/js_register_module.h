/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#ifndef OHOS_JS_INPUT_DEVICE_REGISTER_MODULE_H
#define OHOS_JS_INPUT_DEVICE_REGISTER_MODULE_H

#include <stdio.h>
#include <map>
#include <list>
#include <string.h>
#include <iostream>
#include "libmmi_util.h"
#include "native_api.h"
#include "native_node_api.h"
#include "utils/log.h"

namespace OHOS {
namespace MMI {
    constexpr uint32_t EVDEV_UDEV_TAG_KEYBOARD = (1 << 1);
    constexpr uint32_t EVDEV_UDEV_TAG_MOUSE = (1 << 2);
    constexpr uint32_t EVDEV_UDEV_TAG_TOUCHPAD = (1 << 3);
    constexpr uint32_t EVDEV_UDEV_TAG_TOUCHSCREEN = (1 << 4);
    constexpr uint32_t EVDEV_UDEV_TAG_TABLET = (1 << 5);
    constexpr uint32_t EVDEV_UDEV_TAG_JOYSTICK = (1 << 6);
    constexpr uint32_t EVDEV_UDEV_TAG_ACCELEROMETER = (1 << 7);
    constexpr uint32_t EVDEV_UDEV_TAG_TABLET_PAD = (1 << 8);
    constexpr uint32_t EVDEV_UDEV_TAG_POINTINGSTICK = (1 << 9);
    constexpr uint32_t EVDEV_UDEV_TAG_TRACKBALL = (1 << 10);
    constexpr uint32_t EVDEV_UDEV_TAG_SWITCH = (1 << 11);

    struct DeviceType {
        std::string deviceTypeName;
        uint32_t typeBit;
    };
} // namespace MMI
} // namespace OHOS

#endif
