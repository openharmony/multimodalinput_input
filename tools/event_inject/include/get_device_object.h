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

#ifndef GET_DEVICE_OBJECT_H
#define GET_DEVICE_OBJECT_H

#include "device_base.h"
#include "processing_finger_device.h"
#include "processing_game_pad_device.h"
#include "processing_joystick_device.h"
#include "processing_keyboard_device.h"
#include "processing_mouse_device.h"
#include "processing_pad_device.h"
#include "processing_pen_device.h"
#include "processing_touch_screen_device.h"

namespace OHOS {
namespace MMI {
class GetDeviceObject {
public:
    DISALLOW_COPY_AND_MOVE(GetDeviceObject);
    static DeviceBase* CreateDeviceObject(const std::string &deviceName);
};
} // namespace MMI
} // namespace OHOS
#endif // GET_DEVICE_OBJECT_H