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

#include "virtual_mouse.h"

namespace OHOS {
namespace MMI {
VirtualMouse::VirtualMouse() : VirtualDevice("Virtual Mouse", BUS_USB, 0x93a, 0x2510)
{
    eventTypes_ = { EV_KEY, EV_REL, EV_MSC };
    keys_ = { BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, BTN_SIDE, BTN_EXTRA, BTN_FORWARD, BTN_BACK, BTN_TASK };
    relBits_ = { REL_X, REL_Y, REL_WHEEL, REL_WHEEL_HI_RES };
    miscellaneous_ = { MSC_SCAN };
}
} // namespace MMI
} // namespace OHOS