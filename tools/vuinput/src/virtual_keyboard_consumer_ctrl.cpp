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

#include "virtual_keyboard_consumer_ctrl.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t ABS_MAX_VOLUME = 572;

AbsInfo absInfos[] = {
    {ABS_VOLUME, 0, ABS_MAX_VOLUME, 0, 0}
};
} // namespace

VirtualKeyboardConsumerCtrl::VirtualKeyboardConsumerCtrl()
    : VirtualDevice("Virtual KeyboardConsumerCtrl", BUS_USB, 0x24ae, 0x4035)
{
    eventTypes_ = { EV_KEY, EV_REL, EV_ABS, EV_MSC };
    abs_ = { ABS_VOLUME };
    keys_ = {
        1, 28, 74, 78, 103, 105, 106, 108, 113, 114, 115, 116, 119, 128, 130, 131, 133, 134, 135, 136, 137, 138, 139,
        140, 142, 144, 150, 152, 155, 156, 158, 159, 161, 163, 164, 165, 166, 167, 168, 169, 171, 172, 173, 174, 177,
        178, 181, 206, 207, 208, 209, 210, 212, 216, 217, 219, 224, 225, 228, 229, 230, 234, 235, 240, 241, 244, 256,
        353, 354, 358, 362, 366, 370, 372, 374, 375, 376, 377, 378, 379, 380, 381, 383, 384, 386, 387, 389, 392, 393,
        396, 397, 398, 399, 400, 401, 402, 403, 405, 407, 408, 409, 410, 412, 416, 417, 418, 419, 420, 421, 422, 423,
        424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 439, 442, 576, 577, 578, 579, 580, 581, 582, 583, 592, 593
    };
    relBits_ = { REL_HWHEEL, REL_HWHEEL_HI_RES };
    miscellaneous_ = { MSC_SCAN };

    for (const auto &item : absInfos) {
        SetAbsValue(item);
    }
}
} // namespace MMI
} // namespace OHOS