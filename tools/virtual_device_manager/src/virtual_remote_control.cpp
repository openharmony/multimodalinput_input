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

#include "virtual_remote_control.h"

OHOS::MMI::VirtualRemoteControl::VirtualRemoteControl() : VirtualDevice("Virtual RemoteControl",
    BUS_USB, 0x44f, 0x6008)
{
}

static std::vector<uint32_t> virtualKey = {
    116, 408, 142, 142, 228, 139, 353, 103, 108, 105, 106, 1, 78, 74, 358, 370, 379, 212, 398, 399, 401, 400, 375,
    225, 224, 431, 592, 593, 244, 230, 229, 228, 241, 405, 28, 376, 377, 150, 389, 169, 362, 416, 417, 396, 383, 379,
    386, 174, 138, 384, 378, 381, 366, 402, 403, 380, 207, 119, 167, 208, 168, 163, 165, 166, 161, 439, 410, 499, 164,
    582, 32, 113, 209, 115, 114, 409, 576, 156, 171, 421, 422, 423, 424, 425, 426, 155, 427, 428, 429, 397, 577, 578,
    219, 140, 387, 144, 150, 216, 216, 433, 579, 580, 407, 412, 138, 432, 374, 581, 442, 392, 393, 430, 358, 583, 181,
    134, 206, 174, 234, 210, 130, 131, 133, 137, 135, 136, 217, 354, 172, 158, 159, 128, 173, 156, 418, 419, 420,
    372, 177, 178, 12, 176, 223, 110, 111, 182, 232, 233, 231, 584, 608, 609, 610, 611, 612, 613, 120, 235, 528,
    625, 626, 744
};

const std::vector<uint32_t>& OHOS::MMI::VirtualRemoteControl::GetEventTypes() const
{
    static const std::vector<uint32_t> evt_types {
        EV_KEY
    };
    return evt_types;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualRemoteControl::GetKeys() const
{
    static const std::vector<uint32_t> keys(virtualKey.begin(),
                                            virtualKey.end());
    return keys;
}
