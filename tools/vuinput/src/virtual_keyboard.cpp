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

#include "virtual_keyboard.h"

namespace OHOS {
namespace MMI {
VirtualKeyboard::VirtualKeyboard() : VirtualDevice("Virtual keyboard", BUS_USB, 0x24ae, 0x4035)
{
    eventTypes_ = { EV_KEY, EV_MSC, EV_LED, EV_REP };
    miscellaneous_ = { MSC_SCAN };
    leds_ = { LED_NUML, LED_CAPSL, LED_SCROLLL, LED_COMPOSE, LED_KANA };
    repeats_ = { REP_DELAY, REP_PERIOD };
    keys_ = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
        31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
        59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 85, 86, 87,
        88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 113, 114,
        115, 116, 117, 119, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138,
        140, 142, 150, 152, 158, 159, 161, 163, 164, 165, 166, 173, 176, 177, 178, 179, 180, 183, 184, 185, 186, 187,
        188, 189, 190, 191, 192, 193, 194, 240, 211, 213, 214, 215, 218, 220, 221, 222, 223, 226, 227, 231, 232, 233,
        236, 237, 238, 239, 242, 243, 245, 246, 247, 248, 464, 522, 523, 141, 145, 146, 147, 148, 149, 151, 153, 154,
        157, 160, 162, 170, 175, 182, 200, 201, 202, 203, 204, 205, 101, 112, 118, 120
    };
}
} // namespace MMI
} // namespace OHOS