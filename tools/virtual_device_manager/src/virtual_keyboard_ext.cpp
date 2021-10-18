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

#include "virtual_keyboard_ext.h"

OHOS::MMI::VirtualKeyboardExt::VirtualKeyboardExt() : VirtualDevice("Virtual keyboardExt",
    BUS_USB, 0x24ae, 0x4035)
{
}

static std::vector<uint32_t> virtualKey = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 55, 57, 58, 59, 60, 61, 62,
    63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 86, 87, 88, 96, 98, 99,
    102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 116, 117, 119, 127, 183, 184, 185, 186, 187, 188, 189, 190, 191
};

const std::vector<uint32_t>& OHOS::MMI::VirtualKeyboardExt::GetEventTypes() const
{
    static const std::vector<uint32_t> evt_types {
        EV_KEY, EV_MSC, EV_REP
    };
    return evt_types;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualKeyboardExt::GetKeys() const
{
    static const std::vector<uint32_t> keys(virtualKey.begin(),
                                            virtualKey.end());

    return keys;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualKeyboardExt::GetMscs() const
{
    static const std::vector<uint32_t> mscs {
        MSC_SCAN
    };
    return mscs;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualKeyboardExt::GetReps() const
{
    static const std::vector<uint32_t> reps {
        REP_DELAY, REP_PERIOD
    };
    return reps;
}
