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

#include "virtual_remote_control.h"

namespace OHOS {
namespace MMI {
namespace {
    constexpr int32_t ABS_MAX_REMOTE = 65535;
    constexpr int32_t ABS_FUZZ_REMOTE = 255;
    constexpr int32_t ABS_FLAT_REMOTE = 4095;
}

VirtualRemoteControl::VirtualRemoteControl() : VirtualDevice("Virtual RemoteControl", BUS_USB, 0x7d02, 0x0002)
{
    dev_.absmin[ABS_X] = 0;
    dev_.absmax[ABS_X] = ABS_MAX_REMOTE;
    dev_.absmin[ABS_Y] = 0;
    dev_.absmax[ABS_Y] = ABS_MAX_REMOTE;
    dev_.absfuzz[ABS_X] = ABS_FUZZ_REMOTE;
    dev_.absfuzz[ABS_Y] = ABS_FUZZ_REMOTE;
    dev_.absflat[ABS_X] = ABS_FLAT_REMOTE;
    dev_.absflat[ABS_Y] = ABS_FLAT_REMOTE;
}

VirtualRemoteControl::~VirtualRemoteControl() {}

static std::vector<uint32_t> g_virtualKey = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
    31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
    59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 77, 78, 79, 80, 81, 82, 83, 85, 86, 87, 88,
    89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 113, 114, 115,
    116, 117, 118, 119, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139,
    140, 142, 144, 150, 152, 155, 156, 158, 159, 161, 163, 164, 165, 166, 171, 172, 173, 176, 177, 178, 179, 180, 183,
    184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 198, 199, 200, 201, 202, 203, 204, 205, 209, 217, 240, 418,
    419
};

const std::vector<uint32_t>& VirtualRemoteControl::GetEventTypes() const
{
    static const std::vector<uint32_t> evt_types {
        EV_KEY, EV_ABS, EV_MSC
    };
    return evt_types;
}

const std::vector<uint32_t>& VirtualRemoteControl::GetAbs() const
{
    static const std::vector<uint32_t> abs {
        ABS_X, ABS_Y
    };
    return abs;
}

const std::vector<uint32_t>& VirtualRemoteControl::GetKeys() const
{
    static const std::vector<uint32_t> keys(g_virtualKey.begin(),
                                            g_virtualKey.end());
    return keys;
}

const std::vector<uint32_t>& VirtualRemoteControl::GetMscs() const
{
    static const std::vector<uint32_t> mscs { MSC_SCAN };
    return mscs;
}
} // namespace MMI
} // namespace OHOS