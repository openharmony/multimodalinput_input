/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "virtual_fingerprint_key.h"

namespace OHOS {
namespace MMI {

#define EVENT_FINGERPRINT_DOWN 121
#define EVENT_FINGERPRINT_UP 122
#define EVENT_FINGERPRINT_CLICK 123
VirtualFingerprintKey::VirtualFingerprintKey() : VirtualDevice("FingerprintKey", BUS_USB, 0x12d1, 0x10a5)
{
    eventTypes_ = {EV_KEY, EV_MSC};
    miscellaneous_ = { MSC_SCAN };
    keys_ = {
        EVENT_FINGERPRINT_DOWN,
        EVENT_FINGERPRINT_UP,
        EVENT_FINGERPRINT_CLICK
    };
}
} // namespace MMI
} // namespace OHOS