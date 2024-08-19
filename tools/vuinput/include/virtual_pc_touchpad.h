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

#ifndef VIRTUAL_PC_TOUCHPAD_H
#define VIRTUAL_PC_TOUCHPAD_H

#include "virtual_device.h"

namespace OHOS {
namespace MMI {
class VirtualPcTouchpad : public VirtualDevice {
public:
    VirtualPcTouchpad();
    DISALLOW_COPY_AND_MOVE(VirtualPcTouchpad);
    ~VirtualPcTouchpad() = default;
};
} // namespace MMI
} // namespace OHOS
#endif // VIRTUAL_PC_TOUCHPAD_H