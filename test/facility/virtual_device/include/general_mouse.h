/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef GENERAL_MOUSE_H
#define GENERAL_MOUSE_H

#include "general_device.h"
#include "virtual_mouse.h"
#include "v_input_device.h"

namespace OHOS {
namespace MMI {
class GeneralMouse final : public GeneralDevice {
public:
    GeneralMouse() = default;
    ~GeneralMouse() = default;
    DISALLOW_COPY_AND_MOVE(GeneralMouse);

    bool SetUp() override;
    void Close() override;

private:
    VirtualMouse vMouse_;
};
} // namespace MMI
} // namespace OHOS
#endif // GENERAL_MOUSE_H