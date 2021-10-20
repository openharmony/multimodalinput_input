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

#ifndef OHOS_VIRTUAL_TOUCHSCREEN_H
#define OHOS_VIRTUAL_TOUCHSCREEN_H

#include "virtual_device.h"

namespace OHOS {
namespace MMI {
    class VirtualTouchScreen : public VirtualDevice {
    public:
        VirtualTouchScreen();

    protected:
        virtual const std::vector<uint32_t>& GetEventTypes() const override;
        virtual const std::vector<uint32_t>& GetKeys() const override;
        virtual const std::vector<uint32_t>& GetProperties() const override;
        virtual const std::vector<uint32_t>& GetAbs() const override;
    };
}
}
#endif  // OHOS_VIRTUAL_TOUCHSCREEN_H