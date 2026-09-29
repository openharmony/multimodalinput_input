/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MMI_LIBINPUT_ADAPTER_MOCK_H
#define MMI_LIBINPUT_ADAPTER_MOCK_H

#include <gmock/gmock.h>
#include "libinput.h"

namespace OHOS {
namespace MMI {
class ILibinputAdapter {
public:
    ILibinputAdapter();
    virtual ~ILibinputAdapter() = default;

    virtual int32_t UpdateLed(struct libinput_device *device, int32_t funcKey, bool isEnable) = 0;
};

class LibinputAdapter : public ILibinputAdapter {
public:
    LibinputAdapter() = default;
    ~LibinputAdapter() override = default;

    MOCK_METHOD(int32_t, UpdateLed, (struct libinput_device *, int32_t, bool));

    static int32_t DeviceLedUpdate(struct libinput_device *device, int32_t funcKey, bool isEnable);
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_LIBINPUT_ADAPTER_MOCK_H
