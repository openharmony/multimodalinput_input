/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef DEVICE_MANAGER_H
#define DEVICE_MANAGER_H

#include <vector>

#include "input_device.h"

namespace OHOS {
namespace MMI {
class DeviceManager {
public:
    DeviceManager() = default;
    std::vector<InputDevice> DiscoverDevices();
    void PrintDeviceList();

    static int32_t ExtractEventNumber(const std::string& fileName);
private:
    std::string BuildDevicePath(const std::string& fileName) const;
};
} // namespace MMI
} // namespace OHOS
#endif // DEVICE_MANAGER_H