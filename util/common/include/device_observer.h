/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef DEVICE_OBSERVER_H
#define DEVICE_OBSERVER_H

#include <cstdint>
#include <memory>

namespace OHOS {
namespace MMI {
class IDeviceObserver {
public:
    IDeviceObserver() = default;
    virtual ~IDeviceObserver() = default;

    virtual void OnDeviceAdded(int32_t deviceId) {}
    virtual void OnDeviceRemoved(int32_t deviceId) {}
    virtual void UpdatePointerDevice(bool hasPointerDevice, bool isVisible, bool isHotPlug) = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // DEVICE_OBSERVER_H
