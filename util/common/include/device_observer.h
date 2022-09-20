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

#ifndef DEVICE_OBSERVER_H
#define DEVICE_OBSERVER_H

namespace OHOS {
namespace MMI {
class IDeviceObserver {
public:
    virtual void UpdatePointerDevice(bool hasPointerDevice, bool isVisible) = 0;
};

class IDeviceObject {
public:
    virtual void Attach(std::shared_ptr<IDeviceObserver> observer) = 0;
    virtual void Detach(std::shared_ptr<IDeviceObserver> observer) = 0;
    virtual void NotifyPointerDevice(bool hasPointerDevice, bool isVisible) = 0;
};
} // namespace MMI
} // namespace OHOS
#endif