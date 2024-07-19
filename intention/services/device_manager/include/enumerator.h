/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef ENUMERATOR_H
#define ENUMERATOR_H

#include <set>

#include "nocopyable.h"

#include "i_device_mgr.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class Enumerator {
public:
    Enumerator() = default;
    ~Enumerator() = default;
    DISALLOW_COPY_AND_MOVE(Enumerator);

    void SetDeviceMgr(IDeviceMgr *devMgr);
    void ScanDevices();

private:
    void ScanAndAddDevices();
    void AddDevice(const std::string &devNode) const;

private:
    IDeviceMgr *devMgr_ { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // ENUMERATOR_H