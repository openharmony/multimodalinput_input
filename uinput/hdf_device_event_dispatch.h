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

#ifndef HDF_DEVICE_EVENT_DISPATCH_H
#define HDF_DEVICE_EVENT_DISPATCH_H

#include "inject_thread.h"
#include "v1_0/iinput_interfaces.h"

namespace OHOS {
namespace MMI {
using namespace OHOS::HDI::Input::V1_0;
class HdfDeviceEventDispatch : public IInputCallback {
public:
    HdfDeviceEventDispatch(const uint32_t maxX, const uint32_t maxY);
    DISALLOW_COPY_AND_MOVE(HdfDeviceEventDispatch);
    virtual ~HdfDeviceEventDispatch() = default;

    int32_t EventPkgCallback(const std::vector<EventPackage> &pkgs, uint32_t devIndex) override;
    int32_t HotPlugCallback(const HotPlugEvent &event) override;

private:
    static InjectThread injectThread_;
};
} // namespace MMI
} // namespace OHOS
#endif // HDF_DEVICE_EVENT_DISPATCH_H