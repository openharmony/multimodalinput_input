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

#ifndef HDF_DEVICE_EVENT_MANAGER_H
#define HDF_DEVICE_EVENT_MANAGER_H

#include <cstdint>
#include <thread>

#include "inject_thread.h"
#include "input_manager.h"
#include "input_type.h"

namespace OHOS {
namespace MMI {
class HdfDeviceEventManager {
public:
    HdfDeviceEventManager();
    virtual ~HdfDeviceEventManager();
    void ConnectHDFInit();
    InjectThread injectThread_;
    std::thread thread_;

private:
    InputDeviceInfo *iDevInfo_ { nullptr };
    IInputInterface *inputInterface_ { nullptr };
    InputEventCb callback_ {};
    const uint32_t TOUCH_DEV_ID { 1 };
};
} // namespace MMI
} // namespace OHOS
#endif  // HDF_DEVICE_EVENT_MANAGER_H
