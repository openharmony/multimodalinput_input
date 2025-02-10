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

#ifndef DFX_HISYSEVENT_DEVICE_H
#define DFX_HISYSEVENT_DEVICE_H

#include <string>

#include "hisysevent.h"

#include "input_device_manager.h"
#include "key_event.h"
#include "mmi_log.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class DfxHisyseventDeivce {
public:

    enum DeviceFaultType : int32_t {
        DEVICE_FAULT_TYPE_SYS = 0,
        DEVICE_FAULT_TYPE_INNER,
    };

    static void ReportDeviceFault(int32_t faultType, std::string faultMsg);
    static void ReportDeviceFault(int32_t deviceId, int32_t faultType, std::string faultMsg);
    static void ReportDeviceBehavior(int32_t deviceId, std::string msg);
};
} // namespace MMI
} // namespace OHOS
#endif // DFX_HISYSEVENT_DEVICE_H
