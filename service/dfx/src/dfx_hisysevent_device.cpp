/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "dfx_hisysevent_device.h"

#include <fstream>

#include "i_input_windows_manager.h"
#include "parameters.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DfxHisysevent"

#define DFX_HISYSEVENT_DOMAIN OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MODAL_INPUT
#define DFX_HISYSEVENT_NAME_DEVICE_FAULT "DEVICE_MANAGER_FAULT"
#define DFX_HISYSEVENT_NAME_DEVICE_BEHAVIOR "DEVICE_MANAGER_BEHAVIOR"
#define DFX_HISYSEVENT_NAME_DEVICE_STATISTIC "DEVICE_MANAGER_STATISTIC"

#define DFX_HISYSEVENT_TYPE_FAULT OHOS::HiviewDFX::HiSysEvent::EventType::FAULT
#define DFX_HISYSEVENT_TYPE_BEHAVIOR OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR

namespace OHOS {
namespace MMI {

void DfxHisyseventDeivce::ReportDeviceFault(int32_t faultType, std::string faultMsg)
{
    int32_t ret = HiSysEventWrite(DFX_HISYSEVENT_DOMAIN,
        DFX_HISYSEVENT_NAME_DEVICE_FAULT,
        DFX_HISYSEVENT_TYPE_FAULT,
        "FAULT_TYPE",
        faultType,
        "FAULT_MSG",
        faultMsg);
    if (ret != 0) {
        MMI_HILOGE("HiviewDFX Write failed, ret:%{public}d, faultType:%{public}d, faultMsg:%{public}s",
            ret,
            faultType,
            faultMsg.c_str());
    }
}

void DfxHisyseventDeivce::ReportDeviceFault(int32_t deviceId, int32_t faultType, std::string faultMsg)
{
    std::shared_ptr<InputDevice> dev = INPUT_DEV_MGR->GetInputDevice(deviceId);
    CHKPV(dev);
    int32_t ret = HiSysEventWrite(DFX_HISYSEVENT_DOMAIN,
        DFX_HISYSEVENT_NAME_DEVICE_FAULT,
        DFX_HISYSEVENT_TYPE_FAULT,
        "FAULT_TYPE",
        faultType,
        "DEVICE_ID",
        deviceId,
        "DEVICE_PHYS",
        dev->GetPhys(),
        "DEVICE_NAME",
        dev->GetName(),
        "DEVICE_TYPE",
        dev->GetType(),
        "FAULT_MSG",
        faultMsg);
    if (ret != 0) {
        MMI_HILOGE(
            "HiviewDFX Write failed, ret:%{public}d, deivceId:%{public}d, faultType:%{public}d, faultMsg:%{public}s",
            ret,
            deviceId,
            faultType,
            faultMsg.c_str());
    }
}

void DfxHisyseventDeivce::ReportDeviceBehavior(int32_t deviceId, std::string msg)
{
    std::shared_ptr<InputDevice> dev = INPUT_DEV_MGR->GetInputDevice(deviceId);
    CHKPV(dev);
    std::string message;
    std::string name;
    int32_t ret = HiSysEventWrite(DFX_HISYSEVENT_DOMAIN,
        DFX_HISYSEVENT_NAME_DEVICE_BEHAVIOR,
        DFX_HISYSEVENT_TYPE_BEHAVIOR,
        "DEVICE_ID",
        deviceId,
        "DEVICE_PHYS",
        dev->GetPhys(),
        "DEVICE_NAME",
        dev->GetName(),
        "DEVICE_TYPE",
        dev->GetType(),
        "MSG",
        msg);
    if (ret != 0) {
        MMI_HILOGE(
            "HiviewDFX Write failed, ret:%{public}d, deivceId:%{public}d, msg:%{public}s", ret, deviceId, msg.c_str());
    }
}

} // namespace MMI
} // namespace OHOS
