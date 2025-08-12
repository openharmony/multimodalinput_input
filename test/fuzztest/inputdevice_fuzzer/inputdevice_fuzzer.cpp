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

#include "mmi_log.h"
#include "input_device.h"
#include "inputdevice_fuzzer.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputDeviceFuzzTest"

namespace OHOS {
namespace MMI {
namespace OHOS {
#define ODDEVENFLAG 2
template<class T>
size_t GetObject(T &object, const uint8_t *data, size_t size)
{
    size_t objectSize = sizeof(object);
    if (objectSize > size) {
        return 0;
    }
    errno_t ret = memcpy_s(&object, objectSize, data, objectSize);
    if (ret != EOK) {
        return 0;
    }
    return objectSize;
}

InputDevice::AxisInfo CreateAxisInfo(const uint8_t *data, size_t size, size_t &startPos, int32_t &rowsBefore)
{
    InputDevice::AxisInfo axisInfo;
    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    axisInfo.SetAxisType(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    axisInfo.SetMinimum(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    axisInfo.SetMaximum(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    axisInfo.SetFuzz(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    axisInfo.SetFlat(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    axisInfo.SetResolution(rowsBefore);

    axisInfo.GetAxisType();
    axisInfo.GetMinimum();
    axisInfo.GetMaximum();
    axisInfo.GetFuzz();
    axisInfo.GetFlat();
    axisInfo.GetResolution();
    return axisInfo;
}

bool InputDeviceFuzzTest(const uint8_t *data, size_t size)
{
    size_t startPos = 0;
    int32_t rowsBefore;
    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);

    InputDevice inputDevice;
    inputDevice.SetId(rowsBefore);
    std::string name = "testDevice";
    inputDevice.SetName(name);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputDevice.SetType(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputDevice.SetBus(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputDevice.SetVersion(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputDevice.SetProduct(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputDevice.SetVendor(rowsBefore);

    std::string phy = "testPhy";
    inputDevice.SetPhys(phy);

    std::string uniq = "testUniq";
    inputDevice.SetUniq(uniq);

    inputDevice.AddCapability(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputDevice.HasCapability(rowsBefore);

    InputDevice::AxisInfo axisInfo = CreateAxisInfo(data, size, startPos, rowsBefore);
    inputDevice.AddAxisInfo(axisInfo);
    std::vector<InputDevice::AxisInfo> axisInfos = inputDevice.GetAxisInfo();
    axisInfos.push_back(axisInfo);
    inputDevice.SetAxisInfo(axisInfos);

    inputDevice.GetId();
    inputDevice.GetName();
    inputDevice.GetType();
    inputDevice.GetBus();
    inputDevice.GetVersion();
    inputDevice.GetProduct();
    inputDevice.GetVendor();
    inputDevice.GetPhys();
    inputDevice.GetUniq();
    inputDevice.HasCapability(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::InputDeviceFuzzTest(data, size);
    return 0;
}
} // namespace MMI
} // namespace OHOS