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

#ifndef TAIHE_INPUTDEVICE_UTILS_H
#define TAIHE_INPUTDEVICE_UTILS_H

#include <linux/input.h>
#include <stdexcept>

#include "ani_common.h"
#include "define_multimodal.h"
#include "input_device.h"
#include "input_manager.h"
#include "ohos.multimodalInput.inputDevice.proj.hpp"
#include "ohos.multimodalInput.inputDevice.impl.hpp"
#include "taihe/runtime.hpp"

namespace OHOS {
namespace MMI {
using TaihesType = ohos::multimodalInput::inputDevice::sourceType;
using TaiheaType = ohos::multimodalInput::inputDevice::axisType;
using TaiheSType = ohos::multimodalInput::inputDevice::SourceType;
using TaiheAType = ohos::multimodalInput::inputDevice::AxisType;
using TaiheAxisRange = ohos::multimodalInput::inputDevice::AxisRange;
using TaiheInputDeviceData = ohos::multimodalInput::inputDevice::InputDeviceData;

struct DeviceType {
    std::string sourceTypeName;
    uint32_t typeBit { 0 };
};

class TaiheInputDeviceUtils {
public:
    static TaihesType ConverterSourceTypeValue(const std::string &sourceType);
    static TaiheaType ConverterAxisTypeValue(const std::string &axisType);
    static TaiheSType ConverterSourceType(const TaihesType &sType);
    static TaiheAType ConverterAxisType(const TaiheaType &aType);
    static TaiheAxisRange ConverterAxisRange(const InputDevice::AxisInfo &axisInfo,
        const std::string &sourceType, const std::string &axisType);
    static TaiheInputDeviceData ConverterInputDevice(const std::shared_ptr<InputDevice> &device);
};

} // namespace MMI
} // namespace OHOS
    #endif // TAIHE_INPUTDEVICE_UTILS_H