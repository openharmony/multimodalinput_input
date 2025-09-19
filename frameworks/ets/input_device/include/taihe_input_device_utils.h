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

#include "ohos.multimodalInput.inputDevice.proj.hpp"
#include "ohos.multimodalInput.inputDevice.impl.hpp"
#include "taihe/runtime.hpp"
#include "taihe/callback.hpp"

#include "input_device.h"
#include <linux/input.h>

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
    static TaihesType ConverterSType(const std::string &sourceType);
    static TaiheaType ConverterATxis(const std::string &axisType);
    static TaiheSType ConverterSourceType(const TaihesType &sType);
    static TaiheAType ConverterAxisType(const TaiheaType &aType);
    static TaiheAxisRange ConverterAxisRange(const InputDevice::AxisInfo &axisInfo,
        const std::string &sourceType, const std::string &axisType);
    static TaiheInputDeviceData ConverterInputDevice(std::shared_ptr<InputDevice> &device);
    static ani_object WrapBusinessError(ani_env* env, const std::string& msg);
    static ani_ref CreateBusinessError(ani_env* env, ani_int code, const std::string& msg);
};

} // namespace MMI
} // namespace OHOS
    #endif // TAIHE_INPUTDEVICE_UTILS_H