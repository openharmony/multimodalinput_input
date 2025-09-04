/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "define_multimodal.h"
#include "taihe_input_device_utils.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TaiheInputDeviceUtils"

namespace OHOS {
namespace MMI {
constexpr uint32_t EVDEV_TAG_KEYBOARD = (1 << 1);
constexpr uint32_t EVDEV_TAG_MOUSE = (1 << 2);
constexpr uint32_t EVDEV_TAG_TOUCHPAD = (1 << 3);
constexpr uint32_t EVDEV_TAG_TOUCHSCREEN = (1 << 4);
constexpr uint32_t EVDEV_TAG_JOYSTICK = (1 << 6);
constexpr uint32_t EVDEV_TAG_TRACKBALL = (1 << 10);

DeviceType g_taiheDeviceType[] = {
    { "keyboard", EVDEV_TAG_KEYBOARD },
    { "mouse", EVDEV_TAG_MOUSE },
    { "touchpad", EVDEV_TAG_TOUCHPAD },
    { "touchscreen", EVDEV_TAG_TOUCHSCREEN },
    { "joystick", EVDEV_TAG_JOYSTICK },
    { "trackball", EVDEV_TAG_TRACKBALL },
};

std::unordered_map<int32_t, std::string>  g_taiheAxisType = {
    { ABS_MT_TOUCH_MAJOR, "touchmajor" },
    { ABS_MT_TOUCH_MINOR, "touchminor" },
    { ABS_MT_ORIENTATION, "orientation" },
    { ABS_MT_POSITION_X, "x" },
    { ABS_MT_POSITION_Y, "y" },
    { ABS_MT_PRESSURE, "pressure" },
    { ABS_MT_WIDTH_MAJOR, "toolmajor" },
    { ABS_MT_WIDTH_MINOR, "toolminor" },
};

TaihesType TaiheInputDeviceUtils::ConverterSType(const std::string &sourceType)
{
    return ohos::multimodalInput::inputDevice::sourceType::from_value(sourceType);
}

TaiheaType TaiheInputDeviceUtils::ConverterATxis(const std::string &axisType)
{
    return ohos::multimodalInput::inputDevice::axisType::from_value(axisType);
}

TaiheSType TaiheInputDeviceUtils::ConverterSourceType(const TaihesType &sType)
{
    TaiheSType result = TaiheSType::make_type(sType);
    return result;
}
TaiheAType TaiheInputDeviceUtils::ConverterAxisType(const TaiheaType &aType)
{
    TaiheAType result = TaiheAType::make_type(aType);
    return result;
}

TaiheAxisRange TaiheInputDeviceUtils::ConverterAxisRange(const InputDevice::AxisInfo &axisInfo,
    const std::string &sourceType, const std::string &axisType)
{
    TaiheAxisRange result {
        .source = ConverterSourceType(ConverterSType(sourceType)),
        .axis = ConverterAxisType(ConverterATxis(axisType)),
    };
    result.max = axisInfo.GetMaximum();
    result.min = axisInfo.GetMinimum();
    result.fuzz = axisInfo.GetFuzz();
    result.flat = axisInfo.GetFlat();
    result.resolution = axisInfo.GetResolution();
    return result;
}

TaiheInputDeviceData TaiheInputDeviceUtils::ConverterInputDevice(std::shared_ptr<InputDevice> &device)
{
    TaiheInputDeviceData result {};
    if (device == nullptr) {
        return result;
    }
    result.id = device->GetId();
    result.name = device->GetName();
    std::vector<TaiheSType> vecSourceTypes;
    std::string sourceType = "";
    uint32_t types = static_cast<uint32_t>(device->GetType());
    for (const auto item : g_taiheDeviceType) {
        if (types &item.typeBit) {
            sourceType = item.sourceTypeName;
            vecSourceTypes.push_back(ConverterSourceType(ConverterSType(sourceType)));
        }
    }
    result.sources = taihe::array<TaiheSType>(vecSourceTypes);
    std::string axisType = "";
    std::vector<TaiheAxisRange> vecAxisRanges;
    auto axisArray = device->GetAxisInfo();
    for (auto item : axisArray) {
        auto iter = g_taiheAxisType.find(item.GetAxisType());
        if (iter != g_taiheAxisType.end()) {
            axisType = iter->second;
        } else {
            MMI_HILOGD("Find axisType failed");
            continue;
        }
        TaiheAxisRange axisRange = ConverterAxisRange(item, sourceType, axisType);
        vecAxisRanges.push_back(axisRange);
    }
    result.axisRanges = taihe::array<TaiheAxisRange>(vecAxisRanges);
    result.bus = device->GetBus();
    result.product = device->GetProduct();
    result.vendor = device->GetVendor();
    result.version = device->GetVersion();
    result.phys = std::string_view(device->GetPhys());
    result.uniq = std::string_view(device->GetUniq());
    return result;
}
} // namespace MMI
} // namespace OHOS