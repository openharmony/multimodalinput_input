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

#ifndef INPUT_DEVICE_H
#define INPUT_DEVICE_H

#include <bitset>
#include <string>
#include <vector>

#include "nocopyable.h"

namespace OHOS {
namespace MMI {
enum InputDeviceCapability {
    INPUT_DEV_CAP_KEYBOARD,
    INPUT_DEV_CAP_POINTER,
    INPUT_DEV_CAP_TOUCH,
    INPUT_DEV_CAP_TABLET_TOOL,
    INPUT_DEV_CAP_TABLET_PAD,
    INPUT_DEV_CAP_GESTURE,
    INPUT_DEV_CAP_SWITCH,
    INPUT_DEV_CAP_JOYSTICK,
    INPUT_DEV_CAP_MAX
};

inline constexpr uint32_t CapabilityToTags(InputDeviceCapability capability)
{
    return static_cast<uint32_t>((1 << capability) - (capability / INPUT_DEV_CAP_MAX));
}

enum KeyboardType {
    KEYBOARD_TYPE_NONE,
    KEYBOARD_TYPE_UNKNOWN,
    KEYBOARD_TYPE_ALPHABETICKEYBOARD,
    KEYBOARD_TYPE_DIGITALKEYBOARD,
    KEYBOARD_TYPE_HANDWRITINGPEN,
    KEYBOARD_TYPE_REMOTECONTROL,
    KEYBOARD_TYPE_MAX
};

class InputDevice {
public:
    InputDevice() = default;
    DISALLOW_COPY_AND_MOVE(InputDevice);
    ~InputDevice() = default;

    void SetId(int32_t deviceId);
    int32_t GetId() const;
    void SetName(std::string name);
    std::string GetName() const;
    void SetType(int32_t deviceType);
    int32_t GetType() const;
    void SetBus(int32_t bus);
    int32_t GetBus() const;
    void SetVersion(int32_t version);
    int32_t GetVersion() const;
    void SetProduct(int32_t product);
    int32_t GetProduct() const;
    void SetVendor(int32_t vendor);
    int32_t GetVendor() const;
    void SetPhys(std::string phys);
    std::string GetPhys() const;
    void SetUniq(std::string uniq);
    std::string GetUniq() const;
    void AddCapability(InputDeviceCapability cap);
    bool HasCapability(InputDeviceCapability cap) const;
    bool HasCapability(uint32_t deviceTags) const;

    unsigned long GetCapabilities() const;
    void SetCapabilities(unsigned long caps);

    class AxisInfo {
    public:
        AxisInfo() = default;
        AxisInfo(int32_t type, int32_t min, int32_t max, int32_t fuzz, int32_t flat, int32_t resolution);
        ~AxisInfo() = default;
        void SetAxisType(int32_t type);
        int32_t GetAxisType() const;
        void SetMinimum(int32_t min);
        int32_t GetMinimum() const;
        void SetMaximum(int32_t max);
        int32_t GetMaximum() const;
        void SetFuzz(int32_t fuzz);
        int32_t GetFuzz() const;
        void SetFlat(int32_t flat);
        int32_t GetFlat() const;
        void SetResolution(int32_t resolution);
        int32_t GetResolution() const;

    private:
        int32_t axisType_ { 0 };
        int32_t minimum_ { 0 };
        int32_t maximum_ { 0 };
        int32_t fuzz_ { 0 };
        int32_t flat_ { 0 };
        int32_t resolution_ { 0 };
    };

    void AddAxisInfo(AxisInfo axis);
    std::vector<AxisInfo> GetAxisInfo();
    void SetAxisInfo(std::vector<AxisInfo> axis);
    InputDevice(int32_t id, std::string name, int32_t deviceType, int32_t bus, int32_t version, int32_t product,
                int32_t vendor, std::string phys, std::string uniq, const std::vector<AxisInfo>& axis);

private:
    int32_t id_ { -1 };
    std::string name_ { "null" };
    int32_t type_ { 0 };
    int32_t bus_ { -1 };
    int32_t version_ { -1 };
    int32_t product_ { -1 };
    int32_t vendor_ { -1 };
    std::string phys_ { "null" };
    std::string uniq_ { "null" };
    std::vector<AxisInfo> axis_;
    std::bitset<INPUT_DEV_CAP_MAX> capabilities_;
};

inline unsigned long InputDevice::GetCapabilities() const
{
    return capabilities_.to_ulong();
}

inline void InputDevice::SetCapabilities(unsigned long caps)
{
    capabilities_ = std::bitset<INPUT_DEV_CAP_MAX>(caps % (1 << INPUT_DEV_CAP_MAX));
}
} // namespace MMI
} // namespace OHOS
#endif // INPUT_DEVICE_H