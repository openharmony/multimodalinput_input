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

#ifndef DEVICE_H
#define DEVICE_H

#include <bitset>
#include <string>
#include <vector>

#include <linux/input.h>

#include "nocopyable.h"

#include "i_device.h"
#include "i_epoll_event_source.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
inline constexpr size_t BIT_PER_UINT8 { 8 };

inline constexpr size_t NBYTES(size_t nbits)
{
    return (nbits + BIT_PER_UINT8 - 1) / BIT_PER_UINT8;
}

inline constexpr size_t BYTE(size_t bit)
{
    return (bit / BIT_PER_UINT8);
}

inline constexpr size_t OFFSET(size_t bit)
{
    return (bit % BIT_PER_UINT8);
}

inline bool TestBit(size_t bit, const uint8_t *array)
{
    return ((array)[BYTE(bit)] & (1 << OFFSET(bit)));
}

class Device final : public IDevice,
                     public IEpollEventSource {
public:

    explicit Device(int32_t deviceId);
    DISALLOW_COPY_AND_MOVE(Device);
    ~Device();

    int32_t Open() override;
    void Close() override;
    int32_t GetFd() const override;
    void Dispatch(const struct epoll_event &ev) override;

    void SetId(int32_t id) override;
    void SetDevPath(const std::string &devPath) override;
    void SetSysPath(const std::string &sysPath) override;
    void SetName(const std::string &name) override;
    void SetBus(int32_t bus) override;
    void SetVersion(int32_t version) override;
    void SetProduct(int32_t product) override;
    void SetVendor(int32_t vendor) override;
    void SetPhys(const std::string &phys) override;
    void SetUniq(const std::string &uniq) override;
    void SetKeyboardType(KeyboardType keyboardType) override;
    void AddCapability(Capability capability) override;

    int32_t GetId() const override;
    std::string GetDevPath() const override;
    std::string GetSysPath() const override;
    std::string GetName() const override;
    int32_t GetBus() const override;
    int32_t GetVersion() const override;
    int32_t GetProduct() const override;
    int32_t GetVendor() const override;
    std::string GetPhys() const override;
    std::string GetUniq() const override;
    IDevice::KeyboardType GetKeyboardType() const override;
    bool IsPointerDevice() const override;
    bool IsKeyboard() const override;
    bool IsRemote() const override;

    bool HasAbs(size_t abs) const;
    bool HasKey(size_t key) const;
    bool HasRel(size_t rel) const;
    bool HasProperty(size_t property) const;
    bool HasCapability(Capability capability) const;

private:
    void QueryDeviceInfo();
    void QuerySupportedEvents();
    void UpdateCapability();
    bool HasAbsCoord() const;
    bool HasMtCoord() const;
    bool HasRelCoord() const;
    bool HasAxesOrButton(size_t start, size_t end, const uint8_t* whichBitMask) const;
    bool HasJoystickAxesOrButtons() const;
    void CheckPointers();
    void CheckAbs();
    void CheckJoystick();
    void CheckMt();
    void CheckAdditional();
    void CheckPencilMouse();
    void CheckKeys();
    std::string MakeConfigFileName() const;
    int32_t ReadConfigFile(const std::string &filePath);
    int32_t ConfigItemSwitch(const std::string &configItem, const std::string &value);
    int32_t ReadTomlFile(const std::string &filePath);
    void JudgeKeyboardType();
    void LoadDeviceConfig();
    void PrintCapsDevice() const;
    void GetEventMask(const std::string &eventName, uint32_t type, std::size_t arrayLength,
        uint8_t *whichBitMask) const;
    void GetPropMask(const std::string &eventName, std::size_t arrayLength, uint8_t *whichBitMask) const;

    int32_t fd_ { -1 };
    int32_t deviceId_ { -1 };
    int32_t bus_ { 0 };
    int32_t version_ { 0 };
    int32_t product_ { 0 };
    int32_t vendor_ { 0 };
    std::string devPath_;
    std::string sysPath_;
    std::string dhid_;
    std::string name_;
    std::string phys_;
    std::string uniq_;
    std::string networkId_;
    std::bitset<DEVICE_CAP_MAX> caps_;
    uint8_t evBitmask_[NBYTES(EV_MAX)] {};
    uint8_t keyBitmask_[NBYTES(KEY_MAX)] {};
    uint8_t absBitmask_[NBYTES(ABS_MAX)] {};
    uint8_t relBitmask_[NBYTES(REL_MAX)] {};
    uint8_t propBitmask_[NBYTES(INPUT_PROP_MAX)] {};
    IDevice::KeyboardType keyboardType_ { IDevice::KEYBOARD_TYPE_NONE };
};

inline int32_t Device::GetFd() const
{
    return fd_;
}

inline void Device::SetId(int32_t id)
{
    deviceId_ = id;
}

inline void Device::SetDevPath(const std::string &devPath)
{
    devPath_ = devPath;
}

inline void Device::SetSysPath(const std::string &sysPath)
{
    sysPath_ = sysPath;
}

inline void Device::SetName(const std::string &name)
{
    name_ = name;
}

inline void Device::SetBus(int32_t bus)
{
    bus_ = bus;
}

inline void Device::SetVersion(int32_t version)
{
    version_ = version;
}

inline void Device::SetProduct(int32_t product)
{
    product_ = product;
}

inline void Device::SetVendor(int32_t vendor)
{
    vendor_ = vendor;
}

inline void Device::SetPhys(const std::string &phys)
{
    phys_ = phys;
}

inline void Device::SetUniq(const std::string &uniq)
{
    uniq_ = uniq;
}

inline void Device::SetKeyboardType(KeyboardType type)
{
    if (type >= KEYBOARD_TYPE_NONE && type < KEYBOARD_TYPE_MAX) {
        keyboardType_ = type;
    }
}

inline void Device::AddCapability(Capability capability)
{
    if (capability >= DEVICE_CAP_KEYBOARD && capability < DEVICE_CAP_MAX) {
        caps_.set(capability);
    }
}

inline int32_t Device::GetId() const
{
    return deviceId_;
}

inline std::string Device::GetDevPath() const
{
    return devPath_;
}

inline std::string Device::GetSysPath() const
{
    return sysPath_;
}

inline std::string Device::GetName() const
{
    return name_;
}

inline int32_t Device::GetBus() const
{
    return bus_;
}

inline int32_t Device::GetVersion() const
{
    return version_;
}

inline int32_t Device::GetProduct() const
{
    return product_;
}

inline int32_t Device::GetVendor() const
{
    return vendor_;
}

inline std::string Device::GetPhys() const
{
    return phys_;
}

inline std::string Device::GetUniq() const
{
    return uniq_;
}

inline IDevice::KeyboardType Device::GetKeyboardType() const
{
    return keyboardType_;
}

inline bool Device::IsPointerDevice() const
{
    return caps_.test(DEVICE_CAP_POINTER);
}

inline bool Device::IsKeyboard() const
{
    return caps_.test(DEVICE_CAP_KEYBOARD);
}

inline bool Device::IsRemote() const
{
    return GetName().find("DistributedInput ") != std::string::npos;
}

inline bool Device::HasAbs(size_t abs) const
{
    return TestBit(abs, absBitmask_);
}

inline bool Device::HasRel(size_t rel) const
{
    return TestBit(rel, relBitmask_);
}

inline bool Device::HasKey(size_t key) const
{
    return TestBit(key, keyBitmask_);
}

inline bool Device::HasProperty(size_t property) const
{
    return TestBit(property, propBitmask_);
}

inline bool Device::HasCapability(Capability capability) const
{
    return caps_.test(capability);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DEVICE_H