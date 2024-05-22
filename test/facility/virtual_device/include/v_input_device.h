/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef V_INPUT_DEVICE_H
#define V_INPUT_DEVICE_H

#include <bitset>
#include <string>
#include <vector>

#include <linux/input.h>

#include "nocopyable.h"

namespace OHOS {
namespace MMI {
inline constexpr size_t BITS_PER_UINT8 { 8 };

inline constexpr size_t OFFSET(size_t bit)
{
    return (bit % BITS_PER_UINT8);
}

inline constexpr size_t BYTE(size_t bit)
{
    return (bit / BITS_PER_UINT8);
}

inline bool TestBit(size_t bit, const uint8_t *array)
{
    return ((array)[BYTE(bit)] & (1 << OFFSET(bit)));
}

inline constexpr size_t NBYTES(size_t nbits)
{
    return (nbits + BITS_PER_UINT8 - 1) / BITS_PER_UINT8;
}

class VInputDevice final {
public:
    enum Capability {
        DEVICE_CAP_KEYBOARD = 0,
        DEVICE_CAP_TOUCH,
        DEVICE_CAP_POINTER,
        DEVICE_CAP_TABLET_TOOL,
        DEVICE_CAP_TABLET_PAD,
        DEVICE_CAP_GESTURE,
        DEVICE_CAP_SWITCH,
        DEVICE_CAP_JOYSTICK,
        DEVICE_CAP_MAX
    };

public:
    explicit VInputDevice(const std::string &node);
    ~VInputDevice();
    DISALLOW_COPY_AND_MOVE(VInputDevice);

    int32_t Open();
    void Close();
    bool IsActive() const;
    bool SupportEventType(size_t ev) const;
    bool SupportKey(size_t key) const;
    bool SupportAbs(size_t abs) const;
    bool SupportRel(size_t rel) const;
    bool SupportMsc(size_t msc) const;
    bool SupportLed(size_t led) const;
    bool SupportRep(size_t rep) const;
    bool SupportProperty(size_t prop) const;
    bool QueryAbsInfo(size_t abs, struct input_absinfo &absInfo);
    int32_t SendEvent(uint16_t type, uint16_t code, int32_t value);

    int32_t GetFd() const;
    std::string GetDevPath() const;
    std::string GetSysPath() const;
    std::string GetName() const;
    struct input_id GetInputId() const;
    std::string GetPhys() const;
    std::string GetUniq() const;
    bool IsMouse() const;
    bool IsKeyboard() const;
    bool IsTouchscreen() const;

    bool HasAbs(size_t abs) const;
    bool HasRel(size_t rel) const;
    bool HasKey(size_t key) const;
    bool HasProperty(size_t property) const;
    bool HasCapability(Capability capability) const;

private:
    void QueryDeviceInfo();
    void QuerySupportedEvents();
    void UpdateCapability();
    bool HasAxesOrButton(size_t start, size_t end, const uint8_t* whichBitMask) const;
    bool HasJoystickAxesOrButtons() const;
    bool HasAbsCoord() const;
    bool HasMtCoord() const;
    bool HasRelCoord() const;
    void CheckPointers();
    void CheckKeys();
    void CheckAbs();
    void CheckMt();
    void CheckAdditional();
    void GetEventMask(const std::string &eventName, uint32_t type, std::size_t arrayLength,
        uint8_t *whichBitMask) const;
    void GetPropMask(const std::string &eventName, std::size_t arrayLength, uint8_t *whichBitMask) const;
    void PrintCapsDevice() const;

private:
    int32_t fd_ { -1 };
    struct input_id inputId_ {};
    std::string devPath_;
    std::string sysPath_;
    std::string name_;
    std::string phys_;
    std::string uniq_;
    std::string dhid_;
    std::string networkId_;
    std::bitset<DEVICE_CAP_MAX> caps_;
    uint8_t evBitmask_[NBYTES(EV_MAX)] {};
    uint8_t keyBitmask_[NBYTES(KEY_MAX)] {};
    uint8_t absBitmask_[NBYTES(ABS_MAX)] {};
    uint8_t relBitmask_[NBYTES(REL_MAX)] {};
    uint8_t mscBitmask_[NBYTES(MSC_MAX)] {};
    uint8_t ledBitmask_[NBYTES(LED_MAX)] {};
    uint8_t repBitmask_[NBYTES(REP_MAX)] {};
    uint8_t propBitmask_[NBYTES(INPUT_PROP_MAX)] {};
};

inline bool VInputDevice::IsActive() const
{
    return (fd_ >= 0);
}

inline bool VInputDevice::SupportEventType(size_t ev) const
{
    return TestBit(ev, evBitmask_);
}

inline bool VInputDevice::SupportKey(size_t key) const
{
    return (TestBit(EV_KEY, evBitmask_) && TestBit(key, keyBitmask_));
}

inline bool VInputDevice::SupportAbs(size_t abs) const
{
    return (TestBit(EV_ABS, evBitmask_) && TestBit(abs, absBitmask_));
}

inline bool VInputDevice::SupportRel(size_t rel) const
{
    return (TestBit(EV_REL, evBitmask_) && TestBit(rel, relBitmask_));
}

inline bool VInputDevice::SupportMsc(size_t msc) const
{
    return (TestBit(EV_MSC, evBitmask_) && TestBit(msc, mscBitmask_));
}

inline bool VInputDevice::SupportLed(size_t led) const
{
    return (TestBit(EV_LED, evBitmask_) && TestBit(led, ledBitmask_));
}

inline bool VInputDevice::SupportRep(size_t rep) const
{
    return (TestBit(EV_REP, evBitmask_) && TestBit(rep, repBitmask_));
}

inline bool VInputDevice::SupportProperty(size_t prop) const
{
    return TestBit(prop, propBitmask_);
}

inline int32_t VInputDevice::GetFd() const
{
    return fd_;
}

inline std::string VInputDevice::GetDevPath() const
{
    return devPath_;
}

inline std::string VInputDevice::GetSysPath() const
{
    return sysPath_;
}

inline std::string VInputDevice::GetName() const
{
    return name_;
}

inline struct input_id VInputDevice::GetInputId() const
{
    return inputId_;
}

inline std::string VInputDevice::GetPhys() const
{
    return phys_;
}

inline std::string VInputDevice::GetUniq() const
{
    return uniq_;
}

inline bool VInputDevice::IsMouse() const
{
    return caps_.test(DEVICE_CAP_POINTER);
}

inline bool VInputDevice::IsKeyboard() const
{
    return caps_.test(DEVICE_CAP_KEYBOARD);
}

inline bool VInputDevice::IsTouchscreen() const
{
    return caps_.test(DEVICE_CAP_TOUCH);
}

inline bool VInputDevice::HasAbs(size_t abs) const
{
    return TestBit(abs, absBitmask_);
}

inline bool VInputDevice::HasRel(size_t rel) const
{
    return TestBit(rel, relBitmask_);
}

inline bool VInputDevice::HasKey(size_t key) const
{
    return TestBit(key, keyBitmask_);
}

inline bool VInputDevice::HasProperty(size_t property) const
{
    return TestBit(property, propBitmask_);
}

inline bool VInputDevice::HasCapability(Capability capability) const
{
    return caps_.test(capability);
}
} // namespace MMI
} // namespace OHOS
#endif // V_INPUT_DEVICE_H