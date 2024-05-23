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

#ifndef VIRTUAL_DEVICE_H
#define VIRTUAL_DEVICE_H

#include <map>
#include <string>
#include <vector>

#include <linux/uinput.h>

#include "nocopyable.h"

#include "virtual_device.h"

namespace OHOS {
namespace MMI {
class VirtualDevice {
protected:
    struct ResolutionInfo {
        int16_t axisCode { 0 };
        int32_t absResolution { 0 };
    };

    struct AbsInfo {
        int32_t code { 0 };
        int32_t minValue { 0 };
        int32_t maxValue { 0 };
        int32_t fuzz { 0 };
        int32_t flat { 0 };
    };

public:
    VirtualDevice(const std::string &name, uint16_t bustype, uint16_t vendor, uint16_t product);
    virtual ~VirtualDevice();
    DISALLOW_COPY_AND_MOVE(VirtualDevice);

    virtual bool SetUp();
    void Close();

    std::string GetDevNode() const;

protected:
    void SetResolution(const ResolutionInfo &resolutionInfo);
    void SetAbsValue(const AbsInfo &absInfo);
    virtual const std::vector<uint32_t> &GetAbs() const;
    virtual const std::vector<uint32_t> &GetEventTypes() const;
    virtual const std::vector<uint32_t> &GetKeys() const;
    virtual const std::vector<uint32_t> &GetLeds() const;
    virtual const std::vector<uint32_t> &GetMiscellaneous() const;
    virtual const std::vector<uint32_t> &GetProperties() const;
    virtual const std::vector<uint32_t> &GetRelBits() const;
    virtual const std::vector<uint32_t> &GetRepeats() const;
    virtual const std::vector<uint32_t> &GetSwitches() const;

    static bool FindDeviceNode(const std::string &name, std::string &node);
    static void Execute(std::vector<std::string> &results);
    static void GetInputDeviceNodes(std::map<std::string, std::string> &nodes);

protected:
    std::vector<uinput_abs_setup> absInit_;
    std::vector<uint32_t> abs_;
    std::vector<uint32_t> relBits_;
    std::vector<uint32_t> switches_;
    std::vector<uint32_t> repeats_;
    std::vector<uint32_t> eventTypes_;
    std::vector<uint32_t> keys_;
    std::vector<uint32_t> properties_;
    std::vector<uint32_t> leds_;
    std::vector<uint32_t> miscellaneous_;

private:
    void SetPhys();
    void SetSupportedEvents();
    void SetAbsResolution();
    void SetIdentity();

private:
    int32_t fd_ { -1 };
    struct uinput_user_dev uinputDev_ {};
    struct uinput_abs_setup uinputAbs_ {};
};
} // namespace MMI
} // namespace OHOS
#endif // VIRTUAL_DEVICE_H