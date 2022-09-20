/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "nocopyable.h"
#include "virtual_device_config.h"

namespace OHOS {
namespace MMI {
class VirtualDevice {
public:
    static std::vector<std::string> BrowseDirectory(const std::string& filePath);
    static std::string ReadFile(const std::string& filePath);
    static int32_t GetFileSize(const std::string& filePath);
    static std::string ReadUinputToolFile(const std::string& filePath);
    static bool ClearFileResidues(const std::string& fileName);
    static bool CreateHandle(const std::string& deviceArgv);
    static bool AddDevice(const std::string& startDeviceName);
    static bool CloseDevice(const std::string& closeDeviceName, const std::vector<std::string>& deviceList);
    static bool CommandBranch(std::vector<std::string>& argvList);
    VirtualDevice(const std::string& deviceName, uint16_t busType, uint16_t vendorId, uint16_t productId);
    DISALLOW_COPY_AND_MOVE(VirtualDevice);
    virtual ~VirtualDevice();
    bool SetUp();
    void Close();
    bool CreateKey();
    bool SetAbsResolution();
    bool SetPhys(const std::string& deviceName);
    bool DoIoctl(int32_t fd, int32_t request, const uint32_t value);
    void SetDeviceId();

protected:
    void SetResolution(const ResolutionInfo& resolutionInfo);
    void SetAbsValue(const AbsInfo& absInfo);
    virtual const std::vector<uint32_t>& GetAbs() const;
    virtual const std::vector<uint32_t>& GetEventTypes() const;
    virtual const std::vector<uint32_t>& GetKeys() const;
    virtual const std::vector<uint32_t>& GetLeds() const;
    virtual const std::vector<uint32_t>& GetMiscellaneous() const;
    virtual const std::vector<uint32_t>& GetProperties() const;
    virtual const std::vector<uint32_t>& GetRelBits() const;
    virtual const std::vector<uint32_t>& GetRepeats() const;
    virtual const std::vector<uint32_t>& GetSwitches() const;

protected:
    int32_t fd_ { -1 };
    std::string deviceName_;
    const uint16_t busTtype_ { 0 };
    const uint16_t vendorId_ { 0 };
    const uint16_t productId_ { 0 };
    const uint16_t version_ { 0 };
    struct uinput_user_dev uinputDev_ {};
    struct uinput_abs_setup uinputAbs_ {};
    std::vector<uinput_abs_setup> absInit_;
    std::vector<uint32_t> eventTypes_;
    std::vector<uint32_t> keys_;
    std::vector<uint32_t> properties_;
    std::vector<uint32_t> abs_;
    std::vector<uint32_t> relBits_;
    std::vector<uint32_t> leds_;
    std::vector<uint32_t> miscellaneous_;
    std::vector<uint32_t> switches_;
    std::vector<uint32_t> repeats_;
};
} // namespace MMI
} // namespace OHOS
#endif  // VIRTUAL_DEVICE_H
