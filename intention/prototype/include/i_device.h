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

#ifndef I_DEVICE_H
#define I_DEVICE_H

#include <string>

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

class IDevice {
public:
    enum KeyboardType {
        KEYBOARD_TYPE_NONE,
        KEYBOARD_TYPE_UNKNOWN,
        KEYBOARD_TYPE_ALPHABETICKEYBOARD,
        KEYBOARD_TYPE_DIGITALKEYBOARD,
        KEYBOARD_TYPE_HANDWRITINGPEN,
        KEYBOARD_TYPE_REMOTECONTROL,
        KEYBOARD_TYPE_MAX
    };

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
    IDevice() = default;
    virtual ~IDevice() = default;

    virtual int32_t Open() = 0;
    virtual void Close() = 0;

    virtual void SetId(int32_t id) = 0;
    virtual void SetDevPath(const std::string &devPath) = 0;
    virtual void SetSysPath(const std::string &sysPath) = 0;
    virtual void SetName(const std::string &name) = 0;
    virtual void SetBus(int32_t bus) = 0;
    virtual void SetVersion(int32_t version) = 0;
    virtual void SetProduct(int32_t product) = 0;
    virtual void SetVendor(int32_t vendor) = 0;
    virtual void SetPhys(const std::string &phys) = 0;
    virtual void SetUniq(const std::string &uniq) = 0;
    virtual void SetKeyboardType(KeyboardType keyboardType) = 0;
    virtual void AddCapability(Capability capability) = 0;

    virtual int32_t GetId() const = 0;
    virtual std::string GetDevPath() const = 0;
    virtual std::string GetSysPath() const = 0;
    virtual std::string GetName() const = 0;
    virtual int32_t GetBus() const = 0;
    virtual int32_t GetVersion() const = 0;
    virtual int32_t GetProduct() const = 0;
    virtual int32_t GetVendor() const = 0;
    virtual std::string GetPhys() const = 0;
    virtual std::string GetUniq() const = 0;
    virtual KeyboardType GetKeyboardType() const = 0;
    virtual bool IsPointerDevice() const = 0;
    virtual bool IsKeyboard() const = 0;
    virtual bool IsRemote() const = 0;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // I_DEVICE_H