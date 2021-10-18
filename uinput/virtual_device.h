/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef VIRTUALDEVICE_H
#define VIRTUALDEVICE_H

#include <cstdint>
#include <functional>
#include <iostream>
#include <vector>

#include "linux/input.h"
#include "linux/uinput.h"

class VirtualDevice {
public:
    VirtualDevice(const char *deviceName, uint16_t productId);
    virtual ~VirtualDevice();
    bool EmitEvent(uint16_t type, uint16_t code, uint32_t value) const;
    bool SetUp();

protected:
    virtual const std::vector<uint32_t>& GetEventTypes() const;
    virtual const std::vector<uint32_t>& GetKeys() const;
    virtual const std::vector<uint32_t>& GetProperties() const;
    virtual const std::vector<uint32_t>& GetAbs() const;
    virtual const std::vector<uint32_t>& GetRelBits() const;
    int32_t fd_ = -1;
    const char * const deviceName_;
    const uint16_t busType_;
    const uint16_t vendorId_;
    const uint16_t productId_;
    const uint16_t version_;
    struct uinput_user_dev dev_ {};
    static constexpr uint32_t MAX_NAME_LENGTH = 80;
};
#endif  // VIRTUALDEVICE_H
