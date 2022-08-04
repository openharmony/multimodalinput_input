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

#include "input_device.h"

namespace OHOS {
namespace MMI {
InputDevice::InputDevice(int32_t id, std::string name, int32_t deviceType, int32_t bus, int32_t version,
    int32_t product, int32_t vendor, std::string phys, std::string uniq, std::vector<AxisInfo> axis)
    : id_(id), name_(name), type_(deviceType), bus_(bus), version_(version), product_(product),
      vendor_(vendor), phys_(phys), uniq_(uniq), axis_(axis) {}

void InputDevice::SetId(int32_t deviceId)
{
    id_ = deviceId;
}

int32_t InputDevice::GetId() const
{
    return id_;
}

void InputDevice::SetName(std::string name)
{
    name_ = name;
}

std::string InputDevice::GetName() const
{
    return name_;
}

void InputDevice::SetType(int32_t deviceType)
{
    type_ = deviceType;
}

int32_t InputDevice::GetType() const
{
    return type_;
}

void InputDevice::SetBus(int32_t bus)
{
    bus_ = bus;
}

int32_t InputDevice::GetBus() const
{
    return bus_;
}

void InputDevice::SetVersion(int32_t version)
{
    version_ = version;
}

int32_t InputDevice::GetVersion() const
{
    return version_;
}

void InputDevice::SetProduct(int32_t product)
{
    product_ = product;
}

int32_t InputDevice::GetProduct() const
{
    return product_;
}

void InputDevice::SetVendor(int32_t vendor)
{
    vendor_ = vendor;
}

int32_t InputDevice::GetVendor() const
{
    return vendor_;
}

void InputDevice::SetPhys(std::string phys)
{
    phys_ = phys;
}

std::string InputDevice::GetPhys() const
{
    return phys_;
}

void InputDevice::SetUniq(std::string uniq)
{
    uniq_ = uniq;
}

std::string InputDevice::GetUniq() const
{
    return uniq_;
}

void InputDevice::AddAxisInfo(AxisInfo axis)
{
    axis_.push_back(axis);
}

std::vector<InputDevice::AxisInfo> InputDevice::GetAxisInfo()
{
    return axis_;
}

InputDevice::AxisInfo::AxisInfo(int32_t type, int32_t min, int32_t max, int32_t fuzz, int32_t flat, int32_t resolution)
    : axisType_(type), minimum_(min), maximum_(max), fuzz_(fuzz), flat_(flat), resolution_(resolution) {}

void InputDevice::AxisInfo::SetAxisType(int32_t type)
{
    axisType_ = type;
}

int32_t InputDevice::AxisInfo::GetAxisType() const
{
    return axisType_;
}

void InputDevice::AxisInfo::SetMinimum(int32_t min)
{
    minimum_ = min;
}

int32_t InputDevice::AxisInfo::GetMinimum() const
{
    return minimum_;
}

void InputDevice::AxisInfo::SetMaximum(int32_t max)
{
    maximum_ = max;
}

int32_t InputDevice::AxisInfo::GetMaximum() const
{
    return maximum_;
}

void InputDevice::AxisInfo::SetFuzz(int32_t fuzz)
{
    fuzz_ = fuzz;
}

int32_t InputDevice::AxisInfo::GetFuzz() const
{
    return fuzz_;
}

void InputDevice::AxisInfo::SetFlat(int32_t flat)
{
    flat_ = flat;
}

int32_t InputDevice::AxisInfo::GetFlat() const
{
    return flat_;
}

void InputDevice::AxisInfo::SetResolution(int32_t resolution)
{
    resolution_ = resolution;
}

int32_t InputDevice::AxisInfo::GetResolution() const
{
    return resolution_;
}
} // namespace MMI
} // namespace OHOS