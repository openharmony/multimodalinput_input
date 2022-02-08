/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "device_event.h"

OHOS::DeviceEvent::~DeviceEvent()
{
}
void OHOS::DeviceEvent::Initialize(const std::string& name, const std::string& sysName, int32_t inputDeviceId)
{
    name_ = name;
    sysName_ = sysName;
    inputDeviceId_ = inputDeviceId;
}

std::string OHOS::DeviceEvent::GetName() const
{
    return name_;
}

std::string OHOS::DeviceEvent::GetSysName() const
{
    return sysName_;
}

int32_t OHOS::DeviceEvent::GetInputDeviceId() const
{
    return inputDeviceId_;
}
