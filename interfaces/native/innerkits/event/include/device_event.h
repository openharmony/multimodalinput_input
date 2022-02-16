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
#ifndef DEVICE_EVENT_H
#define DEVICE_EVENT_H
#include "multimodal_event.h"

namespace OHOS {
class DeviceEvent : public MMI::MultimodalEvent {
public:
    virtual ~DeviceEvent();
    void Initialize(const std::string& name, const std::string& sysName, int32_t inputDeviceId);
    virtual std::string GetName() const;
    virtual std::string GetSysName() const;
    virtual int32_t GetInputDeviceId() const;
private:
    std::string name_;
    std::string sysName_;
    int32_t inputDeviceId_ = 0;
};
} // namespace OHOS
#endif // DEVICE_EVENT_H