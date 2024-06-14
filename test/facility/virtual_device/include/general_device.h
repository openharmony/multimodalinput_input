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

#ifndef GENERAL_DEVICE_H
#define GENERAL_DEVICE_H

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "nocopyable.h"

#include "v_input_device.h"

namespace OHOS {
namespace MMI {
class GeneralDevice {
public:
    GeneralDevice() = default;
    virtual ~GeneralDevice() = default;
    DISALLOW_COPY_AND_MOVE(GeneralDevice);

    virtual bool SetUp() = 0;
    virtual void Close();
    void SendEvent(uint16_t type, uint16_t code, int32_t value);

    std::string GetDevPath() const;

protected:
    bool OpenDevice(const std::string &name);
    bool FindDeviceNode(const std::string &name, std::string &node);
    void Execute(std::vector<std::string> &results);
    void GetInputDeviceNodes(std::map<std::string, std::string> &nodes);

    std::unique_ptr<VInputDevice> vDev_;
};
} // namespace MMI
} // namespace OHOS
#endif // GENERAL_DEVICE_H