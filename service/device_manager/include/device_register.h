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

#ifndef OHOS_DEVICE_REGISTER_H
#define OHOS_DEVICE_REGISTER_H
#include <set>
#include "uds_server.h"
#include "util.h"
#include "singleton.h"

namespace OHOS {
namespace MMI {
class DeviceRegister : public DelayedSingleton<DeviceRegister> {
public:
    DeviceRegister();
    virtual ~DeviceRegister();
    bool Init();
    bool DeleteDeviceInfo(const std::string& physical);
    bool FindDeviceId(const std::string& physical, uint32_t& deviceId);
    uint32_t AddDeviceInfo(const std::string& physical);
private:
    std::set<uint32_t> setDeviceId_ = {};
    std::map<std::string, uint32_t> mapDeviceInfo_ = {};
    std::mutex mu_;
};
};
}
#define DevRegister OHOS::MMI::DeviceRegister::GetInstance()
#endif
