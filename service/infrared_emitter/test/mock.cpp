/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "mock.h"

namespace OHOS {
using namespace OHOS::MMI;

sptr<OHOS::HDI::Consumerir::V1_0::ConsumerIr> OHOS::HDI::Consumerir::V1_0::ConsumerIr::Get(
    const std::string& serviceName, bool isStub)
{
    if (OHOS::MMI::DfsMessageParcel::messageParcel == nullptr) {
        return 0;
    }
    return OHOS::MMI::DfsMessageParcel::messageParcel->Get(serviceName, isStub);
}

sptr<OHOS::HDI::DeviceManager::V1_0::IDeviceManager> OHOS::HDI::DeviceManager::V1_0::IDeviceManager::Get()
{
    if (OHOS::MMI::DfsMessageParcel::messageParcel == nullptr) {
        return 0;
    }
    return OHOS::MMI::DfsMessageParcel::messageParcel->Get();
}
} // namespace OHOS