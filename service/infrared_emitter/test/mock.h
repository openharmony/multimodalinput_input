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
#ifndef MESSAGE_PARCEL_MOCK_H
#define MESSAGE_PARCEL_MOCK_H

#include <gmock/gmock.h>

#include "idevmgr_hdi.h"
#include "infrared_emitter_controller.h"

namespace OHOS {
namespace MMI {
class DfsMessageParcel {
public:
    virtual ~DfsMessageParcel() = default;
public:
    virtual sptr<OHOS::HDI::Consumerir::V1_0::ConsumerIr> Get(const std::string& serviceName, bool isStub) = 0;
    virtual sptr<OHOS::HDI::DeviceManager::V1_0::IDeviceManager> Get() = 0;
public:
    static inline std::shared_ptr<DfsMessageParcel> messageParcel = nullptr;
};

class MessageParcelMock : public DfsMessageParcel {
public:
    MOCK_METHOD2(Get, sptr<OHOS::HDI::Consumerir::V1_0::ConsumerIr>(const std::string& serviceName, bool isStub));
    MOCK_METHOD0(Get, sptr<OHOS::HDI::DeviceManager::V1_0::IDeviceManager>());
};
} // namespace MMI
} // namespace OHOS
#endif