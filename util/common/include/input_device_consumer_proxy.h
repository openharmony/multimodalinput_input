/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef INPUT_DEVICE_CONSUMER_PROXY_H
#define INPUT_DEVICE_CONSUMER_PROXY_H

#include "i_input_device_consumer.h"
#include "iremote_proxy.h"
#include "parcel.h"

namespace OHOS {
namespace MMI {
class IInputDeviceConsumerProxy : public IRemoteProxy<IInputDeviceConsumer> {
public:
    explicit IInputDeviceConsumerProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IInputDeviceConsumer>(impl)
    {}
    ~IInputDeviceConsumerProxy() override = default;

    int32_t SendInputDeviceConsumerHandler(const std::vector<std::string> &deviceNames, CODE code);
    int32_t SetInputDeviceConsumerHandler(const std::vector<std::string> &deviceNames) override;
    int32_t ClearInputDeviceConsumerHandler(const std::vector<std::string> &deviceNames) override;
private:
    static inline BrokerDelegator<IInputDeviceConsumerProxy> delegator_;
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_DEVICE_CONSUMER_PROXY_H