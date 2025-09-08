/*
 * Copyright (c) 2021-2022 Huawei Technologies Co., Ltd.
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

#ifndef I_INPUT_DEVICE_CONSUMER_H
#define I_INPUT_DEVICE_CONSUMER_H

#include <string>
#include "iremote_broker.h"

namespace OHOS {
namespace MMI {
class IInputDeviceConsumer : public IRemoteBroker {
public:
    enum CODE: uint32_t {
        CODE_SET_INPUT_DEVICE_CONSUMER_HANDLER = 0,
        CODE_CLEAR_INPUT_DEVICE_CONSUMER_HANDLER = 1
    };

    virtual int32_t SetInputDeviceConsumerHandler(const std::vector<std::string> &deviceNames) = 0;
    virtual int32_t ClearInputDeviceConsumerHandler(const std::vector<std::string> &deviceNames) = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.multimodalinput.IInputDeviceConsumer");
};
}
}
#endif // I_INPUT_DEVICE_CONSUMER_H