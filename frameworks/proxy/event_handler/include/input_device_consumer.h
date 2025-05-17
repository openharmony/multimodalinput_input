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

#ifndef INPUT_DEVICE_CONSUMER_H
#define INPUT_DEVICE_CONSUMER_H

#include <map>
#include <mutex>
#include "nocopyable.h"
#include <singleton.h>

#include "input_device.h"
#include "i_input_event_consumer.h"

namespace OHOS {
namespace MMI {
class InputDeviceConsumer {
public:
    DECLARE_SINGLETON(InputDeviceConsumer);

public:
    DISALLOW_MOVE(InputDeviceConsumer);
    int32_t SetInputDeviceConsumer(const std::vector<std::string>& deviceNames,
        std::shared_ptr<IInputEventConsumer> consumer);

    std::shared_ptr<IInputEventConsumer> deviceConsumer_ { nullptr };
};
#define DEVICE_CONSUMER ::OHOS::Singleton<InputDeviceConsumer>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // INPUT_DEVICE_CONSUMER_H
