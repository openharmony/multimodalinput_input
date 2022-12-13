/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef I_INPUT_DEVICE_COOPERATE_LISTENER_H
#define I_INPUT_DEVICE_COOPERATE_LISTENER_H

#include <string>

#include "cooperation_message.h"

namespace OHOS {
namespace MMI {
class IInputDeviceCooperateListener {
public:
    IInputDeviceCooperateListener() = default;
    virtual ~IInputDeviceCooperateListener() = default;
    virtual void OnCooperateMessage(const std::string &deviceId, CooperationMessage msg) = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // I_INPUT_DEVICE_COOPERATE_LISTENER_H