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
#ifndef OHOS_MANAGE_INJECT_DEVICE_H
#define OHOS_MANAGE_INJECT_DEVICE_H

#include "get_device_node.h"
#include "get_device_object.h"
#include "send_message.h"

namespace OHOS {
namespace MMI {
class ManageInjectDevice {
public:
    ManageInjectDevice() = default;
    ~ManageInjectDevice() = default;
    int32_t TransformJsonData(const Json& configData);
private:
    int32_t SendEvent(const InputEventArray& inputEventArray);
    int32_t SendEventToHdi(const InputEventArray& inputEventArray);
    int32_t SendEventToDeviveNode(const InputEventArray& inputEventArray);
private:
    GetDeviceNode getDeviceNodeObject_;
    DeviceBase* devicePtr_ = nullptr;
private:
    static constexpr int32_t INJECT_SLEEP_TIMES = 10;
};
}
}
#endif