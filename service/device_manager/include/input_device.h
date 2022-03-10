/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef INPUT_DEVICE_H
#define INPUT_DEVICE_H
#include <string>
#include <vector>
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class InputDevice {
public:
    InputDevice() = default;
    DISALLOW_COPY_AND_MOVE(InputDevice);

    void SetId(int32_t deviceId);
    int32_t GetId() const;
    void SetName(std::string name);
    std::string GetName() const;
    void SetType(int32_t deviceType);
    int32_t GetType() const;
private:
    int32_t id_;
    std::string name_;
    int32_t deviceType_;
    std::vector<int32_t> deviceIdList_;
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_DEVICE_H