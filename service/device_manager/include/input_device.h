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

#ifndef OHOS_INPUT_DEVICE_H
#define OHOS_INPUT_DEVICE_H

#include <string>
#include <vector>

namespace OHOS {
namespace MMI {
class InputDevice {
public:
    void SetId(int32_t deviceId);
    int32_t GetId();
    void SetName(std::string name);
    std::string GetName();
    void SetDeviceType(int32_t deviceType);
    int32_t GetDeviceType();
private:
    int32_t id = -1;
    std::string name = "NA";
    int32_t deviceType = 0;
    std::vector<int32_t> deviceIdList;
};
}
}
#endif