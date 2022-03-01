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
#ifndef OHOS_INPUT_DEVICE_EVENT_H
#define OHOS_INPUT_DEVICE_EVENT_H
#include <functional>
#include <map>
#include <mutex>
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class InputDeviceImpl {
public:
    static InputDeviceImpl& GetInstance();
    DISALLOW_COPY_AND_MOVE(InputDeviceImpl);
    ~InputDeviceImpl() = default;

    struct InputDeviceInfo {
        InputDeviceInfo(int32_t id, std::string name, int32_t devcieType) : id(id),
            name(name), devcieType(devcieType) {}
        int32_t id;
        std::string name;
        int32_t devcieType;
    };

    void GetInputDeviceIdsAsync(int32_t userData, std::function<void(int32_t, std::vector<int32_t>)> callback);
    void GetInputDeviceAsync(int32_t userData, int32_t deviceId,
        std::function<void(int32_t, std::shared_ptr<InputDeviceInfo>)> callback);
    void OnInputDevice(int32_t userData, int32_t id, std::string name, int32_t deviceId);
    void OnInputDeviceIds(int32_t userData, std::vector<int32_t> ids);

private:
    InputDeviceImpl() = default;
    std::map<int32_t, std::function<void(int32_t, std::shared_ptr<InputDeviceInfo>)>> inputDevcices_;
    std::map<int32_t, std::function<void(int32_t, std::vector<int32_t>)>> inputDevciceIds_;
    std::mutex mtx_;
};
} // namespace MMI
} // namespace OHOS

#endif // OHOS_INPUT_DEVICE_EVENT_H