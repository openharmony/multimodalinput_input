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
#ifndef OHOS_INPUT_DEVICE_EVENT_H
#define OHOS_INPUT_DEVICE_EVENT_H
#include <functional>
#include <map>
#include <mutex>
#include <vector>

namespace OHOS {
namespace MMI {
class InputDeviceEvent {
public:
    static InputDeviceEvent& GetInstance();
    InputDeviceEvent(const InputDeviceEvent &) = delete;
    InputDeviceEvent &operator=(const InputDeviceEvent &) = delete;
    InputDeviceEvent(InputDeviceEvent &&) = delete;
    ~InputDeviceEvent();

    struct InputDeviceInfo {
        int32_t id;
        std::string name;
        int32_t devcieType;
    };

    void GetInputDeviceIdsAsync(std::function<void(std::vector<int32_t>)> callback);
    void GetInputDeviceAsync(int32_t deviceId, std::function<void(std::shared_ptr<InputDeviceInfo>)> callback);
    void OnInputDevice(int32_t taskId, int32_t id, std::string name, int32_t deviceId);
    void OnInputDeviceIds(int32_t taskId, std::vector<int32_t> ids);

private:
    InputDeviceEvent();
    std::map<int32_t, std::function<void(std::shared_ptr<InputDeviceInfo>)>> inputDevciceRequests_;
    std::map<int32_t, std::function<void(std::vector<int32_t>)>> idsRequests_;
    int32_t inputDeviceTaskId_ {1};
    int32_t idsTaskId_ {1};
    std::mutex lk_;
};
} // namespace MMI
} // namespace OHOS
#endif