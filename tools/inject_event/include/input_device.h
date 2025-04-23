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

#ifndef INPUT_DEVICE_H
#define INPUT_DEVICE_H

#include <map>
#include <string>
#include <vector>

#include "common.h"

namespace OHOS {
namespace MMI {
class InputDevice {
public:
    InputDevice(const InputDevice&) = delete;
    InputDevice& operator=(const InputDevice&) = delete;
    InputDevice();
    InputDevice(const std::string& path, uint32_t id);
    InputDevice(InputDevice&& other) noexcept;
    ~InputDevice();

    InputDevice& operator=(InputDevice&& other) noexcept;

    bool IsOpen() const;
    void Close();
    bool OpenForReading();
    bool OpenForWriting();

    int32_t GetFd() const;
    const std::string& GetPath() const;
    const std::string& GetName() const;
    uint32_t GetId() const;

    void SetId(uint32_t id);
    void SetPath(const std::string& path);
    void SetName(const std::string& name);

    bool ReadEvent(input_event& event);
    bool WriteEvents(const std::vector<input_event>& events);
    bool InitFromTextLine(const std::string& line);

private:
    bool VerifyDeviceMatch() const;
    bool OpenDevice(int32_t flags);
    void QueryDeviceInfo();

    std::string path_;
    std::string name_;
    uint32_t id_;
    int32_t fd_;
    std::map<int32_t, int32_t> deviceMapping_;
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_DEVICE_H