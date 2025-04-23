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

#ifndef EVENT_REPLAYER_H
#define EVENT_REPLAYER_H

#include <map>
#include <memory>
#include <string>
#include <unordered_map>

#include "input_device.h"

namespace OHOS {
namespace MMI {
class EventReplayer {
public:
    EventReplayer(const std::string& inputPath, const std::map<uint16_t, uint16_t>& deviceMapping = {});
    bool Replay();

    static bool ParseInputLine(const std::string& line, uint32_t& deviceId, struct input_event& evt);

private:
    bool SeekToDevicesSection(std::ifstream& inputFile);
    bool SeekToEventsSection(std::ifstream& inputFile);
    bool ProcessDeviceLines(std::ifstream& inputFile,
        std::map<uint32_t, std::unique_ptr<InputDevice>>& outputDevices, uint32_t deviceCount);
    bool InitializeOutputDevices(std::ifstream& inputFile,
        std::map<uint32_t, std::unique_ptr<InputDevice>>& outputDevices);
    bool ReplayEvents(std::ifstream& inputFile,
        const std::map<uint32_t, std::unique_ptr<InputDevice>>& outputDevices);
    void ApplyEventDelay(const struct input_event& currentEvent);

    std::string inputPath_;
    std::unordered_map<uint32_t, std::vector<input_event>> deviceEventBuffers_;
    std::map<uint16_t, std::string> deviceMapping_;
    unsigned long lastSec_{0};
    unsigned long lastUsec_{0};
    bool firstEvent_{true};
};
} // namespace MMI
} // namespace OHOS
#endif // EVENT_REPLAYER_H