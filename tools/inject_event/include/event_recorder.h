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

#ifndef EVENT_RECORDER_H
#define EVENT_RECORDER_H

#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "input_device.h"

namespace OHOS {
namespace MMI {
class EventRecorder {
public:
    EventRecorder(const std::string& outputPath);
    ~EventRecorder();

    bool Start(std::vector<InputDevice>& devices);
    void Stop();

private:
    void ProcessDeviceEvents(fd_set& readFds);
    void MainLoop();
    void FlushDeviceEvents(const EventRecord& record);
    static std::string GetEventTypeString(uint16_t type);
    static std::string GetSecondaryEventCodeString(uint16_t type, uint16_t code);
    static std::string GetEventCodeString(uint16_t type, uint16_t code);
    void WriteEventText(const EventRecord& record);

    std::string outputPath_;
    std::ofstream outputFile_;
    std::vector<InputDevice> devices_;
    std::unordered_map<uint32_t, std::vector<EventRecord>> deviceEventBuffers_;
    bool running_;
};
} // namespace MMI
} // namespace OHOS
#endif // EVENT_RECORDER_H