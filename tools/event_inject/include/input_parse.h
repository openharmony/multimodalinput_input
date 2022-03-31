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

#ifndef INPUT_PARSE_H
#define INPUT_PARSE_H

#include <string>
#include <vector>

namespace OHOS {
namespace MMI {
constexpr int16_t INVALID_VALUE { -1 };
struct Pos {
    int32_t xPos = INVALID_VALUE;
    int32_t yPos = INVALID_VALUE;
    std::string ToString() const;
};
struct DeviceEvent {
    std::string eventType;
    std::vector<int32_t> event;
    int16_t keyValue = INVALID_VALUE;
    int64_t blockTime = INVALID_VALUE;
    std::vector<int32_t> ringEvents;
    std::string direction;
    int32_t distance = INVALID_VALUE;
    int32_t xPos = INVALID_VALUE;
    int32_t yPos = INVALID_VALUE;
    int32_t tiltX = INVALID_VALUE;
    int32_t tiltY = INVALID_VALUE;
    int32_t pressure = INVALID_VALUE;
    int32_t trackingId = INVALID_VALUE;
    int32_t reportType = INVALID_VALUE;
    int32_t keyStatus = INVALID_VALUE;
    std::vector<Pos> posXY;
    std::string ToString() const;
};
struct DeviceItem {
    std::string deviceName;
    int32_t deviceIndex = INVALID_VALUE;
    std::vector<DeviceEvent> events;
    std::string ToString() const;
};
typedef std::vector<DeviceItem> DeviceItems;
class InputParse {
public:
    InputParse() = default;
    ~InputParse() = default;
    DeviceItems DataInit(const std::string &fileData, bool logType);
private:
    std::vector<DeviceEvent> ParseData(const std::string &info) const;
    DeviceEvent ParseEvents(const std::string& info) const;
    DeviceEvent ParseEventsObj(const std::string &info) const;
};
} // namespace MMI
} // namespace OHOS
#endif // FILE_PARSE_H