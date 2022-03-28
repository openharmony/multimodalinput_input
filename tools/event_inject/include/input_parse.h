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

#ifndef FILE_PARSE_H
#define FILE_PARSE_H

#include <ostream>
#include <vector>

namespace OHOS {
namespace MMI {
    struct Pos {
        int32_t xPos = -1;
        int32_t yPos = -1;
        std::string ToString() const;
    };
    struct DeviceEvent {
        std::string eventType;
        std::vector<int32_t> event;
        int16_t keyValue = -1;
        int64_t blockTime = -1;
        std::vector<int32_t> ringEvents;
        std::string direction;
        int32_t distance = -1;
        int32_t xPos = -1;
        int32_t yPos = -1;
        int32_t tiltX = -1;
        int32_t tiltY = -1;
        int32_t pressure = -1;
        int32_t trackingId = -1;
        int32_t reportType = -1;
        int32_t keyStatus = -1;
        std::vector<Pos> posXY;
        std::string ToString() const;
    };
    struct DeviceItem {
        std::string deviceName;
        int32_t deviceIndex = -1;
        std::vector<DeviceEvent> events;
        std::string ToString() const;
    };
    typedef std::vector<DeviceItem> DeviceItems;
    class InputParse {
    public:
        InputParse() = default;
        ~InputParse() = default;
        DeviceItems DataInit(std::string &fileData, bool logType);
    private:
        std::vector<DeviceEvent> ParseData(std::string &events);
        DeviceEvent ParseEvents(std::string& eventInfo);
    };
} // namespace MMI
} // namespace OHOS
#endif // FILE_PARSE_H