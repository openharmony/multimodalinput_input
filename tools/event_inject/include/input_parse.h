/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
struct Pos {
    int32_t xPos { 0 };
    int32_t yPos { 0 };
    std::string ToString() const;
};
struct DeviceEvent {
    std::string eventType;
    std::vector<int32_t> event;
    int16_t keyValue { 0 };
    int64_t blockTime { 0 };
    std::vector<int32_t> ringEvents;
    std::string direction;
    int32_t distance { 0 };
    int32_t xPos { 0 };
    int32_t yPos { 0 };
    int32_t tiltX { 0 };
    int32_t tiltY { 0 };
    int32_t pressure { 0 };
    int32_t trackingId { 0 };
    int32_t reportType { 0 };
    int32_t keyStatus { 0 };
    std::vector<Pos> posXY;
    std::string ToString() const;
};
struct DeviceItem {
    std::string deviceName;
    int32_t deviceIndex { 0 };
    std::vector<DeviceEvent> events;
    std::string ToString() const;
};
typedef std::vector<DeviceItem> DeviceItems;
DeviceItems DataInit(const std::string &fileData, bool logStatus);
} // namespace MMI
} // namespace OHOS
#endif // INPUT_PARSE_H