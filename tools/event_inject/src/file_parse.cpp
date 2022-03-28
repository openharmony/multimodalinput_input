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

#include "file_parse.h"

#include <variant>
#include <sstream>
#include "cJSON.h"

using namespace OHOS::MMI;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "GetDeviceNode" };
} // namespace

std::string Pos::ToString() const
{
    std::ostringstream oss;
    oss << "pos(" << xPos << "," << yPos << ")";
    return oss.str();
}

std::string DeviceEvent::ToString() const
{
    std::ostringstream oss;
    oss << "{eventType:" << eventType
        << ",event:[";
    for (auto &i : event) {
        oss << i << ",";
    }
    oss << "],keyValue:" << keyValue
        << ",blockTime:" << blockTime
        << ",ringEvents:[";
    for (auto &i : ringEvents) {
        oss << i << ",";
    }
    oss << "],direction:" << direction
        << ",distance:" << distance
        << ",xPos:" << xPos
        << ",yPos:" << yPos
        << ",tiltX:" << tiltX
        << ",tiltY:" << tiltY
        << ",pressure:" << pressure
        << ",trackingId:" << trackingId
        << ",reportType:" << reportType
        << ",keyStatus:" << keyStatus
        << ",posXY:";
    for (auto &i : posXY) {
        oss << i.ToString() << ",";
    }
    oss << "}" << std::endl;
    return oss.str();
}

std::string DeviceItem::ToString() const
{
    std::ostringstream oss;
    oss << "{deviceName:" << deviceName
        << ",deviceIndex:" << deviceIndex
        << ",events:[";
    for (auto &i : events) {
        oss << i.ToString() << ",";
    }
    oss << "]" << std::endl;
    return oss.str();
}

bool GetJsonData(cJSON *json, std::string key, std::string& val)
{
    if (cJSON_HasObjectItem(json, key.c_str())) {
        cJSON* rawVal = cJSON_GetObjectItem(json, key.c_str());
        if (rawVal == nullptr) {
            MMI_HILOGE("rawVal is null");
            return false;
        }
        val = rawVal->valuestring;
        return true;
    }
    return false;
}

bool GetJsonData(cJSON *json, std::string key, int32_t& val)
{
    if (cJSON_HasObjectItem(json, key.c_str())) {
        cJSON* rawVal = cJSON_GetObjectItem(json, key.c_str());
        if (rawVal == nullptr) {
            MMI_HILOGE("rawVal is null");
            return false;
        }
        val = rawVal->valueint;
        return true;
    }
    return false;
}

bool GetJsonData(cJSON *json, std::string key, int64_t& val)
{
    if (cJSON_HasObjectItem(json, key.c_str())) {
        cJSON* rawVal = cJSON_GetObjectItem(json, key.c_str());
        if (rawVal == nullptr) {
            MMI_HILOGE("rawVal is null");
            return false;
        }
        val = rawVal->valueint;
        return true;
    }
    return false;
}

bool GetJsonData(cJSON *json, std::string key, std::vector<int32_t>& vals)
{
    if (cJSON_HasObjectItem(json, key.c_str())) {
        cJSON* rawVal = cJSON_GetObjectItem(json, key.c_str());
        if (rawVal == nullptr) {
            MMI_HILOGE("rawVal is null");
            return false;
        }
        if (cJSON_IsArray(rawVal)) {
            int32_t rawValSize = cJSON_GetArraySize(rawVal);
            for (int32_t i = 0; i < rawValSize; i++) {
                cJSON* val = cJSON_GetArrayItem(rawVal, i);
                if (val == nullptr) {
                    return false;
                }
                vals.push_back(val->valueint);
            }
            return true;
        }
    }
    return false;
}

DeviceEvent InputParse::ParseEvents(std::string& Info)
{
    cJSON* eventInfo = cJSON_Parse(Info.c_str());
    DeviceEvent event;
    if (eventInfo == nullptr) {
        return event;
    }
    int32_t eventSize = cJSON_GetArraySize(eventInfo);
    for (int32_t i = 0; i < eventSize; i++) {
        cJSON* eventArray = cJSON_GetArrayItem(eventInfo, i);
        if (eventArray == nullptr) {
            MMI_HILOGE("event is null");
            return event;
        }
        if (cJSON_IsArray(eventArray)) {
            Pos pos;
            cJSON* xPos = cJSON_GetArrayItem(eventArray, 0);
            if (xPos == nullptr) {
                MMI_HILOGE("yPos is null");
                return event;
            }
            pos.xPos = xPos->valueint;
            cJSON* yPos = cJSON_GetArrayItem(eventArray, 1);
            pos.yPos = yPos->valueint;
            if (yPos == nullptr) {
                MMI_HILOGE("yPos is null");
                return event;
            }
            event.posXY.push_back(pos);
        }
    }
    return event;
}

std::vector<DeviceEvent> InputParse::ParseData(std::string& info)
{
    cJSON* events = cJSON_Parse(info.c_str());
    std::vector<DeviceEvent> eventData;
    if (events == nullptr) {
        return eventData;
    }
    int32_t eventsSize = cJSON_GetArraySize(events);
    for (int32_t j = 0; j < eventsSize; j++) {
        DeviceEvent event;
        cJSON* eventInfo = cJSON_GetArrayItem(events, j);
        if (eventInfo == nullptr) {
            MMI_HILOGE("eventInfo is null");
            return eventData;
        }
        if (cJSON_IsArray(eventInfo)) {
            std::string eventInfoStr = cJSON_Print(eventInfo);
            event = ParseEvents(eventInfoStr);
        } else {
            GetJsonData(eventInfo, "eventType", event.eventType);
            GetJsonData(eventInfo, "event", event.event);
            GetJsonData(eventInfo, "keyValue", event.keyValue);
            GetJsonData(eventInfo, "blockTime", event.blockTime);
            GetJsonData(eventInfo, "ringEvents", event.ringEvents);
            GetJsonData(eventInfo, "direction", event.direction);
            GetJsonData(eventInfo, "distance", event.distance);
            GetJsonData(eventInfo, "xPos", event.xPos);
            GetJsonData(eventInfo, "yPos", event.yPos);
            GetJsonData(eventInfo, "tiltX", event.tiltX);
            GetJsonData(eventInfo, "tiltY", event.tiltY);
            GetJsonData(eventInfo, "pressure", event.pressure);
            GetJsonData(eventInfo, "trackingId", event.trackingId);
            GetJsonData(eventInfo, "reportType", event.reportType);
            GetJsonData(eventInfo, "keyStatus", event.keyStatus);
        }
        eventData.push_back(event);
    }
    return eventData;
}

DeviceItems InputParse::DataInit(std::string& fileData, bool logType)
{
    DeviceItems deviceItems;
    cJSON* arrays = cJSON_Parse(fileData.c_str());
    if (arrays == nullptr) {
        MMI_HILOGE("arrays is null");
        return deviceItems;
    }
    int32_t arraysSize = cJSON_GetArraySize(arrays);
    for (int32_t i = 0; i < arraysSize; i++) {
        cJSON* deviceInfo = cJSON_GetArrayItem(arrays, i);
        cJSON* deviceName = cJSON_GetObjectItem(deviceInfo, "deviceName");
        if (deviceInfo == nullptr) {
            MMI_HILOGE("deviceInfo is null");
            return deviceItems;
        }
        DeviceItem deviceItem;
        deviceItem.deviceName = deviceName->valuestring;
        deviceItem.deviceIndex = 0;
        int32_t deviceIndex = 0;
        if (GetJsonData(deviceInfo, "deviceIndex", deviceIndex)) {
            deviceItem.deviceIndex = deviceIndex;
        }
        cJSON *events = nullptr;
        if (cJSON_HasObjectItem(deviceInfo, "events")) {
            events = cJSON_GetObjectItem(deviceInfo, "events");
        } else if (cJSON_HasObjectItem(deviceInfo, "singleEvent")) {
            events = cJSON_GetObjectItem(deviceInfo, "singleEvent");
        }
        if (events == nullptr) {
            MMI_HILOGE("events is null");
            return deviceItems;
        }
        std::string eventsStr = cJSON_Print(events);
        deviceItem.events = ParseData(eventsStr);
        deviceItems.push_back(deviceItem);
        if (logType) {
            MMI_HILOGE("deviceItem[%{public}d]: %{public}s", i, deviceItem.ToString().c_str());
        }
    }
    cJSON_Delete(arrays);
    return deviceItems;
}
