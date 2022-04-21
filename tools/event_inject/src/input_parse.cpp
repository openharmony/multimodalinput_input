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

#include "input_parse.h"

#include "cJSON.h"

#include <sstream>
#include "define_multimodal.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "GetDeviceNode" };
struct DeleteJson {
    DeleteJson() = default;

    ~DeleteJson()
    {
        if (json_ != nullptr) {
            cJSON_Delete(json_);
        }
    }

    operator cJSON *()
    {
        return json_;
    }

    cJSON *json_ = nullptr;
};

void GetJsonData(cJSON *json, const std::string& key, std::string& val)
{
    if (!cJSON_IsObject(json)) {
        return;
    }
    if (cJSON_HasObjectItem(json, key.c_str())) {
        cJSON* rawVal = cJSON_GetObjectItem(json, key.c_str());
        if (cJSON_IsString(rawVal)) {
            val = rawVal->valuestring;
        }
    }
    return;
}

template <class T>
void GetJsonData(cJSON *json, const std::string& key, T& val)
{
    if (!cJSON_IsObject(json)) {
        return;
    }
    if (cJSON_HasObjectItem(json, key.c_str())) {
        cJSON* rawVal = cJSON_GetObjectItem(json, key.c_str());
        if (cJSON_IsNumber(rawVal)) {
            val = rawVal->valueint;
        }
    }
    return;
}

void GetJsonData(cJSON *json, const std::string& key, std::vector<int32_t>& vals)
{
    if (!cJSON_IsObject(json)) {
        return;
    }
    if (!cJSON_HasObjectItem(json, key.c_str())) {
        MMI_HILOGW("GetJsonData json is not data:%{public}s", key.c_str());
        return;
    }
    cJSON* rawVal = cJSON_GetObjectItem(json, key.c_str());
    if (!cJSON_IsArray(rawVal)) {
        MMI_HILOGW("rawVal is not Array");
        return;
    }
    int32_t rawValSize = cJSON_GetArraySize(rawVal);
    for (int32_t i = 0; i < rawValSize; ++i) {
        cJSON* val = cJSON_GetArrayItem(rawVal, i);
        if (cJSON_IsNumber(val)) {
            vals.push_back(val->valueint);
        }
    }

    return;
}

bool ParseEvents(cJSON* eventInfo, DeviceEvent& event)
{
    if (!cJSON_IsArray(eventInfo)) {
        MMI_HILOGW("ParseEvents eventInfo is not Array");
        return false;
    }
    int32_t eventSize = cJSON_GetArraySize(eventInfo);
    for (int32_t i = 0; i < eventSize; ++i) {
        cJSON* eventArray = cJSON_GetArrayItem(eventInfo, i);
        if (cJSON_IsArray(eventArray)) {
            Pos pos;
            cJSON* xPos = cJSON_GetArrayItem(eventArray, 0);
            if (!cJSON_IsNumber(xPos)) {
                MMI_HILOGW("yPos is null");
                return false;
            }
            pos.xPos = xPos->valueint;
            cJSON* yPos = cJSON_GetArrayItem(eventArray, 1);
            if (!cJSON_IsNumber(yPos)) {
                MMI_HILOGW("yPos is null");
                return false;
            }
            pos.yPos = yPos->valueint;
            event.posXY.push_back(pos);
        }
    }
    return true;
}

void ParseEventsObj(cJSON* eventInfo, DeviceEvent& event)
{
    if (!cJSON_IsObject(eventInfo)) {
        MMI_HILOGW("ParseEventsObj eventInfo is not object");
        return;
    }
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
    return;
}

bool ParseData(cJSON* events, std::vector<DeviceEvent>& eventData)
{
    if (!cJSON_IsArray(events)) {
        MMI_HILOGE("ParseData events is not array");
        return false;
    }
    int32_t eventsSize = cJSON_GetArraySize(events);
    for (int32_t i = 0; i < eventsSize; ++i) {
        cJSON* eventInfo = cJSON_GetArrayItem(events, i);
        DeviceEvent event;
        if (cJSON_IsArray(eventInfo)) {
            if (!ParseEvents(eventInfo, event)) {
                MMI_HILOGE("ParseEvents is error");
                return false;
            }
        } else if (cJSON_IsObject(eventInfo)) {
            ParseEventsObj(eventInfo, event);
        } else {
            MMI_HILOGW("eventInfo is null");
            return false;
        }
        eventData.push_back(event);
    }
    return true;
}
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
    for (const auto &item : event) {
        oss << item << ",";
    }
    oss << "],keyValue:" << keyValue
        << ",blockTime:" << blockTime
        << ",ringEvents:[";
    for (const auto &item : ringEvents) {
        oss << item << ",";
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
    for (const auto &item : posXY) {
        oss << item.ToString() << ",";
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
    for (const auto &item : events) {
        oss << item.ToString() << ",";
    }
    oss << "]" << std::endl;
    return oss.str();
}

DeviceItems DataInit(const std::string& fileData, bool logStatus)
{
    CALL_LOG_ENTER;
    DeleteJson arrays;
    arrays.json_ = cJSON_Parse(fileData.c_str());
    if (!cJSON_IsArray(arrays.json_)) {
        MMI_HILOGE("DataInit json_ is not array");
        return {};
    }
    int32_t arraysSize = cJSON_GetArraySize(arrays.json_);
    DeviceItems deviceItems;
    for (int32_t i = 0; i < arraysSize; ++i) {
        cJSON* deviceInfo = cJSON_GetArrayItem(arrays.json_, i);
        if (!cJSON_IsObject(deviceInfo)) {
            MMI_HILOGW("deviceInfo is not Object");
            return {};
        }
        cJSON* deviceName = cJSON_GetObjectItem(deviceInfo, "deviceName");
        if (!cJSON_IsString(deviceName)) {
            MMI_HILOGW("deviceName is not string");
            return {};
        }
        DeviceItem deviceItem;
        deviceItem.deviceName = deviceName->valuestring;
        GetJsonData(deviceInfo, "deviceIndex", deviceItem.deviceIndex);
        cJSON *events = nullptr;
        if (cJSON_HasObjectItem(deviceInfo, "events")) {
            events = cJSON_GetObjectItem(deviceInfo, "events");
        } else if (cJSON_HasObjectItem(deviceInfo, "singleEvent")) {
            events = cJSON_GetObjectItem(deviceInfo, "singleEvent");
        }
        if (!cJSON_IsArray(events)) {
            MMI_HILOGE("DataInit events is not array");
            return {};
        }
        if (!ParseData(events, deviceItem.events)) {
            MMI_HILOGW("ParseData is error");
            return {};
        }
        deviceItems.push_back(deviceItem);
        if (logStatus) {
            MMI_HILOGW("deviceItem[%{public}d]: %{public}s", i, deviceItem.ToString().c_str());
        }
    }
    return deviceItems;
}
} // namespace MMI
} // namespace OHOS