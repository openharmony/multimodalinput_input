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


#include "special_input_device_parser.h"

#include "json_parser.h"
#include "util.h"

#include <cJSON.h>

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SpecialInputDeviceParser"

namespace OHOS {
namespace MMI {
namespace {
constexpr std::string_view specialInputDeviceDir { "/etc/multimodalinput/special_input_device_config.json" };
constexpr int32_t maxJsonArraySize { 100 };
}

SpecialInputDeviceParser& SpecialInputDeviceParser::GetInstance()
{
    static SpecialInputDeviceParser instance;
    return instance;
}

int32_t SpecialInputDeviceParser::Init()
{
    CALL_DEBUG_ENTER;
    static std::once_flag init_flag;
    static int32_t initRes = RET_ERR;
    std::call_once(init_flag, [this]() {
        initRes = InitializeImpl();
    });
    return initRes;
}

int32_t SpecialInputDeviceParser::InitializeImpl()
{
    CALL_INFO_TRACE;
    std::string jsonStr = ReadJsonFile(std::string(specialInputDeviceDir));
    if (jsonStr.empty()) {
        MMI_HILOGE("Read specialInputDevice failed");
        return RET_ERR;
    }
    JsonParser parser(jsonStr.c_str());
    if (!cJSON_IsObject(parser.Get())) {
        MMI_HILOGE("Not valid object");
        return RET_ERR;
    }
    if (ParseExactlyMatch(parser) != RET_OK) {
        MMI_HILOGE("ParseExactlyMatch failed");
        return RET_ERR;
    }
    if (ParseContainMatch(parser) != RET_OK) {
        MMI_HILOGE("ParseContainMatch failed");
        return RET_ERR;
    }
    if (ParseSpecialInputDevice(parser) != RET_OK) {
        MMI_HILOGE("ParseSpecialInputDevice failed");
        return RET_ERR;
    }
    PrintSpecialInputDevice();
    return RET_OK;
}

int32_t SpecialInputDeviceParser::IsPointerDevice(const std::string &name, bool &isPointerDevice)
{
    if (Init() != RET_OK) {
        MMI_HILOGE("Init failed");
        return RET_ERR;
    }
    std::shared_lock<std::shared_mutex> lock(lock_);
    if (exactlyMatchInputDevice_.find(name) != exactlyMatchInputDevice_.end()) {
        isPointerDevice =  exactlyMatchInputDevice_[name].isMouse;
        return RET_OK;
    }
    for (const auto &containItem : containMatchInputDevice_) {
        if (IsAllKeywordsMatched(name, containItem.keywords)) {
            isPointerDevice = containItem.isMouse;
            return RET_OK;
        }
    }
    return RET_ERR;
}

std::string SpecialInputDeviceParser::GetInputDevName(const std::string &alias)
{
    if (Init() != RET_OK) {
        MMI_HILOGE("Init failed");
        return "";
    }
    std::shared_lock<std::shared_mutex> lock(lock_);
    if (specialInputDevices_.find(alias) != specialInputDevices_.end()) {
        return specialInputDevices_[alias];
    }
    MMI_HILOGW("No %{public}s matched.", alias.c_str());
    return "";
}

int32_t SpecialInputDeviceParser::ParseExactlyMatch(const JsonParser &jsonParser)
{
    if (!cJSON_IsObject(jsonParser.Get())) {
        MMI_HILOGE("The jsonParser is not object");
        return RET_ERR;
    }
    cJSON *exactlyMatchJson = cJSON_GetObjectItemCaseSensitive(jsonParser.Get(), "exactly_match");
    if (!cJSON_IsArray(exactlyMatchJson)) {
        MMI_HILOGE("exactlyMatchJson is not array");
        return RET_ERR;
    }
    int32_t arraySize = cJSON_GetArraySize(exactlyMatchJson);
    if (arraySize > maxJsonArraySize) {
        MMI_HILOGW("arraySize is too much, truncate it");
    }
    for (int32_t i = 0; i < std::min(arraySize, maxJsonArraySize); i++) {
        cJSON* devItemJson = cJSON_GetArrayItem(exactlyMatchJson, i);
        if (devItemJson == nullptr) {
            MMI_HILOGE("The devItem init failed");
            continue;
        }
        ExactlyMatchInputDevice inputDev;
        if (ParseExactlyMatchItem(devItemJson, inputDev) != RET_OK) {
            MMI_HILOGE("ParseExactlyMatchItem failed");
            continue;
        }
        std::unique_lock<std::shared_mutex> lock(lock_);
        exactlyMatchInputDevice_.insert({inputDev.devName, { inputDev.devName, inputDev.isMouse }});
    }
    return RET_OK;
}

int32_t SpecialInputDeviceParser::ParseContainMatch(const JsonParser &jsonParser)
{
    if (!cJSON_IsObject(jsonParser.Get())) {
        MMI_HILOGE("The jsonParser is not object");
        return RET_ERR;
    }
    cJSON *containMatchJson = cJSON_GetObjectItemCaseSensitive(jsonParser.Get(), "contain_match");
    if (!cJSON_IsArray(containMatchJson)) {
        MMI_HILOGE("containMatchJson is not array");
        return RET_ERR;
    }
    int32_t arraySize = cJSON_GetArraySize(containMatchJson);
    if (arraySize > maxJsonArraySize) {
        MMI_HILOGE("arraySize is too much");
        return RET_ERR;
    }
    for (int32_t i = 0; i < arraySize; i++) {
        cJSON* devItemJson = cJSON_GetArrayItem(containMatchJson, i);
        if (devItemJson == nullptr) {
            MMI_HILOGE("The devItem init failed");
            continue;
        }
        ContainMatchInputDevice inputDev;
        if (ParseContainMatchItem(devItemJson, inputDev) != RET_OK) {
            MMI_HILOGE("ParseContainMatchItem failed");
            continue;
        }
        std::unique_lock<std::shared_mutex> lock(lock_);
        containMatchInputDevice_.push_back(inputDev);
    }
    return RET_OK;
}

int32_t SpecialInputDeviceParser::ParseSpecialInputDevice(const JsonParser &jsonParser)
{
    if (!cJSON_IsObject(jsonParser.Get())) {
        MMI_HILOGE("The jsonParser is not object");
        return RET_ERR;
    }
    cJSON *specialInputDevJson = cJSON_GetObjectItemCaseSensitive(jsonParser.Get(), "special_input_device");
    if (!cJSON_IsArray(specialInputDevJson)) {
        MMI_HILOGE("specialInputDevJson is not array");
        return RET_ERR;
    }
    int32_t arraySize = cJSON_GetArraySize(specialInputDevJson);
    if (arraySize > maxJsonArraySize) {
        MMI_HILOGE("arraySize is too much");
        return RET_ERR;
    }
    for (int32_t i = 0; i < arraySize; i++) {
        cJSON* devItemJson = cJSON_GetArrayItem(specialInputDevJson, i);
        if (devItemJson == nullptr) {
            MMI_HILOGE("The devItem init failed");
            continue;
        }
        SpecialInputDevice inputDev;
        if (ParseSpecialInputDeviceItem(devItemJson, inputDev) != RET_OK) {
            MMI_HILOGE("ParseSpecialInputDeviceItem failed");
            continue;
        }
        std::unique_lock<std::shared_mutex> lock(lock_);
        specialInputDevices_.insert({ inputDev.inputDevAlias, inputDev.inputDevName });
    }
    return RET_OK;
}

int32_t SpecialInputDeviceParser::ParseExactlyMatchItem(const cJSON *json, ExactlyMatchInputDevice &deviceProp)
{
    if (JsonParser::ParseString(json, "device_name", deviceProp.devName) != RET_OK) {
        MMI_HILOGE("Parse device_name failed");
        return RET_ERR;
    }
    if (JsonParser::ParseBool(json, "is_mouse", deviceProp.isMouse) != RET_OK) {
        MMI_HILOGE("Parse is_mouse failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t SpecialInputDeviceParser::ParseContainMatchItem(const cJSON *json, ContainMatchInputDevice &deviceProp)
{
    std::vector<std::string> keywords;
    if (JsonParser::ParseStringArray(json, "keywords", keywords, maxJsonArraySize) != RET_OK) {
        MMI_HILOGE("Parse keywords failed");
        return RET_ERR;
    }
    deviceProp.keywords = std::move(keywords);
    if (JsonParser::ParseBool(json, "is_mouse", deviceProp.isMouse) != RET_OK) {
        MMI_HILOGE("Parse is_mouse failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t SpecialInputDeviceParser::ParseSpecialInputDeviceItem(const cJSON *json, SpecialInputDevice &specialInputDev)
{
    if (JsonParser::ParseString(json, "input_device_alias", specialInputDev.inputDevAlias) != RET_OK) {
        MMI_HILOGE("Parse input_device_alias failed");
        return RET_ERR;
    }
    if (JsonParser::ParseString(json, "input_device_name", specialInputDev.inputDevName) != RET_OK) {
        MMI_HILOGE("Parse input_device_name failed");
        return RET_ERR;
    }
    return RET_OK;
}

bool SpecialInputDeviceParser::IsAllKeywordsMatched(const std::string &name, const std::vector<std::string> &keywords)
{
    for (const auto &key : keywords) {
        if (name.find(key) == std::string::npos) {
            return false;
        }
    }
    return true;
}

void SpecialInputDeviceParser::PrintSpecialInputDevice()
{
    std::shared_lock<std::shared_mutex> lock(lock_);
    MMI_HILOGI("Excatly Match:");
    for (const auto &elem : exactlyMatchInputDevice_) {
        MMI_HILOGI("deviceName:%{public}s -> isMouse:%{public}d", elem.second.devName.c_str(), elem.second.isMouse);
    }
    MMI_HILOGI("Contain Match:");
    for (const auto &elem : containMatchInputDevice_) {
        std::string keywords;
        std::for_each(elem.keywords.begin(), elem.keywords.end(), [&keywords](const std::string &key) {
            keywords.append(key + ", ");
        });
        MMI_HILOGI("keywords:%{public}s -> isMouse:%{public}d", keywords.c_str(), elem.isMouse);
    }
    MMI_HILOGI("Special Input Device:");
    for (const auto &elem : specialInputDevices_) {
        MMI_HILOGI("devAlias:%{public}s -> devName:%{public}s", elem.first.c_str(), elem.second.c_str());
    }
}
} // namespace MMI
} // namespace OHOS