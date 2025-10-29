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

#include "json_parser.h"

#include <cstdint>
#include <cmath>

#include "mmi_log.h"
#include "define_multimodal.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsonParser"
namespace OHOS {
namespace MMI {

JsonParser::JsonParser(const char *jsonStr)
{
    json_ = cJSON_Parse(jsonStr);
    CHKPV(json_);
}

JsonParser::~JsonParser()
{
    if (json_ != nullptr) {
        cJSON_Delete(json_);
        json_ = nullptr;
    }
}

JsonParser::JsonParser(JsonParser&& other) noexcept : json_(other.json_)
{
    other.json_ = nullptr;
}

JsonParser& JsonParser::operator=(JsonParser&& other) noexcept
{
    if (this == &other) {
        return *this;
    }
    if (json_ != nullptr) {
        cJSON_Delete(json_);
    }
    json_ = other.json_;
    other.json_ = nullptr;
    return *this;
}

const cJSON* JsonParser::Get() const
{
    return json_;
}

bool JsonParser::IsInteger(const cJSON *json)
{
    if (json == nullptr || json->type != cJSON_Number) {
        return false;
    }
    double intPart;
    return (modf(json->valuedouble, &intPart) == 0.0);
}

int32_t JsonParser::ParseInt32(const cJSON *json, const std::string &key, int32_t &value)
{
    if (!cJSON_IsObject(json)) {
        MMI_HILOGE("The json is not object");
        return false;
    }
    cJSON *jsonNode = cJSON_GetObjectItemCaseSensitive(json, key.c_str());
    CHKPR(jsonNode, RET_ERR);
    if (!cJSON_IsNumber(jsonNode)) {
        MMI_HILOGE("value is not number");
        return RET_ERR;
    }
    if (!IsInteger(jsonNode)) {
        MMI_HILOGE("value is not integer");
        return RET_ERR;
    }
    if (jsonNode->valueint < std::numeric_limits<int32_t>::min() ||
        jsonNode->valueint > std::numeric_limits<int32_t>::max()) {
        MMI_HILOGE("value is out of int32_t bounds");
        return RET_ERR;
    }
    value = jsonNode->valueint;
    return RET_OK;
}

int32_t JsonParser::ParseString(const cJSON *json, const std::string &key, std::string &value)
{
    if (!cJSON_IsObject(json)) {
        MMI_HILOGE("The json is not object");
        return false;
    }
    cJSON *jsonNode = cJSON_GetObjectItemCaseSensitive(json, key.c_str());
    CHKPR(jsonNode, RET_ERR);
    if (!cJSON_IsString(jsonNode)) {
        MMI_HILOGE("value is not str");
        return RET_ERR;
    }
    value = jsonNode->valuestring;
    return RET_OK;
}

int32_t JsonParser::ParseBool(const cJSON *json, const std::string &key, bool &value)
{
    if (!cJSON_IsObject(json)) {
        MMI_HILOGE("The json is not object");
        return false;
    }
    cJSON *jsonNode = cJSON_GetObjectItemCaseSensitive(json, key.c_str());
    CHKPR(jsonNode, RET_ERR);
    if (!cJSON_IsBool(jsonNode)) {
        MMI_HILOGE("value is not bool");
        return RET_ERR;
    }
    value = cJSON_IsTrue(jsonNode);
    return RET_OK;
}

int32_t JsonParser::ParseStringArray(const cJSON *json, const std::string &key, std::vector<std::string> &value,
    int32_t maxSize)
{
    if (!cJSON_IsObject(json)) {
        MMI_HILOGE("The json is not object");
        return false;
    }
    cJSON *jsonNode = cJSON_GetObjectItemCaseSensitive(json, key.c_str());
    CHKPR(jsonNode, RET_ERR);
    if (!cJSON_IsArray(jsonNode)) {
        MMI_HILOGE("jsonNode is not array");
        return RET_ERR;
    }
    int32_t arraySize = cJSON_GetArraySize(jsonNode);
    if (arraySize > maxSize) {
        MMI_HILOGW("arraySize is too much, truncate it");
    }
    value.clear();
    for (int32_t i = 0; i < std::min(maxSize, arraySize); i++) {
        cJSON* arrayItem = cJSON_GetArrayItem(jsonNode, i);
        if (!cJSON_IsString(arrayItem)) {
            MMI_HILOGE("The arrayItem is not string");
            return RET_ERR;
        }
        value.push_back(arrayItem->valuestring);
    }
    return RET_OK;
}

} // namespace MMI
} // namespace OHOS