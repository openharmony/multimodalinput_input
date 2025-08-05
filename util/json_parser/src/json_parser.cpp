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

namespace OHOS {
namespace MMI {
explicit JsonParser::JsonParser(const char *jsonStr)
{
    json_ = cJSON_Parse(jsonStr);
    if (!json_) {
        MMI_HILOGE("json_ is nullptr");
    }
}

JsonParser::~JsonParser()
{
    if (json_) {
        cJSON_Delete(json_);
        json_ = nullptr;
    }
}

JsonParser::JsonParser(JsonParser&& other) noexcept : json_(other.json_) {
    other.json_ = nullptr;
}

JsonParser& JsonParser::operator=(JsonParser&& other) noexcept
{
    if (this == &other) {
        return *this;
    }
    if (json_) {
        cJSON_Delete(json_);
    }
    json_ = other.json_;
    other.json_ = nullptr;
    return *this;
}

cJSON* JsonParser::Get() const
{
    return json_;
}

} // namespace MMI
} // namespace OHOS