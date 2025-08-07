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

#ifndef MMI_JSON_PARSER_H
#define MMI_JSON_PARSER_H

#include <cinttypes>
#include <string>
#include <vector>
#include "cJSON.h"

namespace OHOS {
namespace MMI {

class JsonParser {
public:
    explicit JsonParser(const char *jsonStr);
    ~JsonParser();
    JsonParser(const JsonParser&) = delete;
    JsonParser& operator=(const JsonParser&) = delete;
    JsonParser(JsonParser&& other) noexcept;
    JsonParser& operator=(JsonParser&& other) noexcept;
    const cJSON* Get() const;

private:
    cJSON* json_ { nullptr };

public:
    static int32_t ParseInt32(const cJSON *json, const std::string &key, int32_t &value);
    static int32_t ParseString(const cJSON *json, const std::string &key, std::string &value);
    static int32_t ParseBool(const cJSON *json, const std::string &key, bool &value);
    static int32_t ParseStringArray(const cJSON *json, const std::string &key, std::vector<std::string> &value,
        int32_t maxSize);
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_JSON_PARSER_H