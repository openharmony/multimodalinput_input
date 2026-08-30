/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef PARSE_INJECT_VALUE_H
#define PARSE_INJECT_VALUE_H

#include <charconv>
#include <cstdint>
#include <string>
#include <system_error>

namespace OHOS {
namespace MMI {

/* Parse a full-string decimal int32 without throwing (replaces digit-check + stoi). */
inline bool ParseInjectValue(const std::string &str, int32_t &out)
{
    if (str.empty()) {
        return false;
    }
    int64_t value = 0;
    auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), value);
    if (ec != std::errc() || ptr != str.data() + str.size()) {
        return false;
    }
    if (value < INT32_MIN || value > INT32_MAX) {
        return false;
    }
    out = static_cast<int32_t>(value);
    return true;
}

} // namespace MMI
} // namespace OHOS

#endif // PARSE_INJECT_VALUE_H
