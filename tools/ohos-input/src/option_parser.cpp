/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "option_parser.h"

#include <cerrno>
#include <cstdint>
#include <cstdlib>

namespace OHOS::MMI::InputCli {
namespace {
constexpr size_t OPTION_PAIR_STRIDE = 2;
} // namespace

bool ParseInt(const std::string &value, int32_t &number)
{
    char *end = nullptr;
    errno = 0;
    long parsed = strtol(value.c_str(), &end, 10);
    if (errno != 0 || end == value.c_str() || *end != '\0' || parsed < INT32_MIN || parsed > INT32_MAX) {
        return false;
    }
    number = static_cast<int32_t>(parsed);
    return true;
}

bool ParseOptionPairs(const std::vector<std::string> &args, const std::set<std::string> &allowed,
    Options &options)
{
    for (size_t index = 0; index < args.size(); index += OPTION_PAIR_STRIDE) {
        if (index + 1 >= args.size() || args[index].rfind("--", 0) != 0 || options.count(args[index]) != 0 ||
            allowed.count(args[index]) == 0) {
            return false;
        }
        options[args[index]] = args[index + 1];
    }
    return true;
}

bool ParseNumber(const Options &options, const NumberRule &rule, int32_t &value, std::string &error)
{
    const auto option = options.find(rule.optionName);
    if (option == options.end()) {
        if (rule.isRequired) {
            error = !rule.missingOptionMessage.empty() ? rule.missingOptionMessage
                : std::string("missing required ") + rule.optionName;
            return false;
        }
        value = rule.defaultValue;
        return true;
    }
    if (!ParseInt(option->second, value)) {
        error = !rule.invalidValueMessage.empty() ? rule.invalidValueMessage
            : std::string(rule.optionName) + " must be an integer";
        return false;
    }
    if (value < rule.minValue || value > rule.maxValue) {
        error = !rule.outOfRangeMessage.empty() ? rule.outOfRangeMessage
            : std::string(rule.optionName) + " is out of range";
        return false;
    }
    return true;
}

NumberRule CoordinateRule(const std::string &optionName)
{
    return NumberRule {
        .optionName = optionName,
        .isRequired = true,
        .minValue = 0,
        .maxValue = INT32_MAX,
    };
}

NumberRule DisplayIdRule(const std::string &optionName)
{
    return NumberRule {
        .optionName = optionName,
        .isRequired = false,
        .defaultValue = 0,
        .minValue = 0,
        .maxValue = INT32_MAX,
    };
}
} // namespace OHOS::MMI::InputCli
