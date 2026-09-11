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

#ifndef OHOS_INPUT_OPTION_PARSER_H
#define OHOS_INPUT_OPTION_PARSER_H

#include <cstdint>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace OHOS::MMI::InputCli {
using Options = std::unordered_map<std::string, std::string>;

struct NumberRule {
    std::string optionName;
    bool isRequired;
    int32_t defaultValue;
    int32_t minValue;
    int32_t maxValue;
    std::string missingOptionMessage;
    std::string outOfRangeMessage;
    std::string invalidValueMessage;
};

bool ParseInt(const std::string &value, int32_t &number);
bool ParseOptionPairs(const std::vector<std::string> &args, const std::set<std::string> &allowed,
    Options &options);
bool ParseNumber(const Options &options, const NumberRule &rule, int32_t &value, std::string &error);
NumberRule CoordinateRule(const std::string &optionName);
NumberRule DisplayIdRule(const std::string &optionName);
} // namespace OHOS::MMI::InputCli

#endif
