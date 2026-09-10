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

#ifndef OHOS_INPUT_TEST_COMMAND_RUNNER_H
#define OHOS_INPUT_TEST_COMMAND_RUNNER_H

#include <gtest/gtest.h>

#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "executor.h"

namespace OHOS::MMI::InputCli {
struct RecordedCall {
    std::string name;
    std::vector<int32_t> values;
};

struct CommandResult {
    int32_t code;
    std::string stdoutText;
};

class StdoutRedirectGuard final {
public:
    explicit StdoutRedirectGuard(std::streambuf *replacement) : previous_(std::cout.rdbuf(replacement)) {}
    ~StdoutRedirectGuard()
    {
        std::cout.rdbuf(previous_);
    }

    StdoutRedirectGuard(const StdoutRedirectGuard &) = delete;
    StdoutRedirectGuard &operator=(const StdoutRedirectGuard &) = delete;

private:
    std::streambuf *previous_;
};

inline CommandResult Run(const std::vector<std::string> &arguments)
{
    std::ostringstream output;
    StdoutRedirectGuard redirectGuard(output.rdbuf());
    int32_t code = ExecuteCommand(arguments);
    return { code, output.str() };
}

inline nlohmann::json ParseJson(const CommandResult &result)
{
    return nlohmann::json::parse(result.stdoutText);
}

inline void ExpectCalls(const std::vector<RecordedCall> &actual, const std::vector<RecordedCall> &expected)
{
    EXPECT_EQ(actual.size(), expected.size());
    for (size_t index = 0; index < expected.size(); ++index) {
        EXPECT_EQ(actual[index].name, expected[index].name);
        EXPECT_TRUE(actual[index].values == expected[index].values);
    }
}
} // namespace OHOS::MMI::InputCli

#endif
