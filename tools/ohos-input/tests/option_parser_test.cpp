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

#include <gtest/gtest.h>
#include "option_parser.h"
#include <cstdint>
#include <set>
#include <string>
#include <vector>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::MMI::InputCli;

class OptionParserTest : public Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(OptionParserTest, ParseOptionPairs_KnownPairs_Accepted, TestSize.Level1)
{
    const std::set<std::string> allowed { "--key", "--modifier" };
    Options options;
    EXPECT_TRUE(ParseOptionPairs({ "--key", "2049" }, allowed, options));
    EXPECT_EQ(options.count("--key"), 1U);
    EXPECT_EQ(options["--key"], "2049");
}

HWTEST_F(OptionParserTest, ParseOptionPairs_MissingValue_Rejected, TestSize.Level1)
{
    const std::set<std::string> allowed { "--key", "--modifier" };
    Options options;
    EXPECT_FALSE(ParseOptionPairs({ "--key" }, allowed, options));
    EXPECT_TRUE(options.empty());
}

HWTEST_F(OptionParserTest, ParseOptionPairs_NameWithoutDashes_Rejected, TestSize.Level1)
{
    const std::set<std::string> allowed { "--key", "--modifier" };
    Options options;
    EXPECT_FALSE(ParseOptionPairs({ "key", "2049" }, allowed, options));
    EXPECT_TRUE(options.empty());
}

HWTEST_F(OptionParserTest, ParseOptionPairs_UnknownOption_Rejected, TestSize.Level1)
{
    const std::set<std::string> allowed { "--key", "--modifier" };
    Options options;
    EXPECT_FALSE(ParseOptionPairs({ "--unknown", "x" }, allowed, options));
    EXPECT_TRUE(options.empty());
}

HWTEST_F(OptionParserTest, ParseOptionPairs_Duplicate_RejectedAndKeepsFirst, TestSize.Level1)
{
    const std::set<std::string> allowed { "--key", "--modifier" };
    Options options;
    EXPECT_FALSE(ParseOptionPairs({ "--key", "1", "--key", "2" }, allowed, options));
    EXPECT_EQ(options.count("--key"), 1U);
    EXPECT_EQ(options["--key"], "1");
}

HWTEST_F(OptionParserTest, ParseNumber_ValidValue_Accepted, TestSize.Level1)
{
    Options options { { "--x", "10" } };
    int32_t value = -1;
    std::string error;
    EXPECT_TRUE(ParseNumber(options, { "--x", false, 7, 0, 100 }, value, error));
    EXPECT_EQ(value, 10);
}

HWTEST_F(OptionParserTest, ParseNumber_NonNumeric_RejectedWithInvalidMessage, TestSize.Level1)
{
    Options options { { "--x", "abc" } };
    int32_t value = -1;
    std::string error;
    EXPECT_FALSE(ParseNumber(options, { "--x", false, 7, 0, 100 }, value, error));
    EXPECT_EQ(error, "--x must be an integer");
}

HWTEST_F(OptionParserTest, ParseNumber_OutOfRange_RejectedWithRangeMessage, TestSize.Level1)
{
    Options options { { "--x", "101" } };
    int32_t value = -1;
    std::string error;
    EXPECT_FALSE(ParseNumber(options, { "--x", true, 7, 0, 100 }, value, error));
    EXPECT_EQ(error, "--x is out of range");
}

HWTEST_F(OptionParserTest, ParseNumber_MissingOptional_UsesFallback, TestSize.Level1)
{
    Options options;
    int32_t value = -1;
    std::string error;
    EXPECT_TRUE(ParseNumber(options, { "--x", false, 7, 0, 100 }, value, error));
    EXPECT_EQ(value, 7);
}

HWTEST_F(OptionParserTest, ParseNumber_MissingRequired_RejectedWithMissingMessage, TestSize.Level1)
{
    Options options;
    int32_t value = -1;
    std::string error;
    EXPECT_FALSE(ParseNumber(options, { "--x", true, 7, 0, 100 }, value, error));
    EXPECT_EQ(error, "missing required --x");
}
