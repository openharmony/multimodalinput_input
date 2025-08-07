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

#include <gtest/gtest.h>
#include <string>

#include "json_parser.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace OHOS;
} // namespace

class JsonParserTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name:IsIntegerTest_001
 * @tc.desc:Verify JsonParser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, IsInteger_001, TestSize.Level1)
{
    JsonParser parser(nullptr);
    EXPECT_FALSE(JsonParser::IsInteger(parser.Get()));
}
 
/**
 * @tc.name:JsonParserTest_001
 * @tc.desc:Verify JsonParser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParser_001, TestSize.Level1)
{
    JsonParser parser(R"({"Hello": 1})");
    JsonParser parser1(R"({"Hello": 2})");
    parser1 = std::move(parser);
    auto json = parser1.Get();
    EXPECT_NE(json, nullptr);
}
 
/**
 * @tc.name:JsonParserTest_002
 * @tc.desc:Verify JsonParser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, JsonParser_002, TestSize.Level1)
{
    JsonParser parser(R"({"Hello": 1})");
    JsonParser parser1 = std::move(parser);
    auto json = parser1.Get();
    EXPECT_NE(json, nullptr);
}
 
/**
 * @tc.name:ParseInt_001
 * @tc.desc:Verify ParseInt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseInt_001, TestSize.Level1)
{
    std::string jsonData = R"({"Hello": 1})";
    JsonParser parser(jsonData.c_str());
    int32_t value;
    EXPECT_EQ(JsonParser::ParseInt32(parser.Get(), "Hello", value), RET_OK);
}
 
/**
 * @tc.name:ParseInt_002
 * @tc.desc:Verify ParseInt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseInt_002, TestSize.Level1)
{
    std::string jsonData = R"({"Hello": "world"})";
    JsonParser parser(jsonData.c_str());
    int32_t value;
    EXPECT_NE(JsonParser::ParseInt32(parser.Get(), "Hello", value), RET_OK);
}
 
/**
 * @tc.name:ParseInt_003
 * @tc.desc:Verify ParseInt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseInt_003, TestSize.Level1)
{
    std::string jsonData = R"({"integer": 42.13})";
    JsonParser parser(jsonData.c_str());
    int32_t value;
    EXPECT_NE(JsonParser::ParseInt32(parser.Get(), "integer", value), RET_OK);
}
 
/**
 * @tc.name:ParseInt_004
 * @tc.desc:Verify ParseInt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseInt_004, TestSize.Level1)
{
    std::string jsonData = R"({"integer": 21474836480})";
    JsonParser parser(jsonData.c_str());
    int32_t value;
    EXPECT_NE(JsonParser::ParseInt32(parser.Get(), "integer", value), RET_OK);
}

/**
 * @tc.name:ParseString_001
 * @tc.desc:Verify ParseString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseString_001, TestSize.Level1)
{
    std::string jsonData = R"({"Hello": "Hello World"})";
    JsonParser parser(jsonData.c_str());
    std::string value;
    EXPECT_EQ(JsonParser::ParseString(parser.Get(), "Hello", value), RET_OK);
}

/**
 * @tc.name:ParseString_002
 * @tc.desc:Verify ParseString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseString_002, TestSize.Level1)
{
    std::string jsonData = R"({"Hello": 1})";
    JsonParser parser(jsonData.c_str());
    std::string value;
    EXPECT_NE(JsonParser::ParseString(parser.Get(), "Hello", value), RET_OK);
}

/**
 * @tc.name:ParseStringArray_001
 * @tc.desc:Verify ParseStringArray
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseStringArray_001, TestSize.Level1)
{
    std::string jsonData = R"({"Hello": ["a", "b", "c"]})";
    JsonParser parser(jsonData.c_str());
    std::vector<std::string> value;
    EXPECT_EQ(JsonParser::ParseStringArray(parser.Get(), "Hello", value, 10), RET_OK);
}

/**
 * @tc.name:ParseStringArray_002
 * @tc.desc:Verify ParseStringArray
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseStringArray_002, TestSize.Level1)
{
    std::string jsonData = R"({"Hello": "World"})";
    JsonParser parser(jsonData.c_str());
    std::vector<std::string> value;
    EXPECT_NE(JsonParser::ParseStringArray(parser.Get(), "Hello", value, 10), RET_OK);
}

/**
 * @tc.name:ParseStringArray_003
 * @tc.desc:Verify ParseStringArray
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseStringArray_003, TestSize.Level1)
{
    std::string jsonData = R"({"Hello": [1, 2, 3]})";
    JsonParser parser(jsonData.c_str());
    std::vector<std::string> value;
    EXPECT_NE(JsonParser::ParseStringArray(parser.Get(), "Hello", value, 10), RET_OK);
}

/**
 * @tc.name:ParseStringArray_004
 * @tc.desc:Verify ParseStringArray
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseStringArray_004, TestSize.Level1)
{
    std::string jsonData = R"({"Hello": ["a", "b", "c", "d"]})";
    JsonParser parser(jsonData.c_str());
    std::vector<std::string> value;
    EXPECT_EQ(JsonParser::ParseStringArray(parser.Get(), "Hello", value, 2), RET_OK);
}

/**
 * @tc.name:ParseBool_001
 * @tc.desc:Verify ParseBool
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseBool_001, TestSize.Level1)
{
    std::string jsonData = R"({"Boolean": true})";
    JsonParser parser(jsonData.c_str());
    bool value;
    EXPECT_EQ(JsonParser::ParseBool(parser.Get(), "Boolean", value), RET_OK);
}

/**
 * @tc.name:ParseBool_002
 * @tc.desc:Verify ParseBool
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsonParserTest, ParseBool_002, TestSize.Level1)
{
    std::string jsonData = R"({"Boolean": "true"})";
    JsonParser parser(jsonData.c_str());
    bool value;
    EXPECT_NE(JsonParser::ParseBool(parser.Get(), "Boolean", value), RET_OK);
}

} // namespace MMI
} // namespace OHOS