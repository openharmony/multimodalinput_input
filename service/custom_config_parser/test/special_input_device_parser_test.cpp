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
#include <gmock/gmock.h>


#include "special_input_device_parser_mock.h"
#include "mmi_log.h"
#include "special_input_device_parser.h"


#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SpecialInputDeviceParserTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class SpecialInputDeviceParserTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};


/*
 * @tc.name: SpecialInputDeviceParserTestest_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SpecialInputDeviceParserTest, SpecialInputDeviceParserTest001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SpecialInputDeviceParser& parser = SpecialInputDeviceParser::GetInstance();
    SpecialInputDeviceParserMock Mock;
    EXPECT_CALL(Mock, ReadJsonFile).WillRepeatedly(testing::Return(""));
    int32_t result = parser.Init();
    EXPECT_EQ(result, RET_OK);
}

/*
 * @tc.name: SpecialInputDeviceParserTestest_002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SpecialInputDeviceParserTest, SpecialInputDeviceParserTest002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SpecialInputDeviceParser& parser = SpecialInputDeviceParser::GetInstance();
    int32_t result = parser.Init();
    EXPECT_EQ(result, RET_OK);
}

/*
 * @tc.name: SpecialInputDeviceParserTestest_003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SpecialInputDeviceParserTest, SpecialInputDeviceParserTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SpecialInputDeviceParser& parser = SpecialInputDeviceParser::GetInstance();
    SpecialInputDeviceParserMock Mock;
    EXPECT_CALL(Mock, ReadJsonFile).WillRepeatedly(testing::Return("invalid json"));
    int32_t result = parser.Init();
    EXPECT_EQ(result, RET_OK);
}

/*
 * @tc.name: SpecialInputDeviceParserTestest_004
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SpecialInputDeviceParserTest, SpecialInputDeviceParserTest_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonStr = R"({
        "product_name_types": [
            {
                "product_name": "testProduct",
                "type": "testType"
            }
        ]
    })";
    SpecialInputDeviceParser& parser = SpecialInputDeviceParser::GetInstance();
    SpecialInputDeviceParserMock Mock;
    EXPECT_CALL(Mock, ReadJsonFile).WillRepeatedly(testing::Return(jsonStr));
    int32_t result = parser.Init();
    EXPECT_EQ(result, RET_OK);
}

/*
 * @tc.name: SpecialInputDeviceParserTestest_005
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(SpecialInputDeviceParserTest, SpecialInputDeviceParserTest_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonStr = R"({
        "exactly_match": "exactly_match_code"
    })";
    SpecialInputDeviceParser& parser = SpecialInputDeviceParser::GetInstance();
    SpecialInputDeviceParserMock Mock;
    EXPECT_CALL(Mock, ReadJsonFile).WillRepeatedly(testing::Return(jsonStr));
    int32_t result = parser.Init();
    EXPECT_EQ(result, RET_OK);
}

/*
 * @tc.name: SpecialInputDeviceParserTestest_006
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(SpecialInputDeviceParserTest, SpecialInputDeviceParserTest_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string jsonStr = R"({
        "exactly_match": [{}, {}
        ]
    })";
    SpecialInputDeviceParser& parser = SpecialInputDeviceParser::GetInstance();
    SpecialInputDeviceParserMock Mock;
    EXPECT_CALL(Mock, ReadJsonFile).WillRepeatedly(testing::Return(jsonStr));
    int32_t result = parser.Init();
    EXPECT_EQ(result, RET_OK);
}

/*
 * @tc.name: SpecialInputDeviceParserTestest_007
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SpecialInputDeviceParserTest, SpecialInputDeviceParserTest007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SpecialInputDeviceParser& parser = SpecialInputDeviceParser::GetInstance();
    SpecialInputDeviceParserMock Mock;
    EXPECT_CALL(Mock, ReadJsonFile).WillRepeatedly(testing::Return("OK"));
    parser.isInitialized_.store(true);
    int32_t result = parser.Init();
    EXPECT_EQ(result, RET_ERR);
}

} // namespace MMI
} // namespace OHOS