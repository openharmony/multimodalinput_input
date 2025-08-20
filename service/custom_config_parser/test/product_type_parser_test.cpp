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


#include "product_type_parser_mock.h"
#include "mmi_log.h"
#include "product_type_parser.h"


#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ProductTypeParserTest"

namespace OHOS {
namespace MMI {
namespace {

using namespace testing::ext;
} // namespace

class ProductTypeParserTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};


/**
 * @tc.name: ProductTypeParserTest_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProductTypeParserTest, ProductTypeParserTest001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ProductTypeParser& parser = ProductTypeParser::GetInstance();
    int32_t result = parser.Init();
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: ProductTypeParserTest_002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProductTypeParserTest, ProductTypeParserTest002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ProductTypeParser& parser = ProductTypeParser::GetInstance();
    if (parser.Init() != RET_OK) {
        return;
    }
    DeviceType deviceType;
    int32_t result = parser.GetProductType("test_product", deviceType);
    EXPECT_EQ(result, RET_ERR);
}


/**
 * @tc.name: ProductTypeParserTest_003
 * @tc.desc:The test Init() fails to read the JSON file.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProductTypeParserTest, ProductTypeParserTest003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ProductTypeParser& parser = ProductTypeParser::GetInstance();
    ProductTypeParserMock Mock;
    EXPECT_CALL(Mock, ReadJsonFile).WillRepeatedly(testing::Return(""));
    int32_t result = parser.Init();
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: ProductTypeParserTest_004
 * @tc.desc:Test that Init() is initialized successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProductTypeParserTest, ProductTypeParserTest004, TestSize.Level1)
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
    ProductTypeParser& parser = ProductTypeParser::GetInstance();
    ProductTypeParserMock Mock;
    EXPECT_CALL(Mock, ReadJsonFile).WillRepeatedly(testing::Return(jsonStr));
    int32_t result = parser.Init();
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: ProductTypeParserTest_005
 * @tc.desc:Test the GetProductType() product not found.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProductTypeParserTest, ProductTypeParserTest005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ProductTypeParser& parser = ProductTypeParser::GetInstance();
    parser.productTypes_.clear();
    DeviceType deviceType;
    int32_t result = parser.GetProductType("nonExistentProduct", deviceType);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: ProductTypeParserTest_006
 * @tc.desc:Test the GetProductType() device type not found.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProductTypeParserTest, ProductTypeParserTest006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ProductTypeParser& parser = ProductTypeParser::GetInstance();
    parser.productTypes_["testProduct"] = "unknownType";
    DeviceType deviceType;
    int32_t result = parser.GetProductType("testProduct", deviceType);
    EXPECT_EQ(result, RET_ERR);
}

} // namespace MMI
} // namespace OHOS