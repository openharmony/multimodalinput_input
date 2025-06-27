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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "oh_input_manager.h"
#include "mmi_log.h"
#include "mock.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "OHInputManagerEXTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using ::testing::_;
using ::testing::Return;
} // namespace

class OHInputManagerEXTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() {}
    void TearDown() {}

    static inline std::shared_ptr<MessageParcelMock> messageParcelMock_ = nullptr;
};

void OHInputManagerEXTest::SetUpTestCase(void)
{
    messageParcelMock_ = std::make_shared<MessageParcelMock>();
    MessageParcelMock::messageParcel = messageParcelMock_;
}

void OHInputManagerEXTest::TearDownTestCase(void)
{
    MessageParcelMock::messageParcel = nullptr;
    messageParcelMock_ = nullptr;
}


/**
 * @tc.name:  OHInputManagerEXTest_GetPointerLocation_001
 * @tc.desc: Get Pointer location
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerEXTest, OHInputManagerEXTest_GetPointerLocation_001, TestSize.Level1)
{
    int32_t displayId = 0;
    double displayX = 0.0;
    double displayY = 0.0;
    
    EXPECT_CALL(*messageParcelMock_, GetPointerLocation(_, _, _))
        .WillOnce(Return(INPUT_DEVICE_NO_POINTER));
    Input_Result result = OH_Input_GetPointerLocation(&displayId, &displayX, &displayY);
    EXPECT_EQ(result, INPUT_DEVICE_NO_POINTER);
}

/**
 * @tc.name:  OHInputManagerEXTest_GetPointerLocation_002
 * @tc.desc: Get Pointer location
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerEXTest, OHInputManagerEXTest_GetPointerLocation_002, TestSize.Level1)
{
    int32_t displayId = 0;
    double displayX = 0.0;
    double displayY = 0.0;
    
    EXPECT_CALL(*messageParcelMock_, GetPointerLocation(_, _, _))
        .WillOnce(Return(INPUT_APP_NOT_FOCUSED));
    Input_Result result = OH_Input_GetPointerLocation(&displayId, &displayX, &displayY);
    EXPECT_EQ(result, INPUT_APP_NOT_FOCUSED);
}

/**
 * @tc.name:  OHInputManagerEXTest_GetPointerLocation_003
 * @tc.desc: Get Pointer location
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerEXTest, OHInputManagerEXTest_GetPointerLocation_003, TestSize.Level1)
{
    int32_t displayId = 0;
    double displayX = 0.0;
    double displayY = 0.0;
    
    EXPECT_CALL(*messageParcelMock_, GetPointerLocation(_, _, _))
        .WillOnce(Return(INPUT_SERVICE_EXCEPTION));
    Input_Result result = OH_Input_GetPointerLocation(&displayId, &displayX, &displayY);
    EXPECT_EQ(result, INPUT_SERVICE_EXCEPTION);
}

/**
 * @tc.name:  OHInputManagerEXTest_GetPointerLocation_004
 * @tc.desc: Get Pointer location
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerEXTest, OHInputManagerEXTest_GetPointerLocation_004, TestSize.Level1)
{
    int32_t displayId = 0;
    double displayX = 0.0;
    double displayY = 0.0;
    
    EXPECT_CALL(*messageParcelMock_, GetPointerLocation(_, _, _))
        .WillOnce(Return(INPUT_SUCCESS));
    Input_Result result = OH_Input_GetPointerLocation(&displayId, &displayX, &displayY);
    EXPECT_EQ(result, INPUT_SUCCESS);
}

/**
 * @tc.name:  OHInputManagerEXTest_GetPointerLocation_005
 * @tc.desc: Get Pointer location
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerEXTest, OHInputManagerEXTest_GetPointerLocation_005, TestSize.Level1)
{
    double displayX = 0.0;
    double displayY = 0.0;
    
    Input_Result result = OH_Input_GetPointerLocation(nullptr, &displayX, &displayY);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name:  OHInputManagerEXTest_GetPointerLocation_006
 * @tc.desc: Get Pointer location
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerEXTest, OHInputManagerEXTest_GetPointerLocation_006, TestSize.Level1)
{
    int32_t displayId = 0;
    double displayY = 0.0;
    
    Input_Result result = OH_Input_GetPointerLocation(&displayId, nullptr double &displayY);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name:  OHInputManagerEXTest_GetPointerLocation_007
 * @tc.desc: Get Pointer location
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerEXTest, OHInputManagerEXTest_GetPointerLocation_007, TestSize.Level1)
{
    int32_t displayId = 0;
    double displayX = 0.0;

    Input_Result result = OH_Input_GetPointerLocation(&displayId, &displayX, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}
} // namespace MMI
} // namespace OHOS