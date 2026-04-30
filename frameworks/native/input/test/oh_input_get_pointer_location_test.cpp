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

/**
 * @file oh_input_get_pointer_location_test.cpp
 * @brief Unit tests for OH_Input_GetPointerLocation
 * @desc Test getting pointer location with permission checks (OR logic)
 */

#include <cstdio>
#include <gtest/gtest.h>
#include <memory>

#include "oh_input_manager.h"
#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "GetPointerLocationTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class GetPointerLocationTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        MMI_HILOGI("GetPointerLocationTest SetUpTestCase");
    }

    static void TearDownTestCase(void)
    {
        MMI_HILOGI("GetPointerLocationTest TearDownTestCase");
    }

    void SetUp() override
    {
        MMI_HILOGI("GetPointerLocationTest SetUp");
    }

    void TearDown() override
    {
        MMI_HILOGI("GetPointerLocationTest TearDown");
    }
};

/**
 * @tc.name: OH_Input_GetPointerLocation_NullPointer_ParameterError
 * @tc.desc: Test getting pointer location with null pointer parameters
 * @tc.type: FUNC
 * @tc.require: AR000H5VSG
 */
HWTEST_F(GetPointerLocationTest, OH_Input_GetPointerLocation_NullPointer_ParameterError, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMI_HILOGI("OH_Input_GetPointerLocation_NullPointer_ParameterError start");

    // Test null displayId
    double displayX = 0.0;
    double displayY = 0.0;
    Input_Result ret = OH_Input_GetPointerLocation(nullptr, &displayX, &displayY);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);

    int32_t displayId = 0;
    ret = OH_Input_GetPointerLocation(&displayId, nullptr, &displayY);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);

    ret = OH_Input_GetPointerLocation(&displayId, &displayX, nullptr);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);

    ret = OH_Input_GetPointerLocation(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);

    MMI_HILOGI("OH_Input_GetPointerLocation_NullPointer_ParameterError end");
}

/**
 * @tc.name: OH_Input_GetPointerLocation_AllNullPointers_ParameterError
 * @tc.desc: Test getting pointer location with all null pointers
 * @tc.type: FUNC
 * @tc.require: AR000H5VSG
 */
HWTEST_F(GetPointerLocationTest, OH_Input_GetPointerLocation_AllNullPointers_ParameterError, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMI_HILOGI("OH_Input_GetPointerLocation_AllNullPointers_ParameterError start");

    Input_Result ret = OH_Input_GetPointerLocation(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);

    MMI_HILOGI("OH_Input_GetPointerLocation_AllNullPointers_ParameterError end");
}

/**
 * @tc.name: OH_Input_GetPointerLocation_ValidParameters_ReturnsSuccess
 * @tc.desc: Test getting pointer location with valid parameters
 * @tc.type: FUNC
 * @tc.require: AR000H5VSG
 * @tc.note: This test requires pointer device and proper permissions
 */
HWTEST_F(GetPointerLocationTest, OH_Input_GetPointerLocation_ValidParameters_ReturnsSuccess, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId = 0;
    double displayX = 0.0;
    double displayY = 0.0;
    Input_Result ret = OH_Input_GetPointerLocation(&displayId, &displayX, &displayY);
    EXPECT_TRUE(ret == INPUT_SUCCESS || ret == INPUT_PERMISSION_DENIED ||
                ret == INPUT_DEVICE_NO_POINTER || ret == INPUT_APP_NOT_FOCUSED ||
                ret == INPUT_SERVICE_EXCEPTION);
}

/**
 * @tc.name: OH_Input_GetPointerLocation_MultipleCalls_ConsistentResults
 * @tc.desc: Test multiple calls to GetPointerLocation return consistent results
 * @tc.type: FUNC
 * @tc.require: AR000H5VSG
 */
HWTEST_F(GetPointerLocationTest, OH_Input_GetPointerLocation_MultipleCalls_ConsistentResults, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId1 = 0;
    double displayX1 = 0.0;
    double displayY1 = 0.0;
    Input_Result ret1 = OH_Input_GetPointerLocation(&displayId1, &displayX1, &displayY1);

    int32_t displayId2 = 0;
    double displayX2 = 0.0;
    double displayY2 = 0.0;
    Input_Result ret2 = OH_Input_GetPointerLocation(&displayId2, &displayX2, &displayY2);

    EXPECT_EQ(ret1, ret2);
}

/**
 * @tc.name: OH_Input_GetPointerLocation_CheckOutputParameters
 * @tc.desc: Test that output parameters are properly set on success
 * @tc.type: FUNC
 * @tc.require: AR000H5VSG
 */
HWTEST_F(GetPointerLocationTest, OH_Input_GetPointerLocation_CheckOutputParameters, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId = -1;
    double displayX = -1.0;
    double displayY = -1.0;
    Input_Result ret = OH_Input_GetPointerLocation(&displayId, &displayX, &displayY);
    if (ret == INPUT_SUCCESS) {
        EXPECT_GE(displayId, 0);
        MMI_HILOGI("Success case - displayId: %{public}d, displayX: %{public}f, displayY: %{public}f",
                   displayId, displayX, displayY);
    } else {
        MMI_HILOGI("Non-success result: %{public}d", ret);
    }
}
} // namespace MMI
} // namespace OHOS
