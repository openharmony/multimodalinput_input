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
 * @file oh_input_set_display_bind_test.cpp
 * @brief Unit tests for OH_Input_BindInputDeviceToDisplay
 * @desc Test binding input device to display with permission checks
 */

#include <cstdio>
#include <gtest/gtest.h>
#include <memory>
#include <cstring>
#include <algorithm>

#include "oh_input_manager.h"
#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SetDisplayBindTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class SetDisplayBindTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        MMI_HILOGI("SetDisplayBindTest SetUpTestCase");
    }

    static void TearDownTestCase(void)
    {
        MMI_HILOGI("SetDisplayBindTest TearDownTestCase");
    }

    void SetUp() override
    {
        MMI_HILOGI("SetDisplayBindTest SetUp");
    }

    void TearDown() override
    {
        MMI_HILOGI("SetDisplayBindTest TearDown");
    }
};

/**
 * @tc.name: OH_Input_BindInputDeviceToDisplay_Invalid_deviceId
 * @tc.desc: Test binding deviceId is invalid
 * @tc.type: FUNC
 * @tc.require: AR000H5VSG
 */
HWTEST_F(SetDisplayBindTest, OH_Input_BindInputDeviceToDisplay_Invalid_deviceId, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = -1;
    int32_t displayId = 0;

    Input_Result ret = OH_Input_BindInputDeviceToDisplay(deviceId, displayId);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OH_Input_BindInputDeviceToDisplay_Invalid_displayId
 * @tc.desc: Test binding displayId is invalid
 * @tc.type: FUNC
 * @tc.require: AR000H5VSG
 */
HWTEST_F(SetDisplayBindTest, OH_Input_BindInputDeviceToDisplay_Invalid_displayId, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    int32_t displayId = -1;

    Input_Result ret = OH_Input_BindInputDeviceToDisplay(deviceId, displayId);
    EXPECT_EQ(ret, INPUT_PARAMETER_ERROR);
}
} // namespace MMI
} // namespace OHOS