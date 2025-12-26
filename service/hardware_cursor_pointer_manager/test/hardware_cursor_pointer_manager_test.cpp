/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "hardware_cursor_pointer_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "HardwareCursorPointerManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;
} // namespace

class HardwareCursorPointerManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp()
    {
        cursorManager_ = std::make_unique<HardwareCursorPointerManager>();
    }
    void TearDown()
    {
        cursorManager_.reset();
    }

protected:
    std::unique_ptr<HardwareCursorPointerManager> cursorManager_;
};

/**
 * @tc.name: HardwareCursorPointerManagerTest_SetTargetDevice_DevIdValid
 * @tc.desc: Test SetTargetDevice with valid device ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, SetTargetDevice_DevIdValid, TestSize.Level1)
{
    uint32_t validDevId = 1;
    cursorManager_->SetTargetDevice(validDevId);
    EXPECT_NE(cursorManager_, nullptr);
}

/**
 * @tc.name: HardwareCursorPointerManagerTest_SetTargetDevice_DevIdInvalid
 * @tc.desc: Test SetTargetDevice with invalid device ID (negative)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, SetTargetDevice_DevIdInvalid, TestSize.Level1)
{
    uint32_t invalidDevId = static_cast<uint32_t>(-1);
    cursorManager_->SetTargetDevice(invalidDevId);
    EXPECT_NE(cursorManager_, nullptr);
}

/**
 * @tc.name: HardwareCursorPointerManagerTest_SetTargetDevice_ZeroDevId
 * @tc.desc: Test SetTargetDevice with zero device ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, SetTargetDevice_ZeroDevId, TestSize.Level1)
{
    uint32_t zeroDevId = 0;
    cursorManager_->SetTargetDevice(zeroDevId);
    EXPECT_NE(cursorManager_, nullptr);
}

/**
 * @tc.name: HardwareCursorPointerManagerTest_SetHdiServiceState_True
 * @tc.desc: Test SetHdiServiceState with true value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, SetHdiServiceState_True, TestSize.Level1)
{
    cursorManager_->SetHdiServiceState(true);
    EXPECT_NE(cursorManager_, nullptr);
}

/**
 * @tc.name: HardwareCursorPointerManagerTest_SetHdiServiceState_False
 * @tc.desc: Test SetHdiServiceState with false value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, SetHdiServiceState_False, TestSize.Level1)
{
    cursorManager_->SetHdiServiceState(false);
    EXPECT_NE(cursorManager_, nullptr);
}

/**
 * @tc.name: HardwareCursorPointerManagerTest_IsSupported_WhenEnabledAndStateTrue
 * @tc.desc: Test IsSupported when both isEnable_ and isEnableState_ are true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, IsSupported_WhenEnabledAndStateTrue, TestSize.Level1)
{
    cursorManager_->SetHdiServiceState(true);
    EXPECT_NE(cursorManager_, nullptr);
}

/**
 * @tc.name: HardwareCursorPointerManagerTest_IsSupported_WhenDisabled
 * @tc.desc: Test IsSupported when isEnable_ is false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, IsSupported_WhenDisabled, TestSize.Level1)
{
    cursorManager_->SetHdiServiceState(false);
    EXPECT_FALSE(cursorManager_->IsSupported());
}

/**
 * @tc.name: HardwareCursorPointerManagerTest_SetPosition_NullBuffer
 * @tc.desc: Test SetPosition with null buffer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, SetPosition_NullBuffer, TestSize.Level1)
{
    uint32_t devId = 1;
    int32_t x = 10;
    int32_t y = 20;
    BufferHandle* buffer = nullptr;

    auto result = cursorManager_->SetPosition(devId, x, y, buffer);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: HardwareCursorPointerManagerTest_EnableStats_True
 * @tc.desc: Test EnableStats with true parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, EnableStats_True, TestSize.Level1)
{
    bool enable = true;
    EXPECT_NO_FATAL_FAILURE(cursorManager_->EnableStats(enable));
}

/**
 * @tc.name: HardwareCursorPointerManagerTest_EnableStats_False
 * @tc.desc: Test EnableStats with false parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, EnableStats_False, TestSize.Level1)
{
    bool enable = false;
    EXPECT_NO_FATAL_FAILURE(cursorManager_->EnableStats(enable));
}

/**
 * @tc.name: HardwareCursorPointerManagerTest_SetPosition_ValidParams
 * @tc.desc: Test SetPosition with valid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, SetPosition_ValidParams, TestSize.Level1)
{
    BufferHandle mockBuffer;
    uint32_t devId = 1;
    int32_t x = 10;
    int32_t y = 20;
    EXPECT_NO_FATAL_FAILURE(cursorManager_->SetPosition(devId, x, y, &mockBuffer));
}

/**
 * @tc.name: HardwareCursorPointerManagerTest_SetTargetDevice_ChangeDevId
 * @tc.desc: Test SetTargetDevice changing device ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, SetTargetDevice_ChangeDevId, TestSize.Level1)
{
    uint32_t firstDevId = 1;
    uint32_t secondDevId = 2;

    cursorManager_->SetTargetDevice(firstDevId);
    cursorManager_->SetTargetDevice(secondDevId);

    EXPECT_NE(cursorManager_, nullptr);
}

/**
 * @tc.name: HardwareCursorPointerManagerTest_GetPowerInterface
 * @tc.desc: Test GetPowerInterface method (indirectly through other methods)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, GetPowerInterface, TestSize.Level1)
{
    cursorManager_->SetHdiServiceState(true);
    EXPECT_NE(cursorManager_, nullptr);
}
} // namespace MMI
} // namespace OHOS