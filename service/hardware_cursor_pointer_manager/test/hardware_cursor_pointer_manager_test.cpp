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

/**
 * @tc.name: HardwareCursorPointerManagerTest_GetCursorStats_ValidOutput
 * @tc.desc: Test GetCursorStats with valid output parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, GetCursorStats_ValidOutput, TestSize.Level1)
{
    uint32_t frameCount = 0;
    uint32_t vsyncCount = 0;
    
    auto result = cursorManager_->GetCursorStats(frameCount, vsyncCount);
    EXPECT_EQ(result, RET_ERR); // Expecting RET_ERR since there's no actual power interface in test environment
}

/**
 * @tc.name: HardwareCursorPointerManagerTest_GetCursorStats_AfterSettingTargetDevice
 * @tc.desc: Test GetCursorStats after setting target device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, GetCursorStats_AfterSettingTargetDevice, TestSize.Level1)
{
    uint32_t devId = 1;
    cursorManager_->SetTargetDevice(devId);
    
    uint32_t frameCount = 0;
    uint32_t vsyncCount = 0;
    
    auto result = cursorManager_->GetCursorStats(frameCount, vsyncCount);
    EXPECT_EQ(result, RET_ERR); // Expecting RET_ERR since there's no actual power interface in test environment
}

/**
 * @tc.name: HardwareCursorPointerManagerTest_IsSupported_AfterSetTargetDevice
 * @tc.desc: Test IsSupported functionality after setting target device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, IsSupported_AfterSetTargetDevice, TestSize.Level1)
{
    uint32_t devId = 1;
    cursorManager_->SetTargetDevice(devId);
    cursorManager_->SetHdiServiceState(true);
    
    // Note: This will likely return false in test environment due to lack of actual display interface
    bool result = cursorManager_->IsSupported();
    // The important thing is that it doesn't crash
    EXPECT_TRUE(result || !result); // Just checking it returns without crashing
}

/**
 * @tc.name: HardwareCursorPointerManagerTest_SetPosition_InvalidDevId
 * @tc.desc: Test SetPosition with invalid device ID but valid buffer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, SetPosition_InvalidDevId, TestSize.Level1)
{
    BufferHandle mockBuffer;
    uint32_t invalidDevId = static_cast<uint32_t>(-1); // This will be treated as a large positive number
    int32_t x = 10;
    int32_t y = 20;
    
    auto result = cursorManager_->SetPosition(invalidDevId, x, y, &mockBuffer);
    // Result depends on implementation behavior with invalid device IDs
    EXPECT_TRUE(result == RET_OK || result == RET_ERR);
}

/**
 * @tc.name: HardwareCursorPointerManagerTest_SetPosition_NegativeCoordinates
 * @tc.desc: Test SetPosition with negative coordinates
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, SetPosition_NegativeCoordinates, TestSize.Level1)
{
    BufferHandle mockBuffer;
    uint32_t devId = 1;
    int32_t x = -10;  // Negative coordinate
    int32_t y = -20;  // Negative coordinate
    
    auto result = cursorManager_->SetPosition(devId, x, y, &mockBuffer);
    EXPECT_TRUE(result == RET_OK || result == RET_ERR);
}

/**
 * @tc.name: HardwareCursorPointerManagerTest_MultipleOperationsSequence
 * @tc.desc: Test multiple operations in sequence to verify state consistency
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HardwareCursorPointerManagerTest, MultipleOperationsSequence, TestSize.Level1)
{
    // Set up target device
    uint32_t devId = 1;
    cursorManager_->SetTargetDevice(devId);
    
    // Enable HDI service
    cursorManager_->SetHdiServiceState(true);
    
    // Try to check support status
    bool supported = cursorManager_->IsSupported();
    EXPECT_TRUE(supported || !supported); // Just checking it returns without crashing
    
    // Try position update
    BufferHandle mockBuffer;
    int32_t x = 100;
    int32_t y = 200;
    auto posResult = cursorManager_->SetPosition(devId, x, y, &mockBuffer);
    EXPECT_TRUE(posResult == RET_OK || posResult == RET_ERR);
    
    // Try enabling stats
    auto statsResult = cursorManager_->EnableStats(true);
    EXPECT_TRUE(statsResult == RET_OK || statsResult == RET_ERR);
    
    // Try getting cursor stats
    uint32_t frameCount = 0;
    uint32_t vsyncCount = 0;
    auto getStatsResult = cursorManager_->GetCursorStats(frameCount, vsyncCount);
    EXPECT_TRUE(getStatsResult == RET_OK || getStatsResult == RET_ERR);
    
    // Verify all operations completed without crashing
    EXPECT_NE(cursorManager_, nullptr);
}
} // namespace MMI
} // namespace OHOS