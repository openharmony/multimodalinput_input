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
#include "mouse_preference_accessor.h"
#include "multimodal_input_preferences_manager.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;

class MousePreferenceAccessorTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
    }
    
    static void TearDownTestCase()
    {
    }
    
    void SetUp() override
    {
    }
    
    void TearDown() override
    {
    }

class IsolatedTestContext : public IInputServiceContext {
    public:
        IsolatedTestContext()
        {
            isolatedPrefMgr_ = std::make_shared<MultiModalInputPreferencesManager>();
            isolatedPrefMgr_->InitPreferences();
        }
        
        std::shared_ptr<IPreferenceManager> GetPreferenceManager() const override
        {
            return isolatedPrefMgr_;
        }
        
        std::shared_ptr<IDelegateInterface> GetDelegateInterface() const override { return nullptr; }
        IUdsServer* GetUDSServer() const override { return nullptr; }
        std::shared_ptr<IInputEventHandler> GetEventNormalizeHandler() const override { return nullptr; }
        std::shared_ptr<IInputEventHandler> GetMonitorHandler() const override { return nullptr; }
        std::shared_ptr<IInputEventHandler> GetDispatchHandler() const override { return nullptr; }
        std::shared_ptr<ITimerManager> GetTimerManager() const override { return nullptr; }
        std::shared_ptr<IInputWindowsManager> GetInputWindowsManager() const override { return nullptr; }
        std::shared_ptr<IInputDeviceManager> GetDeviceManager() const override { return nullptr; }
        std::shared_ptr<IKeyMapManager> GetKeyMapManager() const override { return nullptr; }
        ICursorDrawingComponent& GetCursorDrawingComponent() const override
        {
            static ICursorDrawingComponent* instance = nullptr;
            return *instance;
        }
        
    private:
        std::shared_ptr<MultiModalInputPreferencesManager> isolatedPrefMgr_;
    };
};

/**
 * @tc.name: MousePreferenceAccessorTest_SetMouseScrollRows_001
 * @tc.desc: Test SetMouseScrollRows with normal value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_SetMouseScrollRows_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    int32_t result = MousePreferenceAccessor::SetMouseScrollRows(ctx, 10);
    EXPECT_EQ(RET_OK, result);
}

/**
 * @tc.name: MousePreferenceAccessorTest_GetMouseScrollRows_001
 * @tc.desc: Test GetMouseScrollRows returns correct value after setting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_GetMouseScrollRows_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    MousePreferenceAccessor::SetMouseScrollRows(ctx, 10);
    int32_t rows = MousePreferenceAccessor::GetMouseScrollRows(ctx);
    EXPECT_EQ(10, rows);
}

/**
 * @tc.name: MousePreferenceAccessorTest_SetMouseScrollRows_BoundaryMin_001
 * @tc.desc: Test SetMouseScrollRows with minimum boundary value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_SetMouseScrollRows_BoundaryMin_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    int32_t result = MousePreferenceAccessor::SetMouseScrollRows(ctx, 0);
    EXPECT_EQ(RET_OK, result);
}

/**
 * @tc.name: MousePreferenceAccessorTest_GetMouseScrollRows_BoundaryMin_001
 * @tc.desc: Test GetMouseScrollRows corrects minimum boundary value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_GetMouseScrollRows_BoundaryMin_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    MousePreferenceAccessor::SetMouseScrollRows(ctx, 0);
    int32_t rows = MousePreferenceAccessor::GetMouseScrollRows(ctx);
    EXPECT_EQ(1, rows);
}

/**
 * @tc.name: MousePreferenceAccessorTest_SetMouseScrollRows_BoundaryMax_001
 * @tc.desc: Test SetMouseScrollRows with maximum boundary value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_SetMouseScrollRows_BoundaryMax_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    int32_t result = MousePreferenceAccessor::SetMouseScrollRows(ctx, 200);
    EXPECT_EQ(RET_OK, result);
}

/**
 * @tc.name: MousePreferenceAccessorTest_GetMouseScrollRows_BoundaryMax_001
 * @tc.desc: Test GetMouseScrollRows corrects maximum boundary value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_GetMouseScrollRows_BoundaryMax_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    MousePreferenceAccessor::SetMouseScrollRows(ctx, 200);
    int32_t rows = MousePreferenceAccessor::GetMouseScrollRows(ctx);
    EXPECT_EQ(100, rows);
}

/**
 * @tc.name: MousePreferenceAccessorTest_GetMouseScrollRows_Default_001
 * @tc.desc: Test GetMouseScrollRows returns default value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_GetMouseScrollRows_Default_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    int32_t rows = MousePreferenceAccessor::GetMouseScrollRows(ctx);
    EXPECT_GE(rows, 1);
    EXPECT_LE(rows, 100);
}

/**
 * @tc.name: MousePreferenceAccessorTest_SetMousePrimaryButton_001
 * @tc.desc: Test SetMousePrimaryButton with normal value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_SetMousePrimaryButton_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    int32_t result = MousePreferenceAccessor::SetMousePrimaryButton(ctx, 1);
    EXPECT_EQ(RET_OK, result);
}

/**
 * @tc.name: MousePreferenceAccessorTest_GetMousePrimaryButton_001
 * @tc.desc: Test GetMousePrimaryButton returns correct value after setting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_GetMousePrimaryButton_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    MousePreferenceAccessor::SetMousePrimaryButton(ctx, 1);
    int32_t button = MousePreferenceAccessor::GetMousePrimaryButton(ctx);
    EXPECT_EQ(1, button);
}

/**
 * @tc.name: MousePreferenceAccessorTest_SetPointerSpeed_001
 * @tc.desc: Test SetPointerSpeed with normal value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_SetPointerSpeed_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    int32_t result = MousePreferenceAccessor::SetPointerSpeed(ctx, 15);
    EXPECT_EQ(RET_OK, result);
}

/**
 * @tc.name: MousePreferenceAccessorTest_GetPointerSpeed_001
 * @tc.desc: Test GetPointerSpeed returns correct value after setting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_GetPointerSpeed_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    MousePreferenceAccessor::SetPointerSpeed(ctx, 15);
    int32_t speed = MousePreferenceAccessor::GetPointerSpeed(ctx);
    EXPECT_EQ(15, speed);
}

/**
 * @tc.name: MousePreferenceAccessorTest_SetPointerSpeed_BoundaryMin_001
 * @tc.desc: Test SetPointerSpeed with minimum boundary value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_SetPointerSpeed_BoundaryMin_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    int32_t result = MousePreferenceAccessor::SetPointerSpeed(ctx, -5);
    EXPECT_EQ(RET_OK, result);
}

/**
 * @tc.name: MousePreferenceAccessorTest_GetPointerSpeed_BoundaryMin_001
 * @tc.desc: Test GetPointerSpeed corrects minimum boundary value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_GetPointerSpeed_BoundaryMin_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    MousePreferenceAccessor::SetPointerSpeed(ctx, -5);
    int32_t speed = MousePreferenceAccessor::GetPointerSpeed(ctx);
    EXPECT_EQ(1, speed);
}

/**
 * @tc.name: MousePreferenceAccessorTest_SetPointerSpeed_BoundaryMax_001
 * @tc.desc: Test SetPointerSpeed with maximum boundary value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_SetPointerSpeed_BoundaryMax_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    int32_t result = MousePreferenceAccessor::SetPointerSpeed(ctx, 30);
    EXPECT_EQ(RET_OK, result);
}

/**
 * @tc.name: MousePreferenceAccessorTest_GetPointerSpeed_BoundaryMax_001
 * @tc.desc: Test GetPointerSpeed corrects maximum boundary value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_GetPointerSpeed_BoundaryMax_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    MousePreferenceAccessor::SetPointerSpeed(ctx, 30);
    int32_t speed = MousePreferenceAccessor::GetPointerSpeed(ctx);
    EXPECT_EQ(20, speed);
}

/**
 * @tc.name: MousePreferenceAccessorTest_SetTouchpadPointerSpeed_001
 * @tc.desc: Test SetTouchpadPointerSpeed with normal value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_SetTouchpadPointerSpeed_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    int32_t result = MousePreferenceAccessor::SetTouchpadPointerSpeed(ctx, 8);
    EXPECT_EQ(RET_OK, result);
}

/**
 * @tc.name: MousePreferenceAccessorTest_GetTouchpadPointerSpeed_001
 * @tc.desc: Test GetTouchpadPointerSpeed returns correct value after setting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_GetTouchpadPointerSpeed_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    MousePreferenceAccessor::SetTouchpadPointerSpeed(ctx, 8);
    int32_t speed = 0;
    MousePreferenceAccessor::GetTouchpadPointerSpeed(ctx, speed);
    EXPECT_EQ(8, speed);
}

/**
 * @tc.name: MousePreferenceAccessorTest_SetTouchpadPointerSpeed_Min_001
 * @tc.desc: Test SetTouchpadPointerSpeed with minimum boundary value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_SetTouchpadPointerSpeed_Min_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    int32_t result = MousePreferenceAccessor::SetTouchpadPointerSpeed(ctx, -2);
    EXPECT_EQ(RET_OK, result);
}

/**
 * @tc.name: MousePreferenceAccessorTest_GetTouchpadPointerSpeed_Min_001
 * @tc.desc: Test GetTouchpadPointerSpeed corrects minimum boundary value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_GetTouchpadPointerSpeed_Min_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    MousePreferenceAccessor::SetTouchpadPointerSpeed(ctx, -2);
    int32_t speed = 0;
    MousePreferenceAccessor::GetTouchpadPointerSpeed(ctx, speed);
    EXPECT_EQ(1, speed);
}

/**
 * @tc.name: MousePreferenceAccessorTest_SetTouchpadPointerSpeed_Max_001
 * @tc.desc: Test SetTouchpadPointerSpeed with maximum boundary value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_SetTouchpadPointerSpeed_Max_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    int32_t result = MousePreferenceAccessor::SetTouchpadPointerSpeed(ctx, 20);
    EXPECT_EQ(RET_OK, result);
}

/**
 * @tc.name: MousePreferenceAccessorTest_GetTouchpadPointerSpeed_Max_001
 * @tc.desc: Test GetTouchpadPointerSpeed corrects maximum boundary value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_GetTouchpadPointerSpeed_Max_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    MousePreferenceAccessor::SetTouchpadPointerSpeed(ctx, 20);
    int32_t speed = 0;
    MousePreferenceAccessor::GetTouchpadPointerSpeed(ctx, speed);
    EXPECT_EQ(11, speed);
}

/**
 * @tc.name: MousePreferenceAccessorTest_SetTouchpadScrollSwitch_001
 * @tc.desc: Test SetTouchpadScrollSwitch with true value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_SetTouchpadScrollSwitch_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    int32_t result = MousePreferenceAccessor::SetTouchpadScrollSwitch(ctx, 1234, true);
    EXPECT_EQ(RET_OK, result);
}

/**
 * @tc.name: MousePreferenceAccessorTest_GetTouchpadScrollSwitch_001
 * @tc.desc: Test GetTouchpadScrollSwitch returns correct value after setting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_GetTouchpadScrollSwitch_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    MousePreferenceAccessor::SetTouchpadScrollSwitch(ctx, 1234, true);
    bool switchFlag = false;
    MousePreferenceAccessor::GetTouchpadScrollSwitch(ctx, switchFlag);
    EXPECT_TRUE(switchFlag);
}

/**
 * @tc.name: MousePreferenceAccessorTest_SetTouchpadScrollDirection_001
 * @tc.desc: Test SetTouchpadScrollDirection with false value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_SetTouchpadScrollDirection_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    int32_t result = MousePreferenceAccessor::SetTouchpadScrollDirection(ctx, false);
    EXPECT_EQ(RET_OK, result);
}

/**
 * @tc.name: MousePreferenceAccessorTest_GetTouchpadScrollDirection_001
 * @tc.desc: Test GetTouchpadScrollDirection returns correct value after setting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_GetTouchpadScrollDirection_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    MousePreferenceAccessor::SetTouchpadScrollDirection(ctx, false);
    bool direction = true;
    MousePreferenceAccessor::GetTouchpadScrollDirection(ctx, direction);
    EXPECT_FALSE(direction);
}

/**
 * @tc.name: MousePreferenceAccessorTest_SetTouchpadTapSwitch_001
 * @tc.desc: Test SetTouchpadTapSwitch with true value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_SetTouchpadTapSwitch_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    int32_t result = MousePreferenceAccessor::SetTouchpadTapSwitch(ctx, true);
    EXPECT_EQ(RET_OK, result);
}

/**
 * @tc.name: MousePreferenceAccessorTest_GetTouchpadTapSwitch_001
 * @tc.desc: Test GetTouchpadTapSwitch returns correct value after setting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_GetTouchpadTapSwitch_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    MousePreferenceAccessor::SetTouchpadTapSwitch(ctx, true);
    bool tapSwitch = false;
    MousePreferenceAccessor::GetTouchpadTapSwitch(ctx, tapSwitch);
    EXPECT_TRUE(tapSwitch);
}

/**
 * @tc.name: MousePreferenceAccessorTest_SetTouchpadRightClickType_001
 * @tc.desc: Test SetTouchpadRightClickType with normal value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_SetTouchpadRightClickType_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    int32_t result = MousePreferenceAccessor::SetTouchpadRightClickType(ctx, 3);
    EXPECT_EQ(RET_OK, result);
}

/**
 * @tc.name: MousePreferenceAccessorTest_GetTouchpadRightClickType_001
 * @tc.desc: Test GetTouchpadRightClickType returns value in valid range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_GetTouchpadRightClickType_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    MousePreferenceAccessor::SetTouchpadRightClickType(ctx, 3);
    int32_t type = 0;
    MousePreferenceAccessor::GetTouchpadRightClickType(ctx, type);
    EXPECT_GE(type, 1);
    EXPECT_LE(type, 5);
}

/**
 * @tc.name: MousePreferenceAccessorTest_GetTouchpadSpeed_AfterSet_001
 * @tc.desc: Test GetTouchpadSpeed returns correct value after setting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_GetTouchpadSpeed_AfterSet_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    MousePreferenceAccessor::SetTouchpadPointerSpeed(ctx, 9);
    int32_t speed = MousePreferenceAccessor::GetTouchpadSpeed(ctx);
    EXPECT_EQ(9, speed);
}

/**
 * @tc.name: MousePreferenceAccessorTest_GetTouchpadSpeed_ZeroValue_001
 * @tc.desc: Test GetTouchpadSpeed handles zero value correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_GetTouchpadSpeed_ZeroValue_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    auto prefMgr = ctx.GetPreferenceManager();
    prefMgr->SetIntValue("touchPadPointerSpeed", "mouse_settings.xml", 0);
    int32_t speed = MousePreferenceAccessor::GetTouchpadSpeed(ctx);
    EXPECT_EQ(6, speed);
}

/**
 * @tc.name: MousePreferenceAccessorTest_GetTouchpadScrollRows_AfterSet_001
 * @tc.desc: Test GetTouchpadScrollRows returns correct value after setting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_GetTouchpadScrollRows_AfterSet_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    auto prefMgr = ctx.GetPreferenceManager();
    prefMgr->SetIntValue("touchpadScrollRows", "touchpad_settings.xml", 7);
    int32_t rows = MousePreferenceAccessor::GetTouchpadScrollRows(ctx);
    EXPECT_EQ(7, rows);
}

/**
 * @tc.name: MousePreferenceAccessorTest_CombinationSettings_001
 * @tc.desc: Test multiple settings work correctly together
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_CombinationSettings_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    MousePreferenceAccessor::SetMouseScrollRows(ctx, 20);
    MousePreferenceAccessor::SetPointerSpeed(ctx, 18);
    MousePreferenceAccessor::SetMousePrimaryButton(ctx, 2);
    
    EXPECT_EQ(20, MousePreferenceAccessor::GetMouseScrollRows(ctx));
    EXPECT_EQ(18, MousePreferenceAccessor::GetPointerSpeed(ctx));
    EXPECT_EQ(2, MousePreferenceAccessor::GetMousePrimaryButton(ctx));
}

/**
 * @tc.name: MousePreferenceAccessorTest_MultipleSetSameValue_001
 * @tc.desc: Test setting same value multiple times works correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MousePreferenceAccessorTest, MousePreferenceAccessorTest_MultipleSetSameValue_001, TestSize.Level1)
{
    IsolatedTestContext ctx;
    for (int32_t i = 0; i < 3; i++) {
        MousePreferenceAccessor::SetMouseScrollRows(ctx, 5);
        MousePreferenceAccessor::SetPointerSpeed(ctx, 12);
    }
    
    EXPECT_EQ(5, MousePreferenceAccessor::GetMouseScrollRows(ctx));
    EXPECT_EQ(12, MousePreferenceAccessor::GetPointerSpeed(ctx));
}
} // namespace
} // namespace MMI
} // namespace OHOS