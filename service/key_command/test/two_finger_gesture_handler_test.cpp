/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "input_windows_manager.h"
#include "mmi_log.h"
#include "two_finger_gesture_handler.h"
#include "test_key_command_service.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TwoFingerGestureHandlerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t TWO_FINGERS_TIME_LIMIT = 150000;
} // namespace
class TwoFingerGestureHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    void SetUp() override
    {
        shortcutKeys_ = std::make_unique<std::map<std::string, ShortcutKey>>();
        sequences_ = std::make_unique<std::vector<Sequence>>();
        repeatKeys_ = std::make_unique<std::vector<RepeatKey>>();
        excludeKeys_ = std::make_unique<std::vector<ExcludeKey>>();

        context_.shortcutKeys_ = shortcutKeys_.get();
        context_.sequences_ = sequences_.get();
        context_.repeatKeys_ = repeatKeys_.get();
        context_.excludeKeys_ = excludeKeys_.get();

        service_ = std::make_unique<TestKeyCommandService>();
        handler_ = std::make_unique<TwoFingerGestureHandler>(context_, *service_);
    }

private:
    KeyCommandContext context_;
    std::unique_ptr<std::map<std::string, ShortcutKey>> shortcutKeys_;
    std::unique_ptr<std::vector<Sequence>> sequences_;
    std::unique_ptr<std::vector<RepeatKey>> repeatKeys_;
    std::unique_ptr<std::vector<ExcludeKey>> excludeKeys_;
    std::unique_ptr<TestKeyCommandService> service_;
    std::unique_ptr<TwoFingerGestureHandler> handler_;
};

/**
 * @tc.name: TwoFingerGestureHandlerTest_StartTwoFingerGesture_003
 * @tc.desc: Test the funcation StartTwoFingerGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_StartTwoFingerGesture_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.touches[0].downTime = 150000;
    context_.twoFingerGesture_.touches[0].id = 10;
    context_.twoFingerGesture_.touches[0].x = 100;
    context_.twoFingerGesture_.touches[0].y = 200;
    context_.twoFingerGesture_.touches[1].downTime = 100000;
    context_.twoFingerGesture_.touches[0].id = 5;
    context_.twoFingerGesture_.touches[0].x = 50;
    context_.twoFingerGesture_.touches[0].y = 100;
    ASSERT_NO_FATAL_FAILURE(handler_->StartTwoFingerGesture());
    context_.twoFingerGesture_.touches[0].downTime = 350000;
    context_.twoFingerGesture_.touches[1].downTime = 100000;
    ASSERT_NO_FATAL_FAILURE(handler_->StartTwoFingerGesture());
    context_.twoFingerGesture_.active = false;
    ASSERT_NO_FATAL_FAILURE(handler_->StartTwoFingerGesture());
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_006
 * @tc.desc: Test the funcation CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.touches[0].id = 1;
    context_.twoFingerGesture_.touches[0].x = 30;
    context_.twoFingerGesture_.touches[0].y = 20;
    context_.twoFingerGesture_.touches[0].downTime = 150000;
    context_.twoFingerGesture_.touches[1].id = 2;
    context_.twoFingerGesture_.touches[1].x = 20;
    context_.twoFingerGesture_.touches[1].y = 10;
    context_.twoFingerGesture_.touches[1].downTime = 100000;
    InputWindowsManager inputWindowsManager;
    OLD::DisplayInfo displayInfo;
    displayInfo.dpi = 320;
    displayInfo.width = 150;
    displayInfo.height = 300;
    displayInfo.uniq = "default0";
    auto it = inputWindowsManager.displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager.displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    bool ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    context_.twoFingerGesture_.touches[0].x = 30;
    context_.twoFingerGesture_.touches[0].y = 200;
    context_.twoFingerGesture_.touches[1].x = 60;
    context_.twoFingerGesture_.touches[1].y = 170;
    ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    context_.twoFingerGesture_.touches[0].x = 120;
    ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    context_.twoFingerGesture_.touches[0].x = 90;
    context_.twoFingerGesture_.touches[0].y = 120;
    ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    context_.twoFingerGesture_.touches[0].y = 250;
    ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_007
 * @tc.desc: Test the funcation CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.touches[0].x = 90;
    context_.twoFingerGesture_.touches[0].y = 200;
    context_.twoFingerGesture_.touches[0].downTime = 150000;
    context_.twoFingerGesture_.touches[1].x = 30;
    context_.twoFingerGesture_.touches[1].y = 170;
    context_.twoFingerGesture_.touches[1].downTime = 100000;
    InputWindowsManager inputWindowsManager;
    OLD::DisplayInfo displayInfo;
    displayInfo.dpi = 320;
    displayInfo.width = 150;
    displayInfo.height = 300;
    displayInfo.uniq = "default0";
    auto it = inputWindowsManager.displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager.displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    context_.twoFingerGesture_.touches[0].y = 200;
    context_.twoFingerGesture_.touches[1].x = 30;
    bool ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    context_.twoFingerGesture_.touches[1].x = 130;
    ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    context_.twoFingerGesture_.touches[1].x = 60;
    context_.twoFingerGesture_.touches[1].y = 100;
    ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    context_.twoFingerGesture_.touches[1].y = 250;
    ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    ASSERT_NO_FATAL_FAILURE(handler_->StartTwoFingerGesture());
    context_.twoFingerGesture_.touches[1].y = 170;
    ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    ASSERT_NO_FATAL_FAILURE(handler_->StartTwoFingerGesture());
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_HandlePointerActionMoveEvent
 * @tc.desc: Test HandlePointerActionMoveEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_HandlePointerActionMoveEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.timerId = -1;
    ASSERT_NO_FATAL_FAILURE(handler_->HandlePointerActionMoveEvent(touchEvent));

    touchEvent->SetPointerId(2);
    context_.twoFingerGesture_.timerId = 1;
    context_.twoFingerGesture_.touches->id = 1;
    context_.twoFingerGesture_.touches->x = 25;
    context_.twoFingerGesture_.touches->y = 25;
    ASSERT_NO_FATAL_FAILURE(handler_->HandlePointerActionMoveEvent(touchEvent));

    touchEvent->SetPointerId(1);
    PointerEvent::PointerItem item;
    item.SetDisplayX(5);
    item.SetDisplayY(5);
    touchEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(handler_->HandlePointerActionMoveEvent(touchEvent));
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_HandleFingerGestureDownEvent
 * @tc.desc: Test HandleFingerGestureDownEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_HandleFingerGestureDownEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerEvent::PointerItem item;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    context_.twoFingerGesture_.active = true;
    item.SetPointerId(1);
    item.SetDisplayX(10);
    item.SetDisplayY(10);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(1);
    ASSERT_NO_FATAL_FAILURE(handler_->HandleFingerGestureDownEvent(touchEvent));

    item.SetPointerId(2);
    item.SetDisplayX(15);
    item.SetDisplayY(15);
    touchEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(handler_->HandleFingerGestureDownEvent(touchEvent));

    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.timerId = 150;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleFingerGestureUpEvent(touchEvent));
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_HandleFingerGestureDownEvent_001
 * @tc.desc: Test HandleFingerGestureDownEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_HandleFingerGestureDownEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerEvent::PointerItem item;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    context_.twoFingerGesture_.active = true;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleFingerGestureDownEvent(touchEvent));

    item.SetPointerId(1);
    touchEvent->AddPointerItem(item);
    item.SetPointerId(2);
    touchEvent->AddPointerItem(item);
    item.SetPointerId(3);
    touchEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(handler_->HandleFingerGestureDownEvent(touchEvent));
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_01
 * @tc.desc: Test CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isActive = context_.twoFingerGesture_.active;
    EXPECT_FALSE(isActive);
    bool ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_02
 * @tc.desc: Test CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pressTimeInterval = fabs(200000 - 40000);
    EXPECT_TRUE(pressTimeInterval > TWO_FINGERS_TIME_LIMIT);
    bool ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_03
 * @tc.desc: Test CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pressTimeInterval = fabs(200000 - 60000);
    EXPECT_FALSE(pressTimeInterval > TWO_FINGERS_TIME_LIMIT);
    bool ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_001
 * @tc.desc: Test the funcation CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.twoFingerGesture_.active = false;
    bool ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.touches[0].id = 1;
    context_.twoFingerGesture_.touches[0].x = 100;
    context_.twoFingerGesture_.touches[0].y = 200;
    context_.twoFingerGesture_.touches[0].downTime = 250000;
    context_.twoFingerGesture_.touches[1].id = 2;
    context_.twoFingerGesture_.touches[1].x = 300;
    context_.twoFingerGesture_.touches[1].y = 400;
    context_.twoFingerGesture_.touches[1].downTime = 50000;
    ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_002
 * @tc.desc: Test the funcation CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.touches[0].id = 1;
    context_.twoFingerGesture_.touches[0].x = 100;
    context_.twoFingerGesture_.touches[0].y = 200;
    context_.twoFingerGesture_.touches[0].downTime = 150000;
    context_.twoFingerGesture_.touches[1].id = 2;
    context_.twoFingerGesture_.touches[1].x = 300;
    context_.twoFingerGesture_.touches[1].y = 400;
    context_.twoFingerGesture_.touches[1].downTime = 50000;
    bool ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_003
 * @tc.desc: Test the funcation CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.touches[0].id = 1;
    context_.twoFingerGesture_.touches[0].x = -100;
    context_.twoFingerGesture_.touches[0].y = -200;
    context_.twoFingerGesture_.touches[0].downTime = 100000;
    context_.twoFingerGesture_.touches[1].id = 2;
    context_.twoFingerGesture_.touches[1].x = -300;
    context_.twoFingerGesture_.touches[1].y = -400;
    context_.twoFingerGesture_.touches[1].downTime = 50000;
    InputWindowsManager inputWindowsManager;
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.x = 2;
    displayInfo.y = 3;
    displayInfo.width = 4;
    displayInfo.height = 5;
    displayInfo.dpi = -1;
    auto it = inputWindowsManager.displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager.displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    bool ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_004
 * @tc.desc: Test the funcation CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.touches[0].id = 1;
    context_.twoFingerGesture_.touches[0].x = 100;
    context_.twoFingerGesture_.touches[0].y = 200;
    context_.twoFingerGesture_.touches[0].downTime = 100000;
    context_.twoFingerGesture_.touches[1].id = 2;
    context_.twoFingerGesture_.touches[1].x = 300;
    context_.twoFingerGesture_.touches[1].y = 400;
    context_.twoFingerGesture_.touches[1].downTime = 50000;
    InputWindowsManager inputWindowsManager;
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.x = 2;
    displayInfo.y = 3;
    displayInfo.width = 40;
    displayInfo.height = 50;
    displayInfo.dpi = -1;
    auto it = inputWindowsManager.displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager.displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    bool ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_005
 * @tc.desc: Test the funcation CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.touches[0].id = 1;
    context_.twoFingerGesture_.touches[0].x = 10;
    context_.twoFingerGesture_.touches[0].y = 20;
    context_.twoFingerGesture_.touches[0].downTime = 100000;
    context_.twoFingerGesture_.touches[1].id = 2;
    context_.twoFingerGesture_.touches[1].x = 30;
    context_.twoFingerGesture_.touches[1].y = 20;
    context_.twoFingerGesture_.touches[1].downTime = 50000;
    InputWindowsManager inputWindowsManager;
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.x = 2;
    displayInfo.y = 3;
    displayInfo.width = 40;
    displayInfo.height = 50;
    displayInfo.dpi = -1;
    auto it = inputWindowsManager.displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager.displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    bool ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_StartTwoFingerGesture_002
 * @tc.desc: Test the funcation StartTwoFingerGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_StartTwoFingerGesture_002, TestSize.Level1)
{
    context_.twoFingerGesture_.active = false;
    ASSERT_NO_FATAL_FAILURE(handler_->StartTwoFingerGesture());
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.touches[0].id = 5;
    context_.twoFingerGesture_.touches[0].x = 50;
    context_.twoFingerGesture_.touches[0].y = 60;
    context_.twoFingerGesture_.touches[0].downTime = 13000;
    context_.twoFingerGesture_.touches[1].id = 9;
    context_.twoFingerGesture_.touches[1].x = 100;
    context_.twoFingerGesture_.touches[1].y = 400;
    context_.twoFingerGesture_.touches[1].downTime = 96000;
    ASSERT_NO_FATAL_FAILURE(handler_->StartTwoFingerGesture());
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_009
 * @tc.desc: Test CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.touches[0].downTime = 0;
    context_.twoFingerGesture_.touches[1].downTime = 1;

    OLD::DisplayInfo displayInfo;
    displayInfo.dpi = 320;
    displayInfo.width = 1260;
    displayInfo.height = 2720;
    displayInfo.uniq = "default0";
    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    IInputWindowsManager::instance_ = inputWindowsManager;
    context_.twoFingerGesture_.touches[0].x = 600;
    context_.twoFingerGesture_.touches[0].y = 600;

    context_.twoFingerGesture_.touches[1].x = 800;
    context_.twoFingerGesture_.touches[1].y = 600;
    ASSERT_NO_FATAL_FAILURE(handler_->CheckTwoFingerGestureAction());

    context_.twoFingerGesture_.touches[1].x = 10;
    context_.twoFingerGesture_.touches[1].y = 600;
    ASSERT_NO_FATAL_FAILURE(handler_->CheckTwoFingerGestureAction());

    context_.twoFingerGesture_.touches[1].x = 1250;
    context_.twoFingerGesture_.touches[1].y = 600;
    ASSERT_NO_FATAL_FAILURE(handler_->CheckTwoFingerGestureAction());

    context_.twoFingerGesture_.touches[1].x = 600;
    context_.twoFingerGesture_.touches[1].y = 10;
    ASSERT_NO_FATAL_FAILURE(handler_->CheckTwoFingerGestureAction());

    context_.twoFingerGesture_.touches[1].x = 600;
    context_.twoFingerGesture_.touches[1].y = 2710;
    ASSERT_NO_FATAL_FAILURE(handler_->CheckTwoFingerGestureAction());
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_ConvertVPToPX_005
 * @tc.desc: Verify if (vp <= 0)
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_ConvertVPToPX_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t vp = -1;
    int32_t ret = handler_->ConvertVPToPX(vp);
    ASSERT_EQ(ret, 0);
    ret = handler_->ConvertVPToPX(vp);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_ConvertVPToPX_006
 * @tc.desc: Verify if (dpi <= 0)
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_ConvertVPToPX_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t vp = 5;
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.x = 2;
    displayInfo.y = 3;
    displayInfo.width = 4;
    displayInfo.height = 5;
    displayInfo.dpi = -1;
    displayInfo.uniq = "default0";
    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    IInputWindowsManager::instance_ = inputWindowsManager;
    int32_t ret = handler_->ConvertVPToPX(vp);
    ASSERT_EQ(ret, 0);
}


/**
 * @tc.name: TwoFingerGestureHandlerTest_ConvertVPToPX_001
 * @tc.desc: Test the funcation ConvertVPToPX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_ConvertVPToPX_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t vp = -1;
    ASSERT_NO_FATAL_FAILURE(handler_->ConvertVPToPX(vp));
    vp = 1;
    ASSERT_NO_FATAL_FAILURE(handler_->ConvertVPToPX(vp));
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_ConvertVPToPX_002
 * @tc.desc: Test the funcation ConvertVPToPX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_ConvertVPToPX_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t vp = -5;
    int32_t ret = handler_->ConvertVPToPX(vp);
    ASSERT_EQ(ret, 0);
    vp = 5;
    InputWindowsManager inputWindowsManager;
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.x = 2;
    displayInfo.y = 3;
    displayInfo.width = 4;
    displayInfo.height = 5;
    displayInfo.dpi = -1;
    auto it = inputWindowsManager.displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager.displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    ret = handler_->ConvertVPToPX(vp);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_ConvertVPToPX_003
 * @tc.desc: Test the funcation ConvertVPToPX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_ConvertVPToPX_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t vp = 5;
    InputWindowsManager inputWindowsManager;
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.x = 2;
    displayInfo.y = 3;
    displayInfo.width = 4;
    displayInfo.height = 5;
    displayInfo.dpi = 160;
    auto it = inputWindowsManager.displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager.displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    int32_t ret = handler_->ConvertVPToPX(vp);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_StartTwoFingerGesture_001
 * @tc.desc: Start two finger gesture verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_StartTwoFingerGesture_001, TestSize.Level1)
{
    context_.twoFingerGesture_.abilityStartDelay = 1000;
    handler_->StartTwoFingerGesture();
    ASSERT_NE(-1, context_.twoFingerGesture_.timerId);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_StopTwoFingerGesture_001
 * @tc.desc: Test StopTwoFingerGesture when timerId is valid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_StopTwoFingerGesture_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.twoFingerGesture_.timerId = 100;
    ASSERT_NO_FATAL_FAILURE(handler_->StopTwoFingerGesture());
    ASSERT_EQ(-1, context_.twoFingerGesture_.timerId);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_StopTwoFingerGesture_002
 * @tc.desc: Test StopTwoFingerGesture when timerId is -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_StopTwoFingerGesture_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.twoFingerGesture_.timerId = -1;
    ASSERT_NO_FATAL_FAILURE(handler_->StopTwoFingerGesture());
    ASSERT_EQ(-1, context_.twoFingerGesture_.timerId);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGesture_001
 * @tc.desc: Test CheckTwoFingerGesture when touchEvent is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGesture_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.twoFingerGesture_.touchEvent = nullptr;
    int32_t ret = handler_->CheckTwoFingerGesture(100);
    ASSERT_EQ(RET_ERR, ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGesture_002
 * @tc.desc: Test CheckTwoFingerGesture when timeOut > SCREEN_TIME_OUT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGesture_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    context_.twoFingerGesture_.touchEvent = touchEvent;
    context_.twoFingerGesture_.startTime = 0;
    int32_t ret = handler_->CheckTwoFingerGesture(100);
    ASSERT_EQ(RET_ERR, ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGesture_003
 * @tc.desc: Test CheckTwoFingerGesture when windowId < 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGesture_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    context_.twoFingerGesture_.touchEvent = touchEvent;
    context_.twoFingerGesture_.startTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    context_.twoFingerGesture_.windowId = -1;
    int32_t ret = handler_->CheckTwoFingerGesture(100);
    ASSERT_EQ(RET_ERR, ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGesture_004
 * @tc.desc: Test CheckTwoFingerGesture when windowId not match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGesture_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    context_.twoFingerGesture_.touchEvent = touchEvent;
    context_.twoFingerGesture_.startTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    context_.twoFingerGesture_.windowId = 100;
    touchEvent->SetTargetWindowId(200);
    int32_t ret = handler_->CheckTwoFingerGesture(100);
    ASSERT_EQ(RET_ERR, ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGesture_005
 * @tc.desc: Test CheckTwoFingerGesture when windowPid not match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGesture_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    context_.twoFingerGesture_.touchEvent = touchEvent;
    context_.twoFingerGesture_.startTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    context_.twoFingerGesture_.windowId = 100;
    context_.twoFingerGesture_.windowPid = 200;
    touchEvent->SetTargetWindowId(100);
    int32_t ret = handler_->CheckTwoFingerGesture(100);
    ASSERT_EQ(RET_ERR, ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGesture_006
 * @tc.desc: Test CheckTwoFingerGesture when longPressFlag is false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGesture_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    context_.twoFingerGesture_.touchEvent = touchEvent;
    context_.twoFingerGesture_.startTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    context_.twoFingerGesture_.windowId = 100;
    context_.twoFingerGesture_.windowPid = 100;
    context_.twoFingerGesture_.longPressFlag = false;
    touchEvent->SetTargetWindowId(100);
    int32_t ret = handler_->CheckTwoFingerGesture(100);
    ASSERT_EQ(RET_ERR, ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGesture_007
 * @tc.desc: Test CheckTwoFingerGesture when all conditions match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGesture_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    context_.twoFingerGesture_.touchEvent = touchEvent;
    context_.twoFingerGesture_.startTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    context_.twoFingerGesture_.windowId = 100;
    context_.twoFingerGesture_.windowPid = 100;
    context_.twoFingerGesture_.longPressFlag = true;
    touchEvent->SetTargetWindowId(100);
    int32_t ret = handler_->CheckTwoFingerGesture(100);
    ASSERT_EQ(RET_OK, ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_LaunchAiScreenAbility_001
 * @tc.desc: Test LaunchAiScreenAbility when CheckTwoFingerGesture fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_LaunchAiScreenAbility_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.twoFingerGesture_.touchEvent = nullptr;
    int32_t ret = handler_->LaunchAiScreenAbility(100);
    ASSERT_EQ(RET_ERR, ret);
    ASSERT_EQ(0, context_.twoFingerGesture_.startTime);
    ASSERT_FALSE(context_.twoFingerGesture_.longPressFlag);
    ASSERT_EQ(-1, context_.twoFingerGesture_.windowId);
    ASSERT_EQ(-1, context_.twoFingerGesture_.windowPid);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_LaunchAiScreenAbility_002
 * @tc.desc: Test LaunchAiScreenAbility when CheckTwoFingerGesture success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_LaunchAiScreenAbility_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    context_.twoFingerGesture_.touchEvent = touchEvent;
    context_.twoFingerGesture_.startTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    context_.twoFingerGesture_.windowId = 100;
    context_.twoFingerGesture_.windowPid = 100;
    context_.twoFingerGesture_.longPressFlag = true;
    touchEvent->SetTargetWindowId(100);
    int32_t ret = handler_->LaunchAiScreenAbility(100);
    ASSERT_EQ(RET_OK, ret);
    ASSERT_EQ(0, context_.twoFingerGesture_.startTime);
    ASSERT_FALSE(context_.twoFingerGesture_.longPressFlag);
    ASSERT_EQ(-1, context_.twoFingerGesture_.windowId);
    ASSERT_EQ(-1, context_.twoFingerGesture_.windowPid);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_LaunchTwoFingerAbility_001
 * @tc.desc: Test LaunchTwoFingerAbility function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_LaunchTwoFingerAbility_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TwoFingerGesture twoFinger;
    twoFinger.ability.bundleName = "com.test.ability";
    twoFinger.abilityStartDelay = 0;
    ASSERT_NO_FATAL_FAILURE(handler_->LaunchTwoFingerAbility(twoFinger));
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_HandleFingerGestureDownEvent_002
 * @tc.desc: Test HandleFingerGestureDownEvent when active is false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_HandleFingerGestureDownEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    context_.twoFingerGesture_.active = false;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleFingerGestureDownEvent(touchEvent));
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_HandleFingerGestureDownEvent_003
 * @tc.desc: Test HandleFingerGestureDownEvent when num > MAX_TOUCH_NUM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_HandleFingerGestureDownEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    context_.twoFingerGesture_.active = true;
    PointerEvent::PointerItem item1, item2, item3;
    item1.SetPointerId(1);
    item1.SetDisplayX(10);
    item1.SetDisplayY(10);
    item2.SetPointerId(2);
    item2.SetDisplayX(20);
    item2.SetDisplayY(20);
    item3.SetPointerId(3);
    item3.SetDisplayX(30);
    item3.SetDisplayY(30);
    touchEvent->AddPointerItem(item1);
    touchEvent->AddPointerItem(item2);
    touchEvent->AddPointerItem(item3);
    touchEvent->SetPointerId(1);
    ASSERT_NO_FATAL_FAILURE(handler_->HandleFingerGestureDownEvent(touchEvent));
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_HandleFingerGestureUpEvent_001
 * @tc.desc: Test HandleFingerGestureUpEvent when active is false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_HandleFingerGestureUpEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    context_.twoFingerGesture_.active = false;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleFingerGestureUpEvent(touchEvent));
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_HandleFingerGestureUpEvent_002
 * @tc.desc: Test HandleFingerGestureUpEvent when active is true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_HandleFingerGestureUpEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.timerId = 100;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleFingerGestureUpEvent(touchEvent));
    ASSERT_EQ(-1, context_.twoFingerGesture_.timerId);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_HandlePointerActionMoveEvent_001
 * @tc.desc: Test HandlePointerActionMoveEvent when touchEvent is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_HandlePointerActionMoveEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> touchEvent = nullptr;
    ASSERT_NO_FATAL_FAILURE(handler_->HandlePointerActionMoveEvent(touchEvent));
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_HandlePointerActionMoveEvent_002
 * @tc.desc: Test HandlePointerActionMoveEvent when active is false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_HandlePointerActionMoveEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    context_.twoFingerGesture_.active = false;
    ASSERT_NO_FATAL_FAILURE(handler_->HandlePointerActionMoveEvent(touchEvent));
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_HandlePointerActionMoveEvent_003
 * @tc.desc: Test HandlePointerActionMoveEvent when timerId is -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_HandlePointerActionMoveEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.timerId = -1;
    ASSERT_NO_FATAL_FAILURE(handler_->HandlePointerActionMoveEvent(touchEvent));
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_HandlePointerActionMoveEvent_004
 * @tc.desc: Test HandlePointerActionMoveEvent when pointer id not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_HandlePointerActionMoveEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.timerId = 100;
    touchEvent->SetPointerId(999);
    ASSERT_NO_FATAL_FAILURE(handler_->HandlePointerActionMoveEvent(touchEvent));
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_HandlePointerActionMoveEvent_005
 * @tc.desc: Test HandlePointerActionMoveEvent when moveDistance > threshold
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_HandlePointerActionMoveEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.timerId = 100;
    context_.twoFingerGesture_.touches[0].id = 1;
    context_.twoFingerGesture_.touches[0].x = 0;
    context_.twoFingerGesture_.touches[0].y = 0;
    touchEvent->SetPointerId(1);
    PointerEvent::PointerItem item;
    item.SetDisplayX(1000);
    item.SetDisplayY(1000);
    touchEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(handler_->HandlePointerActionMoveEvent(touchEvent));
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_ConvertVPToPX_004
 * @tc.desc: Test ConvertVPToPX when vp > 0 and dpi > 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_ConvertVPToPX_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t vp = 10;
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.x = 2;
    displayInfo.y = 3;
    displayInfo.width = 4;
    displayInfo.height = 5;
    displayInfo.dpi = 320;
    displayInfo.uniq = "default0";
    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    IInputWindowsManager::instance_ = inputWindowsManager;
    int32_t ret = handler_->ConvertVPToPX(vp);
    ASSERT_GT(ret, 0);
    IInputWindowsManager::instance_ = originalInstance;
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_008
 * @tc.desc: Test CheckTwoFingerGestureAction when distance < TWO_FINGERS_DISTANCE_LIMIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.touches[0].id = 1;
    context_.twoFingerGesture_.touches[0].x = 100;
    context_.twoFingerGesture_.touches[0].y = 100;
    context_.twoFingerGesture_.touches[0].downTime = 100000;
    context_.twoFingerGesture_.touches[1].id = 2;
    context_.twoFingerGesture_.touches[1].x = 101;
    context_.twoFingerGesture_.touches[1].y = 101;
    context_.twoFingerGesture_.touches[1].downTime = 100000;
    bool ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_010
 * @tc.desc: Test CheckTwoFingerGestureAction when finger out of region left
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.touches[0].id = 1;
    context_.twoFingerGesture_.touches[0].x = 0;
    context_.twoFingerGesture_.touches[0].y = 100;
    context_.twoFingerGesture_.touches[0].downTime = 100000;
    context_.twoFingerGesture_.touches[1].id = 2;
    context_.twoFingerGesture_.touches[1].x = 200;
    context_.twoFingerGesture_.touches[1].y = 100;
    context_.twoFingerGesture_.touches[1].downTime = 100000;
    bool ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_011
 * @tc.desc: Test CheckTwoFingerGestureAction when finger out of region right
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.touches[0].id = 1;
    context_.twoFingerGesture_.touches[0].x = 10000;
    context_.twoFingerGesture_.touches[0].y = 100;
    context_.twoFingerGesture_.touches[0].downTime = 100000;
    context_.twoFingerGesture_.touches[1].id = 2;
    context_.twoFingerGesture_.touches[1].x = 200;
    context_.twoFingerGesture_.touches[1].y = 100;
    context_.twoFingerGesture_.touches[1].downTime = 100000;
    bool ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_012
 * @tc.desc: Test CheckTwoFingerGestureAction when finger out of region top
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.touches[0].id = 1;
    context_.twoFingerGesture_.touches[0].x = 100;
    context_.twoFingerGesture_.touches[0].y = 0;
    context_.twoFingerGesture_.touches[0].downTime = 100000;
    context_.twoFingerGesture_.touches[1].id = 2;
    context_.twoFingerGesture_.touches[1].x = 200;
    context_.twoFingerGesture_.touches[1].y = 100;
    context_.twoFingerGesture_.touches[1].downTime = 100000;
    bool ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_013
 * @tc.desc: Test CheckTwoFingerGestureAction when finger out of region bottom
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TwoFingerGestureHandlerTest, TwoFingerGestureHandlerTest_CheckTwoFingerGestureAction_013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.twoFingerGesture_.active = true;
    context_.twoFingerGesture_.touches[0].id = 1;
    context_.twoFingerGesture_.touches[0].x = 100;
    context_.twoFingerGesture_.touches[0].y = 10000;
    context_.twoFingerGesture_.touches[0].downTime = 100000;
    context_.twoFingerGesture_.touches[1].id = 2;
    context_.twoFingerGesture_.touches[1].x = 200;
    context_.twoFingerGesture_.touches[1].y = 100;
    context_.twoFingerGesture_.touches[1].downTime = 100000;
    bool ret = handler_->CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}
} // namespace MMI
} // namespace OHOS