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
#include "pointer_event.h"

#include <gtest/gtest.h>

#include "axis_event.h"
#include "define_multimodal.h"
#include "input_device.h"
#include "input_event.h"
#include "proto.h"
#include "util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerEventExTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
class PointerEventExTest : public testing::Test {
public:
    static void SetUpTestCase(void);
};

void PointerEventExTest::SetUpTestCase(void)
{
}
/**
 * @tc.name: PointerEventExTest_ToString_001
 * @tc.desc: Test the function ToString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventExTest, PointerEventExTest_ToString_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    PointerEvent::PointerItem pointerItem1;
    int32_t disPlayX1 = 100;
    int32_t disPlayY1 = 110;
    pointerItem1.SetFixedDisplayXPos(disPlayX1);
    pointerItem1.SetFixedDisplayYPos(disPlayY1);
    pointerItem1.SetPointerId(0);
    pointerItem1.SetDownTime(0);
    pointerItem1.SetPressed(true);
    pointerItem1.SetPressure(30);
    pointerItem1.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    pointerEvent->AddPointerItem(pointerItem1);
    
    int32_t buttonId = 1;
    pointerEvent->SetButtonPressed(buttonId);
    buttonId = 2;
    pointerEvent->SetButtonPressed(buttonId);
    auto rlt = pointerEvent->ToString();
    EXPECT_NE(rlt.find("displayX"), string::npos);
}

/**
 * @tc.name: PointerEventExTest_DumpPointerAction_005
 * @tc.desc: Verify the function DumpPointerAction
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventExTest, PointerEventExTest_DumpPointerAction_005, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    double axisValue = 0;
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, axisValue);
    std::string str = pointerEvent->DumpPointerAction();
    EXPECT_EQ(str, "axis-begin");

    pointerEvent->ClearAxisValue();
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, axisValue);
    str = pointerEvent->DumpPointerAction();
    EXPECT_EQ(str, "axis-begin");

    pointerEvent->ClearAxisValue();
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, axisValue);
    str = pointerEvent->DumpPointerAction();
    EXPECT_EQ(str, "pinch-begin");

    pointerEvent->ClearAxisValue();
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_ROTATE, axisValue);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->DumpPointerAction());
    str = pointerEvent->DumpPointerAction();
    EXPECT_EQ(str, "axis-begin");
}

/**
 * @tc.name: PointerEventExTest_DumpPointerAction_006
 * @tc.desc: Verify the function DumpPointerAction
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventExTest, PointerEventExTest_DumpPointerAction_006, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    double axisValue = 0;
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, axisValue);
    std::string str = pointerEvent->DumpPointerAction();
    EXPECT_EQ(str, "axis-update");

    pointerEvent->ClearAxisValue();
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, axisValue);
    str = pointerEvent->DumpPointerAction();
    EXPECT_EQ(str, "axis-update");

    pointerEvent->ClearAxisValue();
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, axisValue);
    str = pointerEvent->DumpPointerAction();
    EXPECT_EQ(str, "pinch-update");

    pointerEvent->ClearAxisValue();
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_ROTATE, axisValue);
    str = pointerEvent->DumpPointerAction();
    EXPECT_EQ(str, "axis-update");
}

/**
 * @tc.name: PointerEventExTest_DumpPointerAction_007
 * @tc.desc: Verify the function DumpPointerAction
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventExTest, PointerEventExTest_DumpPointerAction_007, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
    double axisValue = 0;
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, axisValue);
    std::string str = pointerEvent->DumpPointerAction();
    EXPECT_EQ(str, "axis-end");

    pointerEvent->ClearAxisValue();
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, axisValue);
    str = pointerEvent->DumpPointerAction();
    EXPECT_EQ(str, "axis-end");

    pointerEvent->ClearAxisValue();
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, axisValue);
    str = pointerEvent->DumpPointerAction();
    EXPECT_EQ(str, "pinch-end");

    pointerEvent->ClearAxisValue();
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_ROTATE, axisValue);
    str = pointerEvent->DumpPointerAction();
    EXPECT_EQ(str, "axis-end");
}

/**
 * @tc.name: PointerEventExTest_DumpPointerAction_008
 * @tc.desc: Verify the function DumpPointerAction
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventExTest, PointerEventExTest_DumpPointerAction_008, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    int32_t invalidAction = 9999;
    pointerEvent->SetPointerAction(invalidAction);
    std::string str = pointerEvent->DumpPointerAction();
    EXPECT_EQ(str, "unknown");
}

/**
 * @tc.name: AddPointerItemTest1
 * @tc.desc: Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventExTest, AddPointerItemTest1, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item1;
    item1.SetPointerId(0);
    pointerEvent->AddPointerItem(item1);
    EXPECT_EQ(pointerEvent->pointers_.size(), 1);
    PointerEvent::PointerItem item2;
    item2.SetPointerId(1);
    pointerEvent->AddPointerItem(item2);
    EXPECT_EQ(pointerEvent->pointers_.size(), 2);
    ASSERT_TRUE(!pointerEvent->IsValid());
    PointerEvent::PointerItem item3;
    item3.SetPointerId(2);
    pointerEvent->AddPointerItem(item3);
    EXPECT_EQ(pointerEvent->pointers_.size(), 3);
    PointerEvent::PointerItem item4;
    item4.SetPointerId(3);
    pointerEvent->AddPointerItem(item4);
    EXPECT_EQ(pointerEvent->pointers_.size(), 4);
    PointerEvent::PointerItem item5;
    item5.SetPointerId(4);
    pointerEvent->AddPointerItem(item5);
    EXPECT_EQ(pointerEvent->pointers_.size(), 5);
    PointerEvent::PointerItem item6;
    item6.SetPointerId(5);
    pointerEvent->AddPointerItem(item6);
    PointerEvent::PointerItem item7;
    item7.SetPointerId(6);
    pointerEvent->AddPointerItem(item7);
    PointerEvent::PointerItem item8;
    item8.SetPointerId(7);
    pointerEvent->AddPointerItem(item8);
    PointerEvent::PointerItem item9;
    item9.SetPointerId(8);
    pointerEvent->AddPointerItem(item9);
    PointerEvent::PointerItem item10;
    item10.SetPointerId(9);
    pointerEvent->AddPointerItem(item10);
    EXPECT_EQ(pointerEvent->pointers_.size(), 10);
    PointerEvent::PointerItem item11;
    item11.SetPointerId(10);
    pointerEvent->AddPointerItem(item10);
    EXPECT_EQ(pointerEvent->pointers_.size(), 10);
}

/**
 * @tc.name: AddPointerItemTest2
 * @tc.desc: Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventExTest, AddPointerItemTest2, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item1;
    item1.SetPointerId(0);
    pointerEvent->AddPointerItem(item1);
    EXPECT_EQ(pointerEvent->pointers_.size(), 1);
    PointerEvent::PointerItem item2;
    item2.SetPointerId(0);
    pointerEvent->AddPointerItem(item2);
    EXPECT_EQ(pointerEvent->pointers_.size(), 1);
}

/**
 * @tc.name: SetButtonPressed1
 * @tc.desc: Test SetButtonPressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventExTest, SetButtonPressed1, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    
    int32_t buttonId = 1;
    pointerEvent->SetButtonPressed(buttonId);

    buttonId = 2;
    pointerEvent->SetButtonPressed(buttonId);

    buttonId = 3;
    pointerEvent->SetButtonPressed(buttonId);

    buttonId = 4;
    pointerEvent->SetButtonPressed(buttonId);

    buttonId = 5;
    pointerEvent->SetButtonPressed(buttonId);

    buttonId = 6;
    pointerEvent->SetButtonPressed(buttonId);

    buttonId = 7;
    pointerEvent->SetButtonPressed(buttonId);

    buttonId = 8;
    pointerEvent->SetButtonPressed(buttonId);

    buttonId = 9;
    pointerEvent->SetButtonPressed(buttonId);
    EXPECT_EQ(pointerEvent->pressedButtons_.size(), 9);

    pointerEvent->SetButtonPressed(buttonId);
    EXPECT_EQ(pointerEvent->pressedButtons_.size(), 9);

    buttonId = 10;
    pointerEvent->SetButtonPressed(buttonId);
    EXPECT_TRUE(pointerEvent->IsButtonPressed(buttonId));
    
    buttonId = 11;
    pointerEvent->SetButtonPressed(buttonId);
    EXPECT_FALSE(pointerEvent->IsButtonPressed(buttonId));
}
} // namespace MMI
} // namespace OHOS
