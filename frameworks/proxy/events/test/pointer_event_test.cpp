/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "axis_event.h"
#include "define_multimodal.h"
#include "event_util_test.h"
#include "input_device.h"
#include "input_event.h"
#include "proto.h"
#include "util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerEventTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
class PointerEventTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static std::shared_ptr<PointerEvent> CreatePointEvent();
};

void PointerEventTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestUtil->Init());
}

#ifdef OHOS_BUILD_ENABLE_POINTER
std::shared_ptr<PointerEvent> PointerEventTest::CreatePointEvent()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    int64_t downTime = GetMillisTime();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(downTime);
    item.SetPressed(true);

    item.SetDisplayX(623);
    item.SetDisplayY(823);
    item.SetGlobalX(0);
    item.SetGlobalY(0);
    item.SetWindowX(600);
    item.SetWindowY(800);

    item.SetWidth(0);
    item.SetHeight(0);
    item.SetPressure(0);
    item.SetDeviceId(0);
    pointerEvent->AddPointerItem(item);
    return pointerEvent;
}
#endif // OHOS_BUILD_ENABLE_POINTER

void MyCallback(int32_t paramA, int64_t paramB)
{
    return;
}

/**
 * @tc.name: PointerEventTest_CheckMousePointEvent_001
 * @tc.desc: Verify mouse point event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_CheckMousePointEvent_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_UNKNOWN);
    ASSERT_TRUE(!pointerEvent->IsValid());

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(-1);
    ASSERT_TRUE(!pointerEvent->IsValid());

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    PointerEvent::PointerItem item1;
    item1.SetPointerId(0);
    pointerEvent->AddPointerItem(item1);
    PointerEvent::PointerItem item2;
    item2.SetPointerId(0);
    pointerEvent->AddPointerItem(item2);
    ASSERT_TRUE(!pointerEvent->IsValid());
    PointerEvent::PointerItem item3;
    item3.SetPointerId(0);
    pointerEvent->AddPointerItem(item3);
    PointerEvent::PointerItem item4;
    item4.SetPointerId(0);
    pointerEvent->AddPointerItem(item4);
    PointerEvent::PointerItem item5;
    item5.SetPointerId(0);
    pointerEvent->AddPointerItem(item5);
    PointerEvent::PointerItem item6;
    item6.SetPointerId(0);
    pointerEvent->AddPointerItem(item6);

    auto pointerEvent1 = PointerEvent::Create();
    ASSERT_NE(pointerEvent1, nullptr);
    pointerEvent1->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent1->SetPointerId(0);
    pointerEvent1->SetButtonPressed(PointerEvent::BUTTON_NONE);
    pointerEvent1->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent1->SetButtonPressed(PointerEvent::MOUSE_BUTTON_RIGHT);
    pointerEvent1->SetButtonPressed(PointerEvent::MOUSE_BUTTON_MIDDLE);
    item1.SetPointerId(0);
    pointerEvent1->AddPointerItem(item1);
    ASSERT_TRUE(!pointerEvent1->IsValid());
}

/**
 * @tc.name: PointerEventTest_CheckMousePointEvent_002
 * @tc.desc: Verify mouse point event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_CheckMousePointEvent_002, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent1 = PointerEvent::Create();
    ASSERT_NE(pointerEvent1, nullptr);
    pointerEvent1->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent1->SetPointerId(0);
    pointerEvent1->SetButtonPressed(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    pointerEvent1->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent1->IsValid());

    auto pointerEvent2 = PointerEvent::Create();
    ASSERT_NE(pointerEvent2, nullptr);
    pointerEvent2->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent2->SetPointerId(0);
    pointerEvent2->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent2->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    item.SetPointerId(0);
    pointerEvent2->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent2->IsValid());

    auto pointerEvent3 = PointerEvent::Create();
    ASSERT_NE(pointerEvent3, nullptr);
    pointerEvent3->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent3->SetPointerId(0);
    pointerEvent3->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent3->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    pointerEvent3->SetButtonId(PointerEvent::BUTTON_NONE);
    item.SetPointerId(0);
    pointerEvent3->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent3->IsValid());
}

/**
 * @tc.name: PointerEventTest_CheckMousePointEvent_003
 * @tc.desc: Verify mouse point event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_CheckMousePointEvent_003, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent1 = PointerEvent::Create();
    ASSERT_NE(pointerEvent1, nullptr);
    pointerEvent1->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent1->SetPointerId(0);
    pointerEvent1->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent1->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent1->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    pointerEvent1->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent1->IsValid());

    auto pointerEvent2 = PointerEvent::Create();
    ASSERT_NE(pointerEvent2, nullptr);
    pointerEvent2->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent2->SetPointerId(0);
    pointerEvent2->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent2->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent2->SetButtonId(PointerEvent::BUTTON_NONE);
    item.SetPointerId(-1);
    pointerEvent2->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent2->IsValid());
}

/**
 * @tc.name: PointerEventTest_CheckMousePointEvent_004
 * @tc.desc: Verify mouse point event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_CheckMousePointEvent_004, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent1 = PointerEvent::Create();
    ASSERT_NE(pointerEvent1, nullptr);
    pointerEvent1->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent1->SetPointerId(0);
    pointerEvent1->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent1->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent1->SetButtonId(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item;
    item.SetPointerId(2);
    pointerEvent1->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent1->IsValid());

    auto pointerEvent2 = PointerEvent::Create();
    ASSERT_NE(pointerEvent2, nullptr);
    pointerEvent2->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent2->SetPointerId(0);
    pointerEvent2->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent2->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent2->SetButtonId(PointerEvent::BUTTON_NONE);
    item.SetPointerId(0);
    item.SetDownTime(10010);
    pointerEvent2->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent2->IsValid());

    auto pointerEvent3 = PointerEvent::Create();
    ASSERT_NE(pointerEvent3, nullptr);
    pointerEvent3->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent3->SetPointerId(0);
    pointerEvent3->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent3->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent3->SetButtonId(PointerEvent::BUTTON_NONE);
    item.SetPointerId(0);
    item.SetDownTime(0);
    item.SetPressed(true);
    pointerEvent3->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent3->IsValid());
}

/**
 * @tc.name: PointerEventTest_CheckMousePointEvent_005
 * @tc.desc: Verify mouse point event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_CheckMousePointEvent_005, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetButtonId(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(0);
    item.SetPressed(false);
    pointerEvent->AddPointerItem(item);
    ASSERT_TRUE(pointerEvent->IsValid());
}

/**
 * @tc.name: PointerEventTest_CheckMousePointEvent_006
 * @tc.desc: Verify mouse point event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_CheckMousePointEvent_006, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    inputEvent->SetDeviceId(1);
    inputEvent->SetTargetWindowId(1);
    inputEvent->SetAgentWindowId(1);
    auto event = PointerEvent::from(inputEvent);
    ASSERT_EQ(event, nullptr);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->Reset();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetDeviceId(inputEvent->GetDeviceId());
    pointerEvent->SetTargetWindowId(inputEvent->GetTargetWindowId());
    pointerEvent->SetAgentWindowId(inputEvent->GetAgentWindowId());
    PointerEvent::PointerItem item1;
    item1.SetPointerId(0);
    item1.SetDownTime(0);
    item1.SetPressed(true);
    item1.SetWindowX(10);
    item1.SetWindowY(10);
    item1.SetDeviceId(inputEvent->GetDeviceId());
    item1.SetRawDx(60);
    item1.SetRawDy(60);
    pointerEvent->AddPointerItem(item1);
    PointerEvent::PointerItem item2;
    item2.SetPointerId(1);
    item2.SetDownTime(0);
    item2.SetPressed(false);
    item2.SetWindowX(item1.GetWindowX());
    item2.SetWindowY(item1.GetWindowY());
    item2.SetDeviceId(inputEvent->GetDeviceId());
    item2.SetRawDx(100);
    item2.SetRawDy(100);
    pointerEvent->AddPointerItem(item2);
    ASSERT_TRUE(pointerEvent != nullptr);
}

/**
 * @tc.name: PointerEventTest_CheckTouchPointEvent_001
 * @tc.desc: Verify touch screen event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_CheckTouchPointEvent_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(-1);
    ASSERT_TRUE(!pointerEvent->IsValid());

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    ASSERT_TRUE(!pointerEvent->IsValid());

    auto pointerEvent1 = PointerEvent::Create();
    ASSERT_NE(pointerEvent1, nullptr);
    pointerEvent1->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent1->SetPointerId(0);
    pointerEvent1->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    ASSERT_TRUE(!pointerEvent1->IsValid());

    auto pointerEvent2 = PointerEvent::Create();
    ASSERT_NE(pointerEvent2, nullptr);
    pointerEvent2->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent2->SetPointerId(0);
    pointerEvent2->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent2->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    ASSERT_TRUE(!pointerEvent2->IsValid());
}

/**
 * @tc.name: PointerEventTest_CheckTouchPointEvent_002
 * @tc.desc: Verify touch screen event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_CheckTouchPointEvent_002, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent1 = PointerEvent::Create();
    ASSERT_NE(pointerEvent1, nullptr);
    pointerEvent1->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent1->SetPointerId(0);
    pointerEvent1->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent1->SetButtonId(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item;
    item.SetPointerId(-1);
    pointerEvent1->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent1->IsValid());

    auto pointerEvent2 = PointerEvent::Create();
    ASSERT_NE(pointerEvent2, nullptr);
    pointerEvent2->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent2->SetPointerId(0);
    pointerEvent2->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent2->SetButtonId(PointerEvent::BUTTON_NONE);
    item.SetPointerId(0);
    item.SetDownTime(0);
    item.SetPressed(false);
    pointerEvent2->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent2->IsValid());
}

/**
 * @tc.name: PointerEventTest_CheckTouchPointEvent_003
 * @tc.desc: Verify touch screen event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_CheckTouchPointEvent_003, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent1 = PointerEvent::Create();
    ASSERT_NE(pointerEvent1, nullptr);
    pointerEvent1->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent1->SetPointerId(0);
    pointerEvent1->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent1->SetButtonId(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(100);
    item.SetPressed(true);
    pointerEvent1->AddPointerItem(item);
    ASSERT_TRUE(!pointerEvent1->IsValid());

    auto pointerEvent2 = PointerEvent::Create();
    ASSERT_NE(pointerEvent2, nullptr);
    pointerEvent2->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent2->SetPointerId(0);
    pointerEvent2->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent2->SetButtonId(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item1;
    item1.SetPointerId(0);
    item1.SetDownTime(100);
    item1.SetPressed(false);
    pointerEvent2->AddPointerItem(item1);
    PointerEvent::PointerItem item2;
    item2.SetPointerId(0);
    item2.SetDownTime(100);
    item2.SetPressed(false);
    pointerEvent2->AddPointerItem(item2);
    ASSERT_FALSE(!pointerEvent2->IsValid());
}

/**
 * @tc.name: PointerEventTest_CheckTouchPointEvent_004
 * @tc.desc: Verify touch screen event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_CheckTouchPointEvent_004, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetButtonId(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item1;
    item1.SetPointerId(1);
    item1.SetDownTime(100);
    item1.SetPressed(false);
    pointerEvent->AddPointerItem(item1);
    PointerEvent::PointerItem item2;
    item2.SetPointerId(2);
    item2.SetDownTime(100);
    item2.SetPressed(false);
    pointerEvent->AddPointerItem(item2);
    ASSERT_TRUE(!pointerEvent->IsValid());
}

/**
 * @tc.name: PointerEventTest_CheckTouchPointEvent_005
 * @tc.desc: Verify touch screen event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_CheckTouchPointEvent_005, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetButtonId(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item1;
    item1.SetPointerId(0);
    item1.SetDownTime(100);
    item1.SetPressed(false);
    pointerEvent->AddPointerItem(item1);
    PointerEvent::PointerItem item2;
    item2.SetPointerId(1);
    item2.SetDownTime(100);
    item2.SetPressed(false);
    pointerEvent->AddPointerItem(item2);
    ASSERT_TRUE(pointerEvent->IsValid());
}

/**
 * @tc.name: PointerEventTest_CheckTouchPointEvent_006
 * @tc.desc: Verify touch screen event
 * @tc.type: FUNC
 * @tc.require: I5QSN3
 */
HWTEST_F(PointerEventTest, PointerEventTest_CheckTouchPointEvent_006, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetButtonId(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(100);
    item.SetToolDisplayX(90);
    item.SetToolDisplayY(90);
    item.SetToolWindowX(50);
    item.SetToolWindowY(50);
    item.SetToolWidth(30);
    item.SetToolHeight(30);
    item.SetLongAxis(100);
    item.SetShortAxis(20);
    item.SetToolType(2);
    item.SetTargetWindowId(0);
    pointerEvent->AddPointerItem(item);
    ASSERT_TRUE(pointerEvent->IsValid());
    DumpWindowData(pointerEvent);
    pointerEvent->RemovePointerItem(0);
    pointerEvent->IsButtonPressed(0);
    pointerEvent->ClearButtonPressed();
    pointerEvent->ClearAxisValue();
    pointerEvent->DeleteReleaseButton(PointerEvent::BUTTON_NONE);
    ASSERT_FALSE(pointerEvent->IsValid());
}

/**
 * @tc.name: PointerEventTest_CheckTouchInputEvent_001
 * @tc.desc: Verify touch screen event
 * @tc.type: FUNC
 * @tc.require: I5QSN3
 */
HWTEST_F(PointerEventTest, PointerEventTest_CheckTouchInputEvent_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    inputEvent->SetTargetDisplayId(0);
    inputEvent->SetDeviceId(0);
    inputEvent->EventTypeToString(InputEvent::EVENT_TYPE_POINTER);
    inputEvent->HasFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);
    inputEvent->ClearFlag();
}

/**
 * @tc.name: PointerEventTest_SetEnhanceData_001
 * @tc.desc: Set the enhance data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetEnhanceData_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetButtonId(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item;
    item.SetPointerId(-1);
    pointerEvent->AddPointerItem(item);
    uint32_t enHanceDataLen = 3;
    uint8_t enhanceDataBuf[enHanceDataLen];
    std::vector<uint8_t> enhanceData;
    for (uint32_t i = 0; i < enHanceDataLen; i++) {
        enhanceData.push_back(enhanceDataBuf[i]);
    }
    #ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    ASSERT_NO_FATAL_FAILURE(pointerEvent->SetEnhanceData(enhanceData));
    ASSERT_EQ(pointerEvent->GetEnhanceData(), enhanceData);
    #endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
}

/**
 * @tc.name: PointerEventTest_SetToolDisplayX_001
 * @tc.desc: Set Tool Display Coordinates.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetToolDisplayX_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t displayX = 90;
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(0);
    ASSERT_NO_FATAL_FAILURE(item.SetToolDisplayX(displayX));
    ASSERT_EQ(item.GetToolDisplayX(), displayX);
    pointerEvent->AddPointerItem(item);
}

/**
 * @tc.name: PointerEventTest_SetToolDisplayY_001
 * @tc.desc: Set Tool Display Coordinates.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetToolDisplayY_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t displayY = 70;
    PointerEvent::PointerItem item;
    item.SetPointerId(2);
    item.SetDownTime(1);
    ASSERT_NO_FATAL_FAILURE(item.SetToolDisplayY(displayY));
    ASSERT_EQ(item.GetToolDisplayY(), displayY);
    pointerEvent->AddPointerItem(item);
}

/**
 * @tc.name: PointerEventTest_SetToolWidth_001
 * @tc.desc: Set Tool Display Width.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetToolWidth_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    int32_t toolWidth = 30;
    PointerEvent::PointerItem item;
    item.SetPointerId(3);
    item.SetDownTime(0);
    ASSERT_NO_FATAL_FAILURE(item.SetToolWidth(toolWidth));
    ASSERT_EQ(item.GetToolWidth(), toolWidth);
}

/**
 * @tc.name: PointerEventTest_SetToolHeight_001
 * @tc.desc: Set Tool Display Height.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetToolHeight_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    int32_t toolHeight = 40;
    PointerEvent::PointerItem item;
    item.SetPointerId(4);
    item.SetDownTime(1);
    ASSERT_NO_FATAL_FAILURE(item.SetToolHeight(toolHeight));
    ASSERT_EQ(item.GetToolHeight(), toolHeight);
}

/**
 * @tc.name: PointerEventTest_SetLongAxis_001
 * @tc.desc: Sets the long axis of the touch point area.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetLongAxis_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    int32_t longAxis = 50;
    PointerEvent::PointerItem item;
    item.SetPointerId(5);
    item.SetDownTime(0);
    ASSERT_NO_FATAL_FAILURE(item.SetLongAxis(longAxis));
    ASSERT_EQ(item.GetLongAxis(), longAxis);
}

/**
 * @tc.name: PointerEventTest_SetShortAxis_001
 * @tc.desc: Sets the short axis of the touch point area.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetShortAxis_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    int32_t shortAxis = 45;
    PointerEvent::PointerItem item;
    item.SetPointerId(6);
    item.SetDownTime(1);
    ASSERT_NO_FATAL_FAILURE(item.SetShortAxis(shortAxis));
    ASSERT_EQ(item.GetShortAxis(), shortAxis);
}

/**
 * @tc.name: PointerEventTest_GetPointerCount_001
 * @tc.desc: Get pointer count
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_GetPointerCount_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    int32_t pointerCount = pointerEvent->GetPointerCount();
    ASSERT_EQ(pointerCount, 0);
}

/**
 * @tc.name: PointerEventTest_SetExtraData_001
 * @tc.desc: Set extra data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetExtraData_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    const uint32_t length = 5;
    std::shared_ptr<const uint8_t[]> data;
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    inputEvent->SetExtraData(data, length);
}

/**
 * @tc.name: PointerEventTest_GetExtraData_001
 * @tc.desc: Get extra data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_GetExtraData_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = InputEvent::Create();
    std::shared_ptr<const uint8_t[]> retrievedData;
    uint32_t retrievedLength;
    inputEvent->GetExtraData(retrievedData, retrievedLength);
}

/**
 * @tc.name: PointerEventTest_SetRawDx_001
 * @tc.desc: Sets the raw X coordinate.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetRawDx_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    int32_t rawDx = 55;
    PointerEvent::PointerItem item;
    item.SetPointerId(7);
    item.SetDownTime(0);
    ASSERT_NO_FATAL_FAILURE(item.SetRawDx(rawDx));
    ASSERT_EQ(item.GetRawDx(), rawDx);
}

/**
 * @tc.name: PointerEventTest_SetRawDy_001
 * @tc.desc: Sets the raw Y coordinate.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetRawDy_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    int32_t rawDy = 60;
    PointerEvent::PointerItem item;
    item.SetPointerId(8);
    item.SetDownTime(1);
    ASSERT_NO_FATAL_FAILURE(item.SetRawDy(rawDy));
    ASSERT_EQ(item.GetRawDy(), rawDy);
}

/**
 * @tc.name: PointerEventTest_ClearFlag_001
 * @tc.desc: Clears all flags of an input event.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_ClearFlag_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    inputEvent->SetTargetDisplayId(0);
    inputEvent->SetDeviceId(0);
    inputEvent->EventTypeToString(InputEvent::EVENT_TYPE_POINTER);
    inputEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);
    ASSERT_NO_FATAL_FAILURE(inputEvent->ClearFlag());
    ASSERT_EQ(inputEvent->GetFlag(), InputEvent::EVENT_FLAG_NONE);
}

/**
 * @tc.name: PointerEventTest_From_001
 * @tc.desc: Convert InputEvent to nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_From_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    inputEvent->SetDeviceId(2);
    inputEvent->SetTargetWindowId(2);
    inputEvent->SetAgentWindowId(2);
    auto event = PointerEvent::from(inputEvent);
    ASSERT_EQ(event, nullptr);
}

/**
 * @tc.name: PointerEventTest_Reset_001
 * @tc.desc: Reset pointer event.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_Reset_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->Reset());
    ASSERT_EQ(pointerEvent->GetSourceType(), PointerEvent::SOURCE_TYPE_UNKNOWN);
    ASSERT_EQ(pointerEvent->GetPointerId(), -1);
    ASSERT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_UNKNOWN);
}

/**
 * @tc.name: PointerEventTest_IsButtonPressed_001
 * @tc.desc: Determine whether the button is pressed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_IsButtonPressed_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetButtonId(PointerEvent::BUTTON_NONE);
    pointerEvent->SetButtonPressed(0);
    ASSERT_TRUE(pointerEvent->IsButtonPressed(0));
}

/**
 * @tc.name: PointerEventTest_DeleteReleaseButton_001
 * @tc.desc: Deletes a released button.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_DeleteReleaseButton_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetButtonId(PointerEvent::BUTTON_NONE);
    pointerEvent->SetButtonPressed(0);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->DeleteReleaseButton(0));
    std::set<int32_t> pressButtons = pointerEvent->GetPressedButtons();
    ASSERT_EQ(pressButtons.size(), 0);
}

/**
 * @tc.name: PointerEventTest_ClearButtonPressed_001
 * @tc.desc: Clears the button in the pressed state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_ClearButtonPressed_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetButtonId(PointerEvent::BUTTON_NONE);
    pointerEvent->SetButtonPressed(0);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->ClearButtonPressed());
    std::set<int32_t> pressButtons = pointerEvent->GetPressedButtons();
    ASSERT_EQ(pressButtons.size(), 0);
}

/**
 * @tc.name: PointerEventTest_ClearAxisValue_001
 * @tc.desc: Clears the button in the pressed state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_ClearAxisValue_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, 30.0);
    double axisValue = pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL);
    ASSERT_EQ(axisValue, 30.0);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->ClearAxisValue());
    ASSERT_EQ(pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL), 0);
}

/**
 * @tc.name: PointerEventTest_SetZorderValue_001
 * @tc.desc: Sets the zOrder for this event, inject to windows whose zOrder less than the target zOrder.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetZorderValue_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetZOrder(30.0);
    float zOrder = pointerEvent->GetZOrder();
    ASSERT_EQ(zOrder, 30.0);
}

/**
 * @tc.name: PointerEventTest_IsValid_001
 * @tc.desc: Checks whether this input event is valid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_IsValid_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    ASSERT_FALSE(pointerEvent->IsValid());
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    ASSERT_FALSE(pointerEvent->IsValid());
    pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetButtonId(PointerEvent::BUTTON_NONE);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(0);
    item.SetPressed(false);
    pointerEvent->AddPointerItem(item);
    ASSERT_TRUE(pointerEvent->IsValid());
}

/**
 * @tc.name: PointerEventTest_GetFingerCount_001
 * @tc.desc: Sets the fingerCount for this event.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_GetFingerCount_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetFingerCount(-12);
    int32_t fingerCount = pointerEvent->GetFingerCount();
    ASSERT_EQ(fingerCount, -12);
    pointerEvent->SetFingerCount(-6);
    fingerCount = pointerEvent->GetFingerCount();
    ASSERT_EQ(fingerCount, -6);
    pointerEvent->SetFingerCount(0);
    fingerCount = pointerEvent->GetFingerCount();
    ASSERT_EQ(fingerCount, 0);
    pointerEvent->SetFingerCount(6);
    fingerCount = pointerEvent->GetFingerCount();
    ASSERT_EQ(fingerCount, 6);
    pointerEvent->SetFingerCount(12);
    fingerCount = pointerEvent->GetFingerCount();
    ASSERT_EQ(fingerCount, 12);
}

/**
 * @tc.name: PointerEventTest_ClearBuffer_001
 * @tc.desc: Clear the buffer data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_ClearBuffer_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    uint32_t enHanceDataLen = 3;
    uint8_t enhanceDataBuf[enHanceDataLen];
    std::vector<uint8_t> enhanceData;
    for (uint32_t i = 0; i < enHanceDataLen; i++) {
        enhanceData.push_back(enhanceDataBuf[i]);
    }
    pointerEvent->SetBuffer(enhanceData);
    std::vector<uint8_t> buffer = pointerEvent->GetBuffer();
    ASSERT_NE(buffer.size(), 0);
    pointerEvent->ClearBuffer();
    buffer = pointerEvent->GetBuffer();
    ASSERT_EQ(buffer.size(), 0);
}

/**
 * @tc.name: PointerEventTest_SetOriginPointerId_001
 * @tc.desc: Sets the origin id of the pointer in this event.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetOriginPointerId_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    int32_t originPointerId = 11;
    PointerEvent::PointerItem item;
    ASSERT_NO_FATAL_FAILURE(item.SetOriginPointerId(originPointerId));
    ASSERT_EQ(item.GetOriginPointerId(), originPointerId);
}

/**
 * @tc.name: PointerEvent_PointerItem_GetTwist_001
 * @tc.desc: Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEvent_PointerItem_GetTwist_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    int32_t twist = 1;
    PointerEvent::PointerItem item;
    ASSERT_NO_FATAL_FAILURE(item.SetTwist(twist));
    ASSERT_EQ(item.GetTwist(), twist);
}

/**
 * @tc.name: PointerEventTest_SetDisplayXPos_001
 * @tc.desc: Sets the x coordinate relative to the upper left corner of the screen.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetDisplayXPos_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    double displayX = 10.0;
    PointerEvent::PointerItem item;
    ASSERT_NO_FATAL_FAILURE(item.SetDisplayXPos(displayX));
    ASSERT_EQ(item.GetDisplayXPos(), displayX);
}

/**
 * @tc.name: PointerEventTest_SetDisplayYPos_001
 * @tc.desc: Sets the y coordinate relative to the upper left corner of the screen.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetDisplayYPos_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    double displayY = 10.0;
    PointerEvent::PointerItem item;
    ASSERT_NO_FATAL_FAILURE(item.SetDisplayYPos(displayY));
    ASSERT_EQ(item.GetDisplayYPos(), displayY);
}

/**
 * @tc.name: PointerEventTest_SetWindowXPos_001
 * @tc.desc: Sets the x coordinate of the active window.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetWindowXPos_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    double x = 10.0;
    PointerEvent::PointerItem item;
    ASSERT_NO_FATAL_FAILURE(item.SetWindowXPos(x));
    ASSERT_EQ(item.GetWindowXPos(), x);
}

/**
 * @tc.name: PointerEventTest_SetWindowYPos_001
 * @tc.desc: Sets the y coordinate of the active window.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetWindowYPos_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    double y = 10.0;
    PointerEvent::PointerItem item;
    ASSERT_NO_FATAL_FAILURE(item.SetWindowYPos(y));
    ASSERT_EQ(item.GetWindowYPos(), y);
}

/**
 * @tc.name: PointerEventTest_ActionToShortStr_001
 * @tc.desc: Verify ActionToShortStr
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_ActionToShortStr_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    int32_t eventType = 1;
    AxisEvent axisevent(eventType);
    int32_t action = AxisEvent::AXIS_ACTION_CANCEL;
    auto ret = axisevent.ActionToShortStr(action);
    ASSERT_EQ(ret, "A:C:");
    action = AxisEvent::AXIS_ACTION_START;
    ret = axisevent.ActionToShortStr(action);
    ASSERT_EQ(ret, "A:S:");
    action = AxisEvent::AXIS_ACTION_UPDATE;
    ret = axisevent.ActionToShortStr(action);
    ASSERT_EQ(ret, "A:U:");
    action = AxisEvent::AXIS_ACTION_END;
    ret = axisevent.ActionToShortStr(action);
    ASSERT_EQ(ret, "A:E:");
    action = AxisEvent::AXIS_ACTION_UNKNOWN;
    ret = axisevent.ActionToShortStr(action);
    ASSERT_EQ(ret, "A:UK:");
    action = 10;
    ret = axisevent.ActionToShortStr(action);
    ASSERT_EQ(ret, "A:?:");
}

/**
 * @tc.name: PointerEventTest_AddCapability_001
 * @tc.desc: Verify AddCapability
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_AddCapability_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    InputDevice device;
    InputDeviceCapability cap;
    cap = INPUT_DEV_CAP_TOUCH;
    ASSERT_NO_FATAL_FAILURE(device.AddCapability(cap));
    cap = INPUT_DEV_CAP_MAX;
    ASSERT_NO_FATAL_FAILURE(device.AddCapability(cap));
}

/**
 * @tc.name: PointerEventTest_HasCapability_001
 * @tc.desc: Verify HasCapability
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_HasCapability_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    InputDevice device;
    InputDeviceCapability cap;
    cap = INPUT_DEV_CAP_TOUCH;
    bool ret = device.HasCapability(cap);
    ASSERT_FALSE(ret);
    cap = INPUT_DEV_CAP_MAX;
    ret = device.HasCapability(cap);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: PointerEventTest_HasCapability_002
 * @tc.desc: Verify HasCapability
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_HasCapability_002, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    InputDevice device;
    device.capabilities_.set(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    device.capabilities_.set(InputDeviceCapability::INPUT_DEV_CAP_POINTER);
    EXPECT_TRUE(device.HasCapability(INPUT_DEV_CAP_KEYBOARD));
    EXPECT_TRUE(device.HasCapability(INPUT_DEV_CAP_POINTER));
    EXPECT_FALSE(device.HasCapability(INPUT_DEV_CAP_TOUCH));
    EXPECT_TRUE(device.HasCapability(INPUT_DEV_CAP_KEYBOARD | INPUT_DEV_CAP_POINTER | INPUT_DEV_CAP_TOUCH));
    EXPECT_TRUE(device.HasCapability(INPUT_DEV_CAP_KEYBOARD | INPUT_DEV_CAP_POINTER));
}

/**
 * @tc.name: PointerEventTest_MarkProcessed_001
 * @tc.desc: Verify MarkProcessed
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_MarkProcessed_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    std::function<void(int32_t, int64_t)> processedCallback_;
    auto inputEvent = std::make_shared<InputEvent>(InputEvent::EVENT_TYPE_KEY);
    inputEvent->markEnabled_ = true;
    ASSERT_NO_FATAL_FAILURE(inputEvent->MarkProcessed());
    inputEvent->markEnabled_ = false;
    ASSERT_NO_FATAL_FAILURE(inputEvent->MarkProcessed());
}

/**
 * @tc.name: PointerEventTest_SetExtraData_002
 * @tc.desc: Verify SetExtraData
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetExtraData_002, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = std::make_shared<InputEvent>(InputEvent::EVENT_TYPE_KEY);
    std::shared_ptr<const uint8_t[]> data;
    uint32_t length = 10;
    ASSERT_NO_FATAL_FAILURE(inputEvent->SetExtraData(data, length));
}

/**
 * @tc.name: PointerEventTest_GetExtraData_002
 * @tc.desc: Verify GetExtraData
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_GetExtraData_002, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = std::make_shared<InputEvent>(InputEvent::EVENT_TYPE_KEY);
    std::shared_ptr<const uint8_t[]> data;
    uint32_t length = 10;
    inputEvent->extraDataLength_ = 5;
    std::shared_ptr<const uint8_t[]> extraData;
    inputEvent->extraData_ = extraData;
    ASSERT_NO_FATAL_FAILURE(inputEvent->GetExtraData(data, length));
}

/**
 * @tc.name: PointerEventTest_WriteToParcel_001
 * @tc.desc: Verify WriteToParcel
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_WriteToParcel_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = std::make_shared<InputEvent>(InputEvent::EVENT_TYPE_KEY);
    Parcel out;
    inputEvent->extraDataLength_ = 5;
    std::shared_ptr<const uint8_t[]> extraData;
    inputEvent->extraData_ = extraData;
    bool ret = inputEvent->WriteToParcel(out);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: PointerEventTest_ReadFromParcel_001
 * @tc.desc: Verify ReadFromParcel
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_ReadFromParcel_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = std::make_shared<InputEvent>(InputEvent::EVENT_TYPE_KEY);
    Parcel in;
    inputEvent->extraDataLength_ = 1088;
    bool ret = inputEvent->ReadFromParcel(in);
    ASSERT_FALSE(ret);
    inputEvent->extraDataLength_ = 10;
    ret = inputEvent->ReadFromParcel(in);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: PointerEventTest_ActionToShortStr_002
 * @tc.desc: Verify ActionToShortStr
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_ActionToShortStr_002, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = std::make_shared<InputEvent>(InputEvent::EVENT_TYPE_KEY);
    int32_t action = InputEvent::ACTION_CANCEL;
    auto ret = inputEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "B:C:");
    action = InputEvent::ACTION_UNKNOWN;
    ret = inputEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "B:UK:");
    action = InputEvent::EVENT_FLAG_HIDE_POINTER;
    ret = inputEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "B:?:");
}

#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
/**
 * @tc.name: PointerEventTest_SetFingerprintDistanceX_001
 * @tc.desc: Set the fingerprint distance X.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetFingerprintDistanceX_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    double x = 10.0;
    ASSERT_NO_FATAL_FAILURE(pointerEvent->SetFingerprintDistanceX(x));
    ASSERT_EQ(pointerEvent->GetFingerprintDistanceX(), x);
}

/**
 * @tc.name: PointerEventTest_SetFingerprintDistanceY_001
 * @tc.desc: Set the fingerprint distance Y.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetFingerprintDistanceY_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    double y = 10.0;
    ASSERT_NO_FATAL_FAILURE(pointerEvent->SetFingerprintDistanceY(y));
    ASSERT_EQ(pointerEvent->GetFingerprintDistanceY(), y);
}
#endif // OHOS_BUILD_ENABLE_FINGERPRINT

/**
 * @tc.name: PointerEventTest_SetHandlerEventType
 * @tc.desc: Verify SetHandlerEventType
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetHandlerEventType, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetHandlerEventType(0);
    ASSERT_EQ(pointerEvent->GetHandlerEventType(), 0);
}

/**
 * @tc.name: PointerEventTest_GetAxisValue_001
 * @tc.desc: Test the funcation GetAxisValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_GetAxisValue_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::AxisType axis = PointerEvent::AXIS_TYPE_MAX;
    ASSERT_NO_FATAL_FAILURE(pointerEvent->GetAxisValue(axis));
    axis = PointerEvent::AXIS_TYPE_UNKNOWN;
    ASSERT_NO_FATAL_FAILURE(pointerEvent->GetAxisValue(axis));
    axis = PointerEvent::AXIS_TYPE_PINCH;
    ASSERT_NO_FATAL_FAILURE(pointerEvent->GetAxisValue(axis));
}

/**
 * @tc.name: PointerEventTest_SetAxisValue_001
 * @tc.desc: Test the funcation SetAxisValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetAxisValue_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    double axisValue = 1.0;
    PointerEvent::AxisType axis = PointerEvent::AXIS_TYPE_MAX;
    ASSERT_NO_FATAL_FAILURE(pointerEvent->SetAxisValue(axis, axisValue));
    axis = PointerEvent::AXIS_TYPE_UNKNOWN;
    ASSERT_NO_FATAL_FAILURE(pointerEvent->SetAxisValue(axis, axisValue));
    axis = PointerEvent::AXIS_TYPE_PINCH;
    ASSERT_NO_FATAL_FAILURE(pointerEvent->SetAxisValue(axis, axisValue));
}

/**
 * @tc.name: PointerEventTest_HasAxis_001
 * @tc.desc: Test the funcation HasAxis
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_HasAxis_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    uint32_t axes = 1;
    PointerEvent::AxisType axis = PointerEvent::AXIS_TYPE_MAX;
    bool ret = pointerEvent->HasAxis(axes, axis);
    ASSERT_FALSE(ret);
    axis = PointerEvent::AXIS_TYPE_UNKNOWN;
    ret = pointerEvent->HasAxis(axes, axis);
    ASSERT_TRUE(ret);
    axis = PointerEvent::AXIS_TYPE_PINCH;
    ret = pointerEvent->HasAxis(axes, axis);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: PointerEventTest_SetPressure_001
 * @tc.desc: Test the funcation SetPressure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetPressure_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    double pressure = -1.0;
    PointerEvent::PointerItem item;
    ASSERT_NO_FATAL_FAILURE(item.SetPressure(pressure));
    pressure = 1.0;
    ASSERT_NO_FATAL_FAILURE(item.SetPressure(pressure));
}

/**
 * @tc.name: PointerEventTest_SetMoveFlag_001
 * @tc.desc: Test the funcation SetMoveFlag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetMoveFlag_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    int32_t moveFlag = -1;
    PointerEvent::PointerItem item;
    ASSERT_NO_FATAL_FAILURE(item.SetMoveFlag(moveFlag));
    moveFlag = 0;
    ASSERT_NO_FATAL_FAILURE(item.SetMoveFlag(moveFlag));
}

/**
 * @tc.name: PointerEventTest_ActionToShortStr_003
 * @tc.desc: Test the funcation ActionToShortStr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_ActionToShortStr_003, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = PointerEvent::POINTER_ACTION_PULL_UP;
    auto ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:PU:");
    action = PointerEvent::POINTER_ACTION_PULL_IN_WINDOW;
    ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:PI:");
    action = PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW;
    ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:PO:");
    action = PointerEvent::POINTER_ACTION_SWIPE_BEGIN;
    ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:SB:");
    action = PointerEvent::POINTER_ACTION_SWIPE_UPDATE;
    ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:SU:");
    action = PointerEvent::POINTER_ACTION_SWIPE_END;
    ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:SE:");
    action = PointerEvent::POINTER_ACTION_ROTATE_BEGIN;
    ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:RB:");
    action = PointerEvent::POINTER_ACTION_ROTATE_UPDATE;
    ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:RU:");
    action = PointerEvent::POINTER_ACTION_ROTATE_END;
    ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:RE:");
    action = PointerEvent::POINTER_ACTION_TRIPTAP;
    ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:TT:");
}

/**
 * @tc.name: PointerEventTest_ActionToShortStr_004
 * @tc.desc: Test the funcation ActionToShortStr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_ActionToShortStr_004, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = PointerEvent::POINTER_ACTION_QUADTAP;
    auto ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:Q:");
    action = PointerEvent::POINTER_ACTION_HOVER_MOVE;
    ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:HM:");
    action = PointerEvent::POINTER_ACTION_HOVER_ENTER;
    ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:HE:");
    action = PointerEvent::POINTER_ACTION_FINGERPRINT_DOWN;
    ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:FD:");
    action = PointerEvent::POINTER_ACTION_FINGERPRINT_UP;
    ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:FU:");
    action = PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE;
    ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:FS:");
    action = PointerEvent::POINTER_ACTION_FINGERPRINT_RETOUCH;
    ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:FR:");
    action = PointerEvent::POINTER_ACTION_FINGERPRINT_CLICK;
    ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:FC:");
    action = PointerEvent::POINTER_ACTION_UNKNOWN;
    ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:UK:");
    action = 100;
    ret = pointerEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "P:?:");
}

/**
 * @tc.name: PointerEventTest_SetTiltX_001
 * @tc.desc: Test the funcation SetTiltX and GetTiltX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetTiltX_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    double x = 10.0;
    PointerEvent::PointerItem item;
    ASSERT_NO_FATAL_FAILURE(item.SetTiltX(x));
    ASSERT_EQ(item.GetTiltX(), x);
}

/**
 * @tc.name: PointerEventTest_SetTiltY_001
 * @tc.desc: Test the funcation SetTiltY and GetTiltY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetTiltY_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    double y = 10.0;
    PointerEvent::PointerItem item;
    ASSERT_NO_FATAL_FAILURE(item.SetTiltY(y));
    ASSERT_EQ(item.GetTiltY(), y);
}

/**
 * @tc.name: PointerEventTest_SetRawDisplayX_001
 * @tc.desc: Sets the raw X coordinate.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetRawDisplayX_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    int32_t rawDisplayX = 60;
    PointerEvent::PointerItem item;
    item.SetPointerId(8);
    item.SetDownTime(1);
    ASSERT_NO_FATAL_FAILURE(item.SetRawDisplayX(rawDisplayX));
    ASSERT_EQ(item.GetRawDisplayX(), rawDisplayX);
}

/**
 * @tc.name: PointerEventTest_SetRawDisplayY_001
 * @tc.desc: Sets the raw Y coordinate.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetRawDisplayY_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    int32_t rawDisplayY = 60;
    PointerEvent::PointerItem item;
    item.SetPointerId(8);
    item.SetDownTime(1);
    ASSERT_NO_FATAL_FAILURE(item.SetRawDisplayY(rawDisplayY));
    ASSERT_EQ(item.GetRawDisplayY(), rawDisplayY);
}

/**
 * @tc.name: PointerEventTest_EventTypeToString_001
 * @tc.desc: Test the funcation EventTypeToString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_EventTypeToString_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    int32_t eventType = InputEvent::EVENT_TYPE_BASE;
    std::string ret = inputEvent->EventTypeToString(eventType);
    ASSERT_EQ(ret, "base");
    eventType = InputEvent::EVENT_TYPE_KEY;
    ret = inputEvent->EventTypeToString(eventType);
    ASSERT_EQ(ret, "key");
    eventType = InputEvent::EVENT_TYPE_POINTER;
    ret = inputEvent->EventTypeToString(eventType);
    ASSERT_EQ(ret, "pointer");
    eventType = InputEvent::EVENT_TYPE_AXIS;
    ret = inputEvent->EventTypeToString(eventType);
    ASSERT_EQ(ret, "axis");
    eventType = InputEvent::EVENT_TYPE_FINGERPRINT;
    ret = inputEvent->EventTypeToString(eventType);
    ASSERT_EQ(ret, "fingerprint");
    eventType = InputEvent::EVENT_FLAG_NO_INTERCEPT;
    ret = inputEvent->EventTypeToString(eventType);
    ASSERT_EQ(ret, "unknown");
}

/**
 * @tc.name: PointerEventTest_MarkProcessed_002
 * @tc.desc: Test the funcation MarkProcessed
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_MarkProcessed_002, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    auto callback = [](int a, int b) {};
    inputEvent->processedCallback_ = callback;
    inputEvent->processedCallback_(10, 20);
    inputEvent->markEnabled_ = false;
    ASSERT_NO_FATAL_FAILURE(inputEvent->MarkProcessed());
    inputEvent->markEnabled_ = true;
    ASSERT_NO_FATAL_FAILURE(inputEvent->MarkProcessed());
}

/**
 * @tc.name: PointerEventTest_SetExtraData_005
 * @tc.desc: Set extra data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetExtraData_005, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    uint32_t length = 5;
    uint8_t data[5] = {1, 2, 3, 4, 5};
    std::shared_ptr<const uint8_t[]> sharedData(data, [](const uint8_t*) {});
    ASSERT_NO_FATAL_FAILURE(inputEvent->SetExtraData(sharedData, length));
    length = -5;
    ASSERT_NO_FATAL_FAILURE(inputEvent->SetExtraData(sharedData, length));
    length = 2000;
    ASSERT_NO_FATAL_FAILURE(inputEvent->SetExtraData(sharedData, length));
}

/**
 * @tc.name: PointerEventTest_GetExtraData_004
 * @tc.desc: Verify GetExtraData
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_GetExtraData_004, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    uint32_t length = 5;
    inputEvent->extraDataLength_ = 5;
    std::shared_ptr<const uint8_t[]> data;
    ASSERT_NO_FATAL_FAILURE(inputEvent->GetExtraData(data, length));
    inputEvent->extraDataLength_ = 0;
    ASSERT_NO_FATAL_FAILURE(inputEvent->GetExtraData(data, length));
    uint8_t datas[5] = {1, 2, 3, 4, 5};
    std::shared_ptr<const uint8_t[]> sharedData(datas, [](const uint8_t*) {});
    ASSERT_NO_FATAL_FAILURE(inputEvent->SetExtraData(sharedData, length));
    inputEvent->extraDataLength_ = 10;
    ASSERT_NO_FATAL_FAILURE(inputEvent->GetExtraData(data, length));
    inputEvent->extraDataLength_ = 0;
    ASSERT_NO_FATAL_FAILURE(inputEvent->GetExtraData(data, length));
}

/**
 * @tc.name: PointerEventTest_WriteToParcel_003
 * @tc.desc: Verify WriteToParcel
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_WriteToParcel_003, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    Parcel out;
    uint32_t length = 5;
    inputEvent->extraDataLength_ = 0;
    bool ret = inputEvent->WriteToParcel(out);
    ASSERT_TRUE(ret);
    inputEvent->extraDataLength_ = 5;
    ret = inputEvent->WriteToParcel(out);
    ASSERT_TRUE(ret);
    uint8_t datas[5] = {1, 2, 3, 4, 5};
    std::shared_ptr<const uint8_t[]> sharedData(datas, [](const uint8_t*) {});
    ASSERT_NO_FATAL_FAILURE(inputEvent->SetExtraData(sharedData, length));
    inputEvent->extraDataLength_ = 0;
    ret = inputEvent->WriteToParcel(out);
    ASSERT_TRUE(ret);
    inputEvent->extraDataLength_ = 5;
    ret = inputEvent->WriteToParcel(out);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: PointerEventTest_ToString
 * @tc.desc: Test the funcation ToString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_ToString, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->ToString());

    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(inputEvent->ToString());
}

/**
 * @tc.name: PointerEventTest_ReadFromParcel
 * @tc.desc: Test the funcation ReadFromParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_ReadFromParcel, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    Parcel in;
    PointerEvent::PointerItem item;
    item.pressed_ = false;
    bool ret = item.ReadFromParcel(in);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: PointerEventTest_ClearAxisStatus
 * @tc.desc: Test the funcation ClearAxisStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_ClearAxisStatus, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::AxisType axis = PointerEvent::AXIS_TYPE_MAX;
    ASSERT_NO_FATAL_FAILURE(pointerEvent->ClearAxisStatus(axis));
}

/**
 * @tc.name: PointerEventTest_from
 * @tc.desc: Verify the funcation from
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_from, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(PointerEvent::from(inputEvent));
}

/**
 * @tc.name: PointerEventTest_GetBlobId
 * @tc.desc: Verify the funcation GetBlobId
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_GetBlobId, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    auto item = PointerEvent::PointerItem();
    item.blobId_ = 0;
    int32_t bloBid = item.GetBlobId();
    ASSERT_EQ(bloBid, item.blobId_);
}

/**
 * @tc.name: PointerEventTest_SetBlobId
 * @tc.desc: Verify the funcation SetBlobId
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetBlobId, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    auto item = PointerEvent::PointerItem();
    item.SetBlobId(32);
    ASSERT_EQ(32, item.blobId_);
}

/**
 * @tc.name: PointerEventTest_IsCanceled
 * @tc.desc: Verify the funcation IsCanceled
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_IsCanceled, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto item = PointerEvent::PointerItem();
    item.SetCanceled(true);
    ASSERT_TRUE(item.IsCanceled());
}

/**
 * @tc.name: PointerEventTest_GetFixedDisplayX
 * @tc.desc: Verify the funcation FixedDisplayX
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_GetFixedDisplayX, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto item = PointerEvent::PointerItem();
    double disPlayX = 25.00;
    item.SetFixedDisplayX(disPlayX);
    ASSERT_EQ(item.GetFixedDisplayX(), disPlayX);
}

/**
 * @tc.name: PointerEventTest_GetFixedDisplayY
 * @tc.desc: Verify the funcation FixedDisplayY
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_GetFixedDisplayY, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto item = PointerEvent::PointerItem();
    double disPlayY = 30.00;
    item.SetFixedDisplayY(disPlayY);
    ASSERT_EQ(item.GetFixedDisplayY(), disPlayY);
}

/**
 * @tc.name: PointerEventTest_ClearAxisStatus_01
 * @tc.desc: Verify the funcation ClearAxisStatus
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_ClearAxisStatus_01, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointer = PointerEvent::Create();
    PointerEvent::AxisType axisType = PointerEvent::AxisType::AXIS_TYPE_SCROLL_VERTICAL;
    ASSERT_NO_FATAL_FAILURE(pointer->SetAxisEventType(axisType));
    ASSERT_NO_FATAL_FAILURE(pointer->ClearAxisStatus(axisType));
}

/**
 * @tc.name: PointerEventTest_SetVelocity
 * @tc.desc: Verify the funcation SetVelocity
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetVelocity, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointer = PointerEvent::Create();
    double velocity = 8.0;
    ASSERT_NO_FATAL_FAILURE(pointer->SetVelocity(velocity));
    ASSERT_EQ(pointer->GetVelocity(), velocity);
}

/**
 * @tc.name: PointerEventTest_SetHandOption
 * @tc.desc: Verify the funcation SetHandOption
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetHandOption, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointer = PointerEvent::Create();
    int32_t handOption = 5;
    ASSERT_NO_FATAL_FAILURE(pointer->SetHandOption(handOption));
    ASSERT_EQ(pointer->GetHandOption(), handOption);
}

/**
 * @tc.name: PointerEventTest_SetOriginPointerAction
 * @tc.desc: Verify the funcation SetOriginPointerAction
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetOriginPointerAction, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointer = PointerEvent::Create();
    int32_t handOption = 5;
    ASSERT_NO_FATAL_FAILURE(pointer->SetOriginPointerAction(handOption));
    ASSERT_EQ(pointer->GetOriginPointerAction(), handOption);
}

/**
 * @tc.name: PointerEventTest_SetPullId
 * @tc.desc: Verify the funcation SetPullId
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetPullId, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointer = PointerEvent::Create();
    int32_t pullId = 5;
    ASSERT_NO_FATAL_FAILURE(pointer->SetPullId(pullId));
    ASSERT_EQ(pointer->GetPullId(), pullId);
}

/**
 * @tc.name: PointerEventTest_SetScrollRows
 * @tc.desc: Verify the funcation SetScrollRows
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetScrollRows, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointer = PointerEvent::Create();
    int32_t scrollRows = 5;
    ASSERT_NO_FATAL_FAILURE(pointer->SetScrollRows(scrollRows));
    ASSERT_EQ(pointer->GetScrollRows(), scrollRows);
}

/**
 * @tc.name: PointerEventTest_SetFixedMode
 * @tc.desc: Verify the funcation SetFixedMode
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetFixedMode, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointer = PointerEvent::Create();
    auto fixedMode = PointerEvent::FixedMode::SCREEN_MODE_MAX;
    ASSERT_NO_FATAL_FAILURE(pointer->SetFixedMode(fixedMode));
    ASSERT_EQ(pointer->GetFixedMode(), fixedMode);
}

/**
 * @tc.name: PointerEventTest_GetFixedModeStr
 * @tc.desc: Verify the funcation GetFixedModeStr
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_GetFixedModeStr, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointer = PointerEvent::Create();
    auto fixedMode = PointerEvent::FixedMode::SCREEN_MODE_MAX;
    ASSERT_NO_FATAL_FAILURE(pointer->SetFixedMode(fixedMode));
    ASSERT_EQ(pointer->GetFixedModeStr(), "unknown");
    fixedMode = PointerEvent::FixedMode::NORMAL;
    pointer->SetFixedMode(fixedMode);
    ASSERT_EQ(pointer->GetFixedModeStr(), "normal");
    fixedMode = PointerEvent::FixedMode::AUTO;
    pointer->SetFixedMode(fixedMode);
    ASSERT_EQ(pointer->GetFixedModeStr(), "one-hand");
}

/**
 * @tc.name: PointerEventTest_SetProcessedCallback
 * @tc.desc: Verify the funcation SetProcessedCallback
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetProcessedCallback, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = InputEvent::Create();
    ASSERT_NO_FATAL_FAILURE(inputEvent->SetProcessedCallback(MyCallback));
}

/**
 * @tc.name: PointerEventTest_DumpPointerAction_001
 * @tc.desc: Verify the funcation DumpPointerAction
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_DumpPointerAction_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    double axisValue = 0;
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, axisValue);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->DumpPointerAction());

    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, axisValue);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->DumpPointerAction());

    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, axisValue);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->DumpPointerAction());

    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_ROTATE, axisValue);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->DumpPointerAction());
}

/**
 * @tc.name: PointerEventTest_DumpPointerAction_002
 * @tc.desc: Verify the funcation DumpPointerAction
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_DumpPointerAction_002, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    double axisValue = 0;
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, axisValue);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->DumpPointerAction());

    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, axisValue);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->DumpPointerAction());

    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, axisValue);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->DumpPointerAction());

    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_ROTATE, axisValue);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->DumpPointerAction());
}

/**
 * @tc.name: PointerEventTest_DumpPointerAction_003
 * @tc.desc: Verify the funcation DumpPointerAction
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_DumpPointerAction_003, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
    double axisValue = 0;
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, axisValue);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->DumpPointerAction());

    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, axisValue);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->DumpPointerAction());

    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, axisValue);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->DumpPointerAction());

    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_ROTATE, axisValue);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->DumpPointerAction());
}

/**
 * @tc.name: PointerEventTest_DumpPointerAction_004
 * @tc.desc: Verify the funcation DumpPointerAction
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_DumpPointerAction_004, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->DumpPointerAction());
}

/**
 * @tc.name: PointerEventTest_IsValidCheckMouseFunc_001
 * @tc.desc: Verify if (pointers_.size() != 1)
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_IsValidCheckMouseFunc_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->IsValidCheckMouseFunc());
}

/**
 * @tc.name: PointerEventTest_IsValidCheckMouseFunc_002
 * @tc.desc: Verify if (pointers_.size() != 1)
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_IsValidCheckMouseFunc_002, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->IsValidCheckMouseFunc());
}

/**
 * @tc.name: PointerEventTest_IsValidCheckMouseFunc_003
 * @tc.desc: Verify if (pressedButtons_.size() > maxPressedButtons)
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_IsValidCheckMouseFunc_003, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetButtonPressed(0);
    pointerEvent->SetButtonPressed(1);
    pointerEvent->SetButtonPressed(2);
    pointerEvent->SetButtonPressed(3);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->IsValidCheckMouseFunc());
}

/**
 * @tc.name: PointerEventTest_IsValidCheckMouseFunc_004
 * @tc.desc: Verify if (pressedButtons_.size() > maxPressedButtons)
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_IsValidCheckMouseFunc_004, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetButtonPressed(0);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->IsValidCheckMouseFunc());
}

/**
 * @tc.name: PointerEventTest_IsValidCheckMouseFunc_005
 * @tc.desc: Verify if (checkFlag)
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_IsValidCheckMouseFunc_005, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetButtonPressed(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->IsValidCheckMouseFunc());
}

/**
 * @tc.name: PointerEventTest_IsValidCheckMouseFunc_006
 * @tc.desc: Verify if (checkFlag)
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_IsValidCheckMouseFunc_006, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetButtonPressed(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->IsValidCheckMouseFunc());
}

/**
 * @tc.name: PointerEventTest_IsValidCheckMouseFunc_007
 * @tc.desc: Verify if (buttonId != BUTTON_NONE)
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_IsValidCheckMouseFunc_007, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetButtonPressed(-1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->IsValidCheckMouseFunc());
}

/**
 * @tc.name: PointerEventTest_SetTwist_001
 * @tc.desc: SetTwist
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_SetTwist_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    int32_t twist = 3;
    ASSERT_NO_FATAL_FAILURE(item.SetTwist(twist));
}

/**
 * @tc.name: PointerEventTest_GetTwist_001
 * @tc.desc: GetTwist
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(PointerEventTest, PointerEventTest_GetTwist_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    int32_t twist = 3;
    ASSERT_NO_FATAL_FAILURE(item.SetTwist(twist));
    int32_t ret = item.GetTwist();
    ASSERT_EQ(ret, twist);
}

/**
 * @tc.name: PointerEventTest_CheckInputEvent_001
 * @tc.desc: Verify point event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_CheckInputEvent_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    inputEvent->HasFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);
    inputEvent->IsFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);
    inputEvent->ClearFlag();
}

/**
 * @tc.name: PointerEventTest_PointerItem_SetOrientation
 * @tc.desc: Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_PointerItem_SetOrientation, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    int32_t orientation = 1;
    PointerEvent::PointerItem item;
    ASSERT_NO_FATAL_FAILURE(item.SetOrientation(orientation));
    ASSERT_EQ(item.GetOrientation(), orientation);
}

/**
 * @tc.name: PointerEventTest_PointerItem_GlobalCoordinates
 * @tc.desc: Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, PointerEventTest_PointerItem_GlobalCoordinates, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    double globalX { -1.0 };
    double globalY { -1.0 };
    PointerEvent::PointerItem item;
    ASSERT_NO_FATAL_FAILURE(item.SetGlobalX(globalX));
    ASSERT_NO_FATAL_FAILURE(item.SetGlobalY(globalY));
    ASSERT_EQ(static_cast<int32_t>(item.GetGlobalX()), static_cast<int32_t>(globalX));
    ASSERT_EQ(static_cast<int32_t>(item.GetGlobalY()), static_cast<int32_t>(globalY));
}

/**
 * @tc.name: AddPointerItemTest1
 * @tc.desc: Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventTest, AddPointerItemTest1, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item1;
    item1.SetPointerId(0);
    pointerEvent->AddPointerItem(item1);
    PointerEvent::PointerItem item2;
    item2.SetPointerId(0);
    pointerEvent->AddPointerItem(item2);
    ASSERT_TRUE(!pointerEvent->IsValid());
    PointerEvent::PointerItem item3;
    item3.SetPointerId(0);
    pointerEvent->AddPointerItem(item3);
    PointerEvent::PointerItem item4;
    item4.SetPointerId(0);
    pointerEvent->AddPointerItem(item4);
    PointerEvent::PointerItem item5;
    item5.SetPointerId(0);
    pointerEvent->AddPointerItem(item5);
    PointerEvent::PointerItem item6;
    item6.SetPointerId(0);
    pointerEvent->AddPointerItem(item6);
    PointerEvent::PointerItem item7;
    item7.SetPointerId(0);
    pointerEvent->AddPointerItem(item7);
    PointerEvent::PointerItem item8;
    item8.SetPointerId(0);
    pointerEvent->AddPointerItem(item8);
    PointerEvent::PointerItem item9;
    item9.SetPointerId(0);
    pointerEvent->AddPointerItem(item9);
    PointerEvent::PointerItem item10;
    item10.SetPointerId(0);
    pointerEvent->AddPointerItem(item10);
    PointerEvent::PointerItem item11;
    item11.SetPointerId(0);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->AddPointerItem(item11));
}
} // namespace MMI
} // namespace OHOS
