/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "event_statistic.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventStatisticTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t EVENT_OUT_SIZE { 30 };
constexpr int32_t POINTER_RECORD_MAX_SIZE { 100 };
} // namespace

class EventStatisticTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: EventDumpTest_ConvertInputEventToStr
 * @tc.desc: Event dump ConvertInputEventToStr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_ConvertInputEventToStr, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    auto inputEvent = std::make_shared<InputEvent>(3);
    inputEvent->eventType_ = 3;
    inputEvent->actionTime_ = 280000000;
    inputEvent->deviceId_ = 2;
    inputEvent->sourceType_ = 6;
    std::string str = "";
    str = eventStatistic.ConvertInputEventToStr(inputEvent);
    ASSERT_FALSE(str.empty());
}

/**
 * @tc.name: EventDumpTest_ConvertTimeToStr
 * @tc.desc: Event dump ConvertTimeToStr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_ConvertTimeToStr, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    int64_t time = -1;
    std::string str = "";
    str = eventStatistic.ConvertTimeToStr(time);
    ASSERT_EQ(str, "1970-01-01 07:59:59");

    time = 280000000;
    str = eventStatistic.ConvertTimeToStr(time);
    ASSERT_EQ(str, "1978-11-16 01:46:40");
}

/**
 * @tc.name: EventDumpTest_PushPointerEvent
 * @tc.desc: Event dump PushPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushPointerEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->bitwise_ = 0x000040;
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushPointerEvent(pointerEvent));

    pointerEvent->SetAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE);
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushPointerEvent(pointerEvent));

    pointerEvent->SetAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushPointerEvent(pointerEvent));
}

/**
 * @tc.name: EventDumpTest_PushKeyEvent
 * @tc.desc: Event dump PushKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushKeyEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->bitwise_ = 0x000040;
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushKeyEvent(keyEvent));

    keyEvent->AddFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE);
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushKeyEvent(keyEvent));

    keyEvent->SetAction(KeyEvent::KEY_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushKeyEvent(keyEvent));
}

/**
 * @tc.name: EventDumpTest_PushSwitchEvent
 * @tc.desc: Event dump PushSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushSwitchEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    std::shared_ptr<SwitchEvent> switchEvent = std::make_shared<SwitchEvent>(0);
    switchEvent->SetSwitchType(SwitchEvent::SWITCH_DEFAULT);
    switchEvent->bitwise_ = 0x000040;
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushSwitchEvent(switchEvent));

    switchEvent->SetSwitchType(SwitchEvent::SWITCH_TABLET);
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushSwitchEvent(switchEvent));
}

/**
 * @tc.name: EventDumpTest_PushEventStr
 * @tc.desc: Event dump PushEventStr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushEventStr, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    eventStatistic.writeFileEnabled_ = true;
    std::string str = "test_push_event_str";
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushEventStr(str));

    for (auto i = 0; i < EVENT_OUT_SIZE - 1; i++) {
        auto inputEvent1 = std::make_shared<InputEvent>(2);
        eventStatistic.dumperEventList_.push_back(EventStatistic::ConvertInputEventToStr(inputEvent1));
    }
    eventStatistic.writeFileEnabled_ = false;
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushEventStr(str));
}

/**
 * @tc.name: EventDumpTest_Dump
 * @tc.desc: Event dump Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_Dump, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    int32_t fd = 0;
    std::vector<std::string> dumpStr;
    for (auto i = 0; i < 5; i++) {
        std::string str = "EventStatistic Test Dump ";
        eventStatistic.dumperEventList_.push_back(str);
        dumpStr.push_back(str);
    }
    ASSERT_NO_FATAL_FAILURE(eventStatistic.Dump(fd, dumpStr));
}

/**
 * @tc.name: EventDumpTest_ConvertEventTypeToString
 * @tc.desc: Event dump ConvertEventTypeToString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_ConvertEventTypeToString, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    int32_t eventType = InputEvent::EVENT_TYPE_BASE;
    ASSERT_STREQ(eventStatistic.ConvertEventTypeToString(eventType), "base");

    eventType = InputEvent::EVENT_TYPE_KEY;
    ASSERT_STREQ(eventStatistic.ConvertEventTypeToString(eventType), "key");

    eventType = InputEvent::EVENT_TYPE_POINTER;
    ASSERT_STREQ(eventStatistic.ConvertEventTypeToString(eventType), "pointer");

    eventType = InputEvent::EVENT_TYPE_AXIS;
    ASSERT_STREQ(eventStatistic.ConvertEventTypeToString(eventType), "axis");

    eventType = InputEvent::EVENT_TYPE_FINGERPRINT;
    ASSERT_STREQ(eventStatistic.ConvertEventTypeToString(eventType), "fingerprint");

    eventType = -1;
    ASSERT_STREQ(eventStatistic.ConvertEventTypeToString(eventType), "unknown");
}

/**
 * @tc.name: EventDumpTest_ConvertSourceTypeToString
 * @tc.desc: Event dump ConvertSourceTypeToString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_ConvertSourceTypeToString, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    int32_t sourceType = InputEvent::SOURCE_TYPE_MOUSE;
    ASSERT_STREQ(eventStatistic.ConvertSourceTypeToString(sourceType), "mouse");

    sourceType = InputEvent::SOURCE_TYPE_TOUCHSCREEN;
    ASSERT_STREQ(eventStatistic.ConvertSourceTypeToString(sourceType), "touch-screen");

    sourceType = InputEvent::SOURCE_TYPE_TOUCHPAD;
    ASSERT_STREQ(eventStatistic.ConvertSourceTypeToString(sourceType), "touch-pad");

    sourceType = InputEvent::SOURCE_TYPE_JOYSTICK;
    ASSERT_STREQ(eventStatistic.ConvertSourceTypeToString(sourceType), "joystick");

    sourceType = InputEvent::SOURCE_TYPE_FINGERPRINT;
    ASSERT_STREQ(eventStatistic.ConvertSourceTypeToString(sourceType), "fingerprint");

    sourceType = InputEvent::SOURCE_TYPE_CROWN;
    ASSERT_STREQ(eventStatistic.ConvertSourceTypeToString(sourceType), "crown");

    sourceType = InputEvent::EVENT_FLAG_NONE;
    ASSERT_STREQ(eventStatistic.ConvertSourceTypeToString(sourceType), "unknown");
}

/**
 * @tc.name: EventDumpTest_ConvertPointerActionToString_001
 * @tc.desc: Event dump ConvertPointerActionToString_001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_ConvertPointerActionToString_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->bitwise_ = 0x000040;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, 0);
    ASSERT_STREQ(eventStatistic.ConvertPointerActionToString(pointerEvent), "axis-begin");
    pointerEvent->ClearAxisValue();

    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, 0);
    ASSERT_STREQ(eventStatistic.ConvertPointerActionToString(pointerEvent), "axis-begin");
    pointerEvent->ClearAxisValue();

    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, 0);
    ASSERT_STREQ(eventStatistic.ConvertPointerActionToString(pointerEvent), "pinch-begin");
    pointerEvent->ClearAxisValue();
}

/**
 * @tc.name: EventDumpTest_ConvertPointerActionToString_002
 * @tc.desc: Event dump ConvertPointerActionToString_002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_ConvertPointerActionToString_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->bitwise_ = 0x000040;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, 0);
    ASSERT_STREQ(eventStatistic.ConvertPointerActionToString(pointerEvent), "axis-update");
    pointerEvent->ClearAxisValue();

    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, 0);
    ASSERT_STREQ(eventStatistic.ConvertPointerActionToString(pointerEvent), "axis-update");
    pointerEvent->ClearAxisValue();

    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, 0);
    ASSERT_STREQ(eventStatistic.ConvertPointerActionToString(pointerEvent), "pinch-update");
    pointerEvent->ClearAxisValue();
}

/**
 * @tc.name: EventDumpTest_ConvertPointerActionToString_003
 * @tc.desc: Event dump ConvertPointerActionToString_003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_ConvertPointerActionToString_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->bitwise_ = 0x000040;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, 0);
    ASSERT_STREQ(eventStatistic.ConvertPointerActionToString(pointerEvent), "axis-end");
    pointerEvent->ClearAxisValue();

    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, 0);
    ASSERT_STREQ(eventStatistic.ConvertPointerActionToString(pointerEvent), "axis-end");
    pointerEvent->ClearAxisValue();

    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, 0);
    ASSERT_STREQ(eventStatistic.ConvertPointerActionToString(pointerEvent), "pinch-end");
    pointerEvent->ClearAxisValue();
}

/**
 * @tc.name: EventDumpTest_ConvertPointerActionToString_004
 * @tc.desc: Event dump ConvertPointerActionToString_004
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_ConvertPointerActionToString_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->bitwise_ = 0x000040;
    pointerEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_SWIPE_UP);
    ASSERT_STREQ(eventStatistic.ConvertPointerActionToString(pointerEvent), "touch-swipe-up");
}

/**
 * @tc.name: EventDumpTest_ConvertKeyActionToString
 * @tc.desc: Event dump ConvertKeyActionToString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_ConvertKeyActionToString, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    ASSERT_STREQ(eventStatistic.ConvertKeyActionToString(KeyEvent::KEY_ACTION_CANCEL), "key_action_cancel");

    ASSERT_STREQ(eventStatistic.ConvertKeyActionToString(KeyEvent::INTENTION_UNKNOWN), "unknown");
}

/**
 * @tc.name: EventDumpTest_ConvertSwitchTypeToString
 * @tc.desc: Event dump ConvertSwitchTypeToString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_ConvertSwitchTypeToString, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    int32_t switchType = SwitchEvent::SWITCH_DEFAULT;
    ASSERT_STREQ(eventStatistic.ConvertSwitchTypeToString(switchType), "switch_default");

    switchType = SwitchEvent::SWITCH_LID;
    ASSERT_STREQ(eventStatistic.ConvertSwitchTypeToString(switchType), "switch_lid");

    switchType = SwitchEvent::SWITCH_TABLET;
    ASSERT_STREQ(eventStatistic.ConvertSwitchTypeToString(switchType), "switch_tablet");

    switchType = SwitchEvent::SWITCH_PRIVACY;
    ASSERT_STREQ(eventStatistic.ConvertSwitchTypeToString(switchType), "switch_privacy");

    switchType = -1;
    ASSERT_STREQ(eventStatistic.ConvertSwitchTypeToString(switchType), "unknown");
}

/**
 * @tc.name: EventDumpTest_PushPointerRecord
 * @tc.desc: Event dump PushPointerRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushPointerRecord, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    auto pointerEvent = PointerEvent::Create();
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetPressure(0);
    pointerItem.SetTiltX(0);
    pointerItem.SetTiltY(0);
    pointerEvent->AddPointerItem(pointerItem);
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushPointerRecord(pointerEvent));
    for (auto i = 0; i <= POINTER_RECORD_MAX_SIZE; ++i) {
        auto pointerEvent = PointerEvent::Create();
        eventStatistic.PushPointerRecord(pointerEvent);
    }
    EXPECT_EQ(eventStatistic.pointerRecordDeque_.size(), POINTER_RECORD_MAX_SIZE);
}

/**
 * @tc.name: EventDumpTest_QueryPointerRecord_001
 * @tc.desc: Event dump QueryPointerRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_QueryPointerRecord_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    int32_t count = -1;
    std::vector<std::shared_ptr<PointerEvent>> pointerList;
    eventStatistic.pointerRecordDeque_.clear();
    EXPECT_EQ(eventStatistic.QueryPointerRecord(count, pointerList), RET_OK);
}

/**
 * @tc.name: EventDumpTest_QueryPointerRecord_002
 * @tc.desc: Event dump QueryPointerRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_QueryPointerRecord_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    int32_t count = 0;
    std::vector<std::shared_ptr<PointerEvent>> pointerList;
    auto pointerEvent = PointerEvent::Create();
    eventStatistic.PushPointerRecord(pointerEvent);
    EXPECT_EQ(eventStatistic.QueryPointerRecord(count, pointerList), RET_OK);
}

/**
 * @tc.name: EventDumpTest_QueryPointerRecord_003
 * @tc.desc: Event dump QueryPointerRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_QueryPointerRecord_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    int32_t count = 30;
    std::vector<std::shared_ptr<PointerEvent>> pointerList;
    eventStatistic.pointerRecordDeque_.clear();
    EXPECT_EQ(eventStatistic.QueryPointerRecord(count, pointerList), RET_OK);
}

/**
 * @tc.name: EventDumpTest_QueryPointerRecord_004
 * @tc.desc: Event dump QueryPointerRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_QueryPointerRecord_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    int32_t count = 100;
    std::vector<std::shared_ptr<PointerEvent>> pointerList;
    auto pointerEvent = PointerEvent::Create();
    eventStatistic.PushPointerRecord(pointerEvent);
    EXPECT_EQ(eventStatistic.QueryPointerRecord(count, pointerList), RET_OK);
}

/**
 * @tc.name: EventDumpTest_QueryPointerRecord_005
 * @tc.desc: Event dump QueryPointerRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_QueryPointerRecord_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    int32_t count = 101;
    std::vector<std::shared_ptr<PointerEvent>> pointerList;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);
    eventStatistic.PushPointerRecord(pointerEvent);
    EXPECT_EQ(eventStatistic.QueryPointerRecord(count, pointerList), RET_OK);
}

/**
 * @tc.name: EventStatisticTest_PushPointerEvent_001
 * @tc.desc: Verify PushPointerEvent with nullptr eventPtr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushPointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    std::shared_ptr<PointerEvent> nullEvent = nullptr;
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushPointerEvent(nullEvent));
}

/**
 * @tc.name: EventStatisticTest_PushPointerEvent_002
 * @tc.desc: Verify PushPointerEvent with pointerAction that should be filtered (POINTER_ACTION_MOVE)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushPointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetAction(PointerEvent::POINTER_ACTION_MOVE);
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushPointerEvent(pointerEvent));
}

/**
 * @tc.name: EventStatisticTest_PushPointerEvent_003
 * @tc.desc: Verify PushPointerEvent with privacy mode flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushPointerEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE);
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushPointerEvent(pointerEvent));
}

/**
 * @tc.name: EventStatisticTest_PushPointerEvent_004
 * @tc.desc: Verify PushPointerEvent with multiple pointer items and pressed buttons
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushPointerEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetAction(PointerEvent::POINTER_ACTION_DOWN);
    PointerEvent::PointerItem item1;
    item1.SetDisplayX(10);
    item1.SetDisplayY(20);
    item1.SetPressure(1.0f);
    pointerEvent->AddPointerItem(item1);
    PointerEvent::PointerItem item2;
    item2.SetDisplayX(30);
    item2.SetDisplayY(40);
    item2.SetPressure(0.5f);
    pointerEvent->AddPointerItem(item2);
    pointerEvent->SetPressedKeys({1, 2});
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushPointerEvent(pointerEvent));
}

/**
 * @tc.name: EventStatisticTest_PushPointerEvent_005
 * @tc.desc: Verify PushPointerEvent with SOURCE_TYPE_TOUCHSCREEN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushPointerEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushPointerEvent(pointerEvent));
}

/**
 * @tc.name: EventStatisticTest_PushKeyEvent_001
 * @tc.desc: Verify PushKeyEvent with nullptr eventPtr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    std::shared_ptr<KeyEvent> nullKeyEvent = nullptr;
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushKeyEvent(nullKeyEvent));
}

/**
 * @tc.name: EventStatisticTest_PushKeyEvent_002
 * @tc.desc: Verify PushKeyEvent with KEY_ACTION_DOWN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(65); // 'A'
    keyEvent->bitwise_ = 0x000040;
    KeyEvent::KeyItem keyItem;
    keyItem.SetDeviceId(1);
    keyItem.SetKeyCode(65);
    keyItem.SetDownTime(100);
    keyItem.SetUnicode(65);
    keyItem.SetPressed(true);
    keyEvent->AddKeyItem(keyItem);
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushKeyEvent(keyEvent));
}

/**
 * @tc.name: EventStatisticTest_PushKeyEvent_003
 * @tc.desc: Verify PushKeyEvent with privacy mode flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushKeyEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE); // 隐私模式
    keyEvent->SetKeyCode(66); // 'B'
    KeyEvent::KeyItem keyItem;
    keyItem.SetDeviceId(2);
    keyItem.SetKeyCode(66);
    keyItem.SetDownTime(200);
    keyItem.SetUnicode(66);
    keyItem.SetPressed(false);
    keyEvent->AddKeyItem(keyItem);
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushKeyEvent(keyEvent));
}

/**
 * @tc.name: EventStatisticTest_PushKeyEvent_004
 * @tc.desc: Verify PushKeyEvent with KEY_ACTION_UP and multiple key items
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushKeyEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetKeyCode(67); // 'C'
    KeyEvent::KeyItem keyItem1;
    keyItem1.SetDeviceId(1);
    keyItem1.SetKeyCode(67);
    keyItem1.SetDownTime(300);
    keyItem1.SetUnicode(67);
    keyItem1.SetPressed(true);
    keyEvent->AddKeyItem(keyItem1);
    KeyEvent::KeyItem keyItem2;
    keyItem2.SetDeviceId(2);
    keyItem2.SetKeyCode(68);
    keyItem2.SetDownTime(400);
    keyItem2.SetUnicode(68);
    keyItem2.SetPressed(false);
    keyEvent->AddKeyItem(keyItem2);
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushKeyEvent(keyEvent));
}

/**
 * @tc.name: EventStatisticTest_QueryPointerRecord_006
 * @tc.desc: Verify QueryPointerRecord with multiple pointer items
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_QueryPointerRecord_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    std::vector<std::shared_ptr<PointerEvent>> pointerList;

    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetActionTime(123456);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    PointerEvent::PointerItem item1;
    item1.SetPressure(1.0f);
    item1.SetTiltX(10.0f);
    item1.SetTiltY(30.0f);
    pointerEvent->AddPointerItem(item1);
    PointerEvent::PointerItem item2;
    item2.SetPressure(0.5f);
    item2.SetTiltX(20.0f);
    item2.SetTiltY(40.0f);
    pointerEvent->AddPointerItem(item2);
    eventStatistic.PushPointerRecord(pointerEvent);
    EXPECT_EQ(eventStatistic.QueryPointerRecord(1, pointerList), RET_OK);
    EXPECT_EQ(pointerList.size(), 1u);
    EXPECT_EQ(pointerList[0]->GetAllPointerItems().size(), 1u);
}

/**
 * @tc.name: EventStatisticTest_QueryPointerRecord_007
 * @tc.desc: Verify QueryPointerRecord with simulate flag (EVENT_FLAG_SIMULATE)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_QueryPointerRecord_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    std::vector<std::shared_ptr<PointerEvent>> pointerList;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetActionTime(987654);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);
    PointerEvent::PointerItem item;
    item.SetPressure(0.8f);
    item.SetTiltX(15.0f);
    item.SetTiltY(25.0f);
    pointerEvent->AddPointerItem(item);
    eventStatistic.PushPointerRecord(pointerEvent);
    EXPECT_EQ(eventStatistic.QueryPointerRecord(1, pointerList), RET_OK);
    EXPECT_EQ(pointerList.size(), 1u);
    EXPECT_TRUE(pointerList[0]->HasFlag(InputEvent::EVENT_FLAG_SIMULATE));
}

/**
 * @tc.name: EventStatisticTest_QueryPointerRecord_008
 * @tc.desc: Verify QueryPointerRecord when count exceeds pointerRecordDeque_ size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_QueryPointerRecord_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    eventStatistic.pointerRecordDeque_.clear();
    std::vector<std::shared_ptr<PointerEvent>> pointerList;
    for (int i = 0; i < 3; i++) {
        auto pointerEvent = PointerEvent::Create();
        pointerEvent->SetAction(PointerEvent::POINTER_ACTION_DOWN);
        eventStatistic.PushPointerRecord(pointerEvent);
    }
    EXPECT_EQ(eventStatistic.QueryPointerRecord(10, pointerList), RET_OK);
    EXPECT_EQ(pointerList.size(), 3u);
}

/**
 * @tc.name: EventStatisticTest_QueryPointerRecord_009
 * @tc.desc: Verify QueryPointerRecord with zero count (should return RET_OK and not crash)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_QueryPointerRecord_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    std::vector<std::shared_ptr<PointerEvent>> pointerList;
    auto pointerEvent = PointerEvent::Create();
    eventStatistic.PushPointerRecord(pointerEvent);
    EXPECT_EQ(eventStatistic.QueryPointerRecord(0, pointerList), RET_OK);
    EXPECT_TRUE(pointerList.empty());
}

/**
 * @tc.name: EventStatisticTest_PopEvent_001
 * @tc.desc: Verify PopEvent returns the correct event string when queue is not empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PopEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    {
        std::lock_guard<std::mutex> lock(eventStatistic.queueMutex_);
        while (!eventStatistic.eventQueue_.empty()) {
            eventStatistic.eventQueue_.pop();
        }
        eventStatistic.eventQueue_.push("TestEvent1");
        eventStatistic.queueCondition_.notify_one();
    }
    std::string eventStr = eventStatistic.PopEvent();
    EXPECT_EQ(eventStr, "TestEvent1");
}

/**
 * @tc.name: EventStatisticTest_PopEvent_002
 * @tc.desc: Verify PopEvent blocks until eventQueue_ is filled (using thread).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PopEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    {
        std::lock_guard<std::mutex> lock(eventStatistic.queueMutex_);
        while (!eventStatistic.eventQueue_.empty()) {
            eventStatistic.eventQueue_.pop();
        }
    }
    std::thread producer([&eventStatistic]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::lock_guard<std::mutex> lock(eventStatistic.queueMutex_);
        eventStatistic.eventQueue_.push("DelayedEvent");
        eventStatistic.queueCondition_.notify_one();
    });
    std::string result = eventStatistic.PopEvent();
    producer.join();
    EXPECT_EQ(result, "DelayedEvent");
}

/**
 * @tc.name: EventStatisticTest_WriteEventFile_001
 * @tc.desc: Verify WriteEventFile writes event string into the file
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_WriteEventFile_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    {
        std::lock_guard<std::mutex> lock(eventStatistic.queueMutex_);
        while (!eventStatistic.eventQueue_.empty()) {
            eventStatistic.eventQueue_.pop();
        }
    }
    unlink(EVENT_FILE_NAME);
    unlink(EVENT_FILE_NAME_HISTORY);
    {
        std::lock_guard<std::mutex> lock(eventStatistic.queueMutex_);
        eventStatistic.eventQueue_.push("TestEventFile");
        eventStatistic.queueCondition_.notify_one();
    }
    eventStatistic.writeFileEnabled_ = true;
    std::thread writer([&eventStatistic]() {
        eventStatistic.WriteEventFile();
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    eventStatistic.writeFileEnabled_ = false;
    {
        std::lock_guard<std::mutex> lock(eventStatistic.queueMutex_);
        eventStatistic.eventQueue_.push("Exit");
        eventStatistic.queueCondition_.notify_one();
    }
    writer.join();
    std::ifstream file(EVENT_FILE_NAME);
    ASSERT_TRUE(file.is_open());
    std::string content;
    std::getline(file, content);
    file.close();
    EXPECT_EQ(content, "TestEventFile");
    unlink(EVENT_FILE_NAME);
    unlink(EVENT_FILE_NAME_HISTORY);
}

/**
 * @tc.name: EventStatisticTest_WriteEventFile_002
 * @tc.desc: Verify WriteEventFile rotates file when file exceeds FILE_MAX_SIZE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_WriteEventFile_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    {
        std::ofstream bigFile(EVENT_FILE_NAME);
        bigFile << std::string(FILE_MAX_SIZE + 10, 'X');
        bigFile.close();
    }
    {
        std::lock_guard<std::mutex> lock(eventStatistic.queueMutex_);
        eventStatistic.eventQueue_.push("RotateEvent");
        eventStatistic.queueCondition_.notify_one();
    }
    eventStatistic.writeFileEnabled_ = true;
    std::thread writer([&eventStatistic]() {
        eventStatistic.WriteEventFile();
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    eventStatistic.writeFileEnabled_ = false;
    {
        std::lock_guard<std::mutex> lock(eventStatistic.queueMutex_);
        eventStatistic.eventQueue_.push("Exit");
        eventStatistic.queueCondition_.notify_one();
    }
    writer.join();
    EXPECT_EQ(access(EVENT_FILE_NAME_HISTORY, F_OK), 0);
    unlink(EVENT_FILE_NAME);
    unlink(EVENT_FILE_NAME_HISTORY);
}
} // OHOS
} // MMI