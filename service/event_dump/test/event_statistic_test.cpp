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
 * @tc.name: EventDumpTest_PopEvent
 * @tc.desc: Event dump PopEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PopEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    auto inputEvent = std::make_shared<InputEvent>(3);
    eventStatistic.writeFileEnabled_ = true;
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushEvent(inputEvent));
    std::string str = "";
    str = eventStatistic.PopEvent();
    ASSERT_TRUE(!str.empty());
}
} // OHOS
} // MMI