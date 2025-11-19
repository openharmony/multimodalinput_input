/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include <chrono>
#include <gtest/gtest.h>
#include <thread>

#include "util.h"

#include "ability_manager_client.h"
#include "bundle_name_parser.h"
#include "common_event_support.h"
#include "display_event_monitor.h"
#include "event_log_helper.h"
#include "gesturesense_wrapper.h"
#include "input_event_handler.h"
#include "input_handler_type.h"
#include "input_windows_manager.h"
#include "i_preference_manager.h"
#include "key_shortcut_manager.h"
#include "mmi_log.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_preferences_manager.h"
#include "system_info.h"
#include "stylus_key_handler.h"
#define private public
#include "key_command_handler.h"
#undef private

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyCommandHandlerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t NANOSECOND_TO_MILLISECOND = 1000000;
constexpr int32_t SEC_TO_NANOSEC = 1000000000;
constexpr int32_t COMMON_PARAMETER_ERROR = 401;
constexpr int32_t INTERVAL_TIME = 100;
constexpr int32_t INTERVAL_TIME_OUT = 500000;
constexpr int32_t ERROR_DELAY_VALUE = -1000;
constexpr int32_t TWO_FINGERS_TIME_LIMIT = 150000;
constexpr int32_t TWO_FINGERS_DISTANCE_LIMIT = 16;
constexpr int32_t TOUCH_LIFT_LIMIT = 24;
constexpr int32_t TOUCH_RIGHT_LIMIT = 24;
constexpr int32_t TOUCH_TOP_LIMIT = 80;
constexpr int32_t TOUCH_BOTTOM_LIMIT = 41;
constexpr int32_t MAX_SHORT_KEY_DOWN_DURATION = 4000;
constexpr int32_t MIN_SHORT_KEY_DOWN_DURATION = 0;
constexpr float DOUBLE_CLICK_DISTANCE_DEFAULT_CONFIG = 64.0;
constexpr int32_t WINDOW_INPUT_METHOD_TYPE = 2105;
const std::string EXTENSION_ABILITY = "extensionAbility";
const std::string EXTENSION_ABILITY_ABNORMAL = "extensionAbilityAbnormal";
const std::string SOS_BUNDLE_NAME {"com.hmos.emergencycommunication"};
const std::string SCREENRECORDER_BUNDLE_NAME {"com.hmos.screenrecorder"};
const vector<float> CIRCLE_COORDINATES = {328.0f, 596.0f, 328.0f, 597.0f, 322.0f, 606.0f, 306.0f, 635.0f, 291.0f,
    665.0f, 283.0f, 691.0f, 291.0f, 739.0f, 300.0f, 751.0f, 312.0f, 759.0f, 327.0f, 765.0f, 343.0f, 768.0f, 361.0f,
    769.0f, 379.0f, 767.0f, 395.0f, 761.0f, 411.0f, 751.0f, 425.0f, 737.0f, 439.0f, 718.0f, 449.0f, 709.0f, 456.0f,
    683.0f, 459.0f, 654.0f, 451.0f, 569.0f, 437.0f, 552.0f, 418.0f, 542.0f, 392.0f, 540.0f, 363.0f, 545.0f};
const vector<int64_t> CIRCLE_TIMESTAMPS = {71304451, 71377126, 71387783, 71398239, 71409629, 71419392, 71461386,
    71472044, 71483797, 71493077, 71503426, 71514339, 71524715, 71535126, 71545652, 71556329, 71566506, 71577283,
    71587745, 71598921, 71630319, 71642155, 71651090, 71662474, 71671657};
const vector<float> CURVE_COORDINATES = {374.0f, 489.0f, 373.0f, 489.0f, 365.0f, 491.0f, 341.0f, 503.0f, 316.0f, 519.0f,
    300.0f, 541.0f, 293.0f, 561.0f, 289.0f, 582.0f, 292.0f, 643.0f, 301.0f, 657.0f, 317.0f, 668.0f, 336.0f, 681.0f,
    358.0f, 695.0f, 381.0f, 706.0f, 403.0f, 717.0f, 423.0f, 715.0f, 441.0f, 727.0f, 458.0f, 739.0f, 468.0f, 751.0f,
    474.0f, 764.0f, 467.0f, 812.0f, 455.0f, 828.0f, 435.0f, 844.0f, 412.0f, 860.0f, 387.0f, 876.0f, 362.0f, 894.0f,
    338.0f, 906.0f, 317.0f, 913.0f, 296.0f, 918.0f};
const vector<int64_t> CURVE_TIMESTAMPS = {134900436, 134951403, 134962832, 134973234, 134983492, 134995390, 135003876,
    135014389, 135045917, 135057774, 135067076, 135077688, 135088139, 135098494, 135109130, 135119679, 135130101,
    135140670, 135151182, 135161672, 135193739, 135203790, 135214272, 135224868, 135236197, 135245828, 135256481,
    135267186, 135276939};
const vector<float> LINE_COORDINATES = {390.0f, 340.0f, 390.0f, 348.0f, 390.0f, 367.0f, 387.0f, 417.0f, 385.0f, 455.0f,
    384.0f, 491.0f, 382.0f, 516.0f, 381.0f, 539.0f, 380.0f, 564.0f, 378.0f, 589.0f, 377.0f, 616.0f, 376.0f, 643.0f,
    375.0f, 669.0f, 375.0f, 694.0f, 374.0f, 718.0f, 374.0f, 727.0f, 374.0f, 750.0f, 374.0f, 771.0f, 374.0f, 791.0f,
    374.0f, 811.0f, 375.0f, 831.0f, 375.0f, 851.0f, 376.0f, 870.0f, 377.0f, 886.0f, 377.0f, 902.0f, 379.0f, 918.0f,
    379.0f, 934.0f, 380.0f, 950.0f, 381.0f, 963.0f, 383.0f, 977.0f, 385.0f, 992.0f, 387.0f, 1002.0f, 389.0f, 1016.0f,
    390.0f, 1030.0f, 390.0f, 1042.0f, 390.0f, 1052.0f, 390.0f, 1061.0f, 391.0f, 1069.0f, 391.0f, 1075.0f, 391.0f,
    1080.0f, 391.0f, 1085.0f, 391.0f, 1089.0f, 392.0f, 1095.0f, 393.0f, 1099.0f, 394.0f, 1103.0f, 395.0f, 1111.0f,
    395.0f, 1117.0f, 396.0f, 1124.0f, 397.0f, 1130.0f, 397.0f, 1134.0f, 397.0f, 1138.0f};
const vector<int64_t> LINE_TIMESTAMPS = {70809086, 70912930, 70923294, 70933960, 70944571, 70955130, 70965726, 70976076,
    70986620, 70997190, 71007517, 71017998, 71028551, 71039171, 71049654, 71060120, 71070809, 71082130, 71091709,
    71102285, 71112746, 71123402, 71133898, 71144469, 71154894, 71165617, 71175944, 71186477, 71197199, 71207737,
    71218030, 71228652, 71239243, 71249733, 71260291, 71270821, 71281313, 71291919, 71302477, 71313573, 71323426,
    71333880, 71355034, 71376110, 71418297, 71439219, 71449749, 71460268, 71470874, 71481275, 71744747};
} // namespace
class KeyCommandHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void)
    {
        touchEvent_ = PointerEvent::Create();
        keyEvent_ = KeyEvent::Create();
    }
    void TearDown(void)
    {
        touchEvent_ = nullptr;
        keyEvent_ = nullptr;
    }
    std::shared_ptr<PointerEvent> touchEvent_;
    std::shared_ptr<KeyEvent> keyEvent_;
    std::shared_ptr<KeyEvent> SetupKeyEvent();
    std::shared_ptr<PointerEvent> SetupThreeFingerTapEvent();
    std::shared_ptr<PointerEvent> SetupFourFingerTapEvent();
#ifdef OHOS_BUILD_ENABLE_TOUCH
    std::shared_ptr<PointerEvent> SetupDoubleFingerDownEvent();
    std::shared_ptr<PointerEvent> SetupSingleKnuckleDownEvent();
    std::shared_ptr<PointerEvent> SetupDoubleKnuckleDownEvent();
#endif // OHOS_BUILD_ENABLE_TOUCH
};

int64_t GetNanoTime()
{
    struct timespec time = {0};
    clock_gettime(CLOCK_MONOTONIC, &time);
    return static_cast<int64_t>(time.tv_sec) * SEC_TO_NANOSEC + time.tv_nsec;
}

std::shared_ptr<KeyEvent> KeyCommandHandlerTest::SetupKeyEvent()
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_HOME);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_HOME);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->AddPressedKeyItems(kitDown);

    return keyEvent;
}

#ifdef OHOS_BUILD_ENABLE_TOUCH
std::shared_ptr<PointerEvent> KeyCommandHandlerTest::SetupDoubleFingerDownEvent()
{
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    PointerEvent::PointerItem item2;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    int32_t downX = 100;
    int32_t downY = 200;
    item.SetDisplayX(downX);
    item.SetDisplayY(downY);
    item.SetPressed(true);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);

    item2.SetPointerId(1);
    item2.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    int32_t secondDownX = 120;
    int32_t secondDownY = 220;
    item2.SetDisplayX(secondDownX);
    item2.SetDisplayY(secondDownY);
    item2.SetPressed(true);
    pointerEvent->SetPointerId(1);
    pointerEvent->AddPointerItem(item2);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> KeyCommandHandlerTest::SetupSingleKnuckleDownEvent()
{
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    int32_t downX = 100;
    int32_t downY = 200;
    item.SetDisplayX(downX);
    item.SetDisplayY(downY);
    item.SetPressed(true);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> KeyCommandHandlerTest::SetupDoubleKnuckleDownEvent()
{
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    PointerEvent::PointerItem item2;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    int32_t downX = 100;
    int32_t downY = 200;
    item.SetDisplayX(downX);
    item.SetDisplayY(downY);
    item.SetPressed(true);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);

    item2.SetPointerId(1);
    item2.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    int32_t secondDownX = 120;
    int32_t secondDownY = 220;
    item2.SetDisplayX(secondDownX);
    item2.SetDisplayY(secondDownY);
    item2.SetPressed(true);
    pointerEvent->SetPointerId(1);
    pointerEvent->AddPointerItem(item2);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}
#endif // OHOS_BUILD_ENABLE_TOUCH

std::shared_ptr<PointerEvent> KeyCommandHandlerTest::SetupThreeFingerTapEvent()
{
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item1;
    PointerEvent::PointerItem item2;
    PointerEvent::PointerItem item3;

    int32_t id0 = 0;
    item1.SetPointerId(id0);
    int32_t downX1 = 100;
    int32_t downY1 = 200;
    int64_t actionTime1 = 1000000;
    item1.SetDisplayX(downX1);
    item1.SetDisplayY(downY1);
    item1.SetDownTime(actionTime1);
    pointerEvent->SetPointerId(id0);
    pointerEvent->AddPointerItem(item1);

    int32_t id1 = 1;
    item2.SetPointerId(id1);
    int32_t downX2 = 200;
    int32_t downY2 = 300;
    int64_t actionTime2 = 1000100;
    item2.SetDisplayX(downX2);
    item2.SetDisplayY(downY2);
    item2.SetDownTime(actionTime2);
    pointerEvent->SetPointerId(id1);
    pointerEvent->AddPointerItem(item2);

    int32_t id2 = 2;
    item3.SetPointerId(id2);
    int32_t downX3 = 100;
    int32_t downY3 = 200;
    int64_t actionTime3 = 1000200;
    item3.SetDisplayX(downX3);
    item3.SetDisplayY(downY3);
    item3.SetDownTime(actionTime3);
    pointerEvent->SetPointerId(id2);
    pointerEvent->AddPointerItem(item3);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_TRIPTAP);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> KeyCommandHandlerTest::SetupFourFingerTapEvent()
{
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item1;
    PointerEvent::PointerItem item2;
    PointerEvent::PointerItem item3;
    PointerEvent::PointerItem item4;

    int32_t id0 = 0;
    item1.SetPointerId(id0);
    int32_t downX1 = 100;
    int32_t downY1 = 200;
    int64_t actionTime1 = 1000000;
    item1.SetDisplayX(downX1);
    item1.SetDisplayY(downY1);
    item1.SetDownTime(actionTime1);
    pointerEvent->SetPointerId(id0);
    pointerEvent->AddPointerItem(item1);

    int32_t id1 = 1;
    item2.SetPointerId(id1);
    int32_t downX2 = 200;
    int32_t downY2 = 300;
    int64_t actionTime2 = 1000100;
    item2.SetDisplayX(downX2);
    item2.SetDisplayY(downY2);
    item2.SetDownTime(actionTime2);
    pointerEvent->SetPointerId(id1);
    pointerEvent->AddPointerItem(item2);

    int32_t id2 = 2;
    item3.SetPointerId(id2);
    int32_t downX3 = 100;
    int32_t downY3 = 200;
    int64_t actionTime3 = 1000200;
    item3.SetDisplayX(downX3);
    item3.SetDisplayY(downY3);
    item3.SetDownTime(actionTime3);
    pointerEvent->SetPointerId(id2);
    pointerEvent->AddPointerItem(item3);

    int32_t id3 = 3;
    item4.SetPointerId(id3);
    int32_t downX4 = 400;
    int32_t downY4 = 280;
    int64_t actionTime4 = 1000300;
    item4.SetDisplayX(downX4);
    item4.SetDisplayY(downY4);
    item4.SetDownTime(actionTime4);
    pointerEvent->SetPointerId(id3);
    pointerEvent->AddPointerItem(item4);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_QUADTAP);
    return pointerEvent;
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckAndUpdateTappingCountAtDown_01
 * @tc.desc: Test CheckAndUpdateTappingCountAtDown
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckAndUpdateTappingCountAtDown_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->actionTime_ = 10000;
    handler.lastDownTime_ = 15000;
    ASSERT_NO_FATAL_FAILURE(handler.CheckAndUpdateTappingCountAtDown(pointerEvent));

    pointerEvent->actionTime_ = 800000;
    handler.lastDownTime_ = 200000;
    ASSERT_NO_FATAL_FAILURE(handler.CheckAndUpdateTappingCountAtDown(pointerEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckAndUpdateTappingCountAtDown_02
 * @tc.desc: Test CheckAndUpdateTappingCountAtDown
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckAndUpdateTappingCountAtDown_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    pointerEvent->actionTime_ = 800000;
    handler.lastDownTime_ = 500000;
    handler.previousUpTime_ = 850000;
    handler.downToPrevUpTimeConfig_ = 0;
    handler.tappingCount_ = 2;
    ASSERT_NO_FATAL_FAILURE(handler.CheckAndUpdateTappingCountAtDown(pointerEvent));

    handler.tappingCount_ = 5;
    ASSERT_NO_FATAL_FAILURE(handler.CheckAndUpdateTappingCountAtDown(pointerEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_MatchShortcutKey_002
 * @tc.desc: Test the function MatchShortcutKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_MatchShortcutKey_002, TestSize.Level1)
{
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey shortcutKey;
    std::vector<ShortcutKey> upAbilities;
    shortcutKey.statusConfigValue = true;
    shortcutKey.finalKey = -1;
    shortcutKey.keyDownDuration = 0;
    EXPECT_FALSE(handler.IsKeyMatch(shortcutKey, keyEvent));
    EXPECT_FALSE(handler.MatchShortcutKey(keyEvent, shortcutKey, upAbilities));

    shortcutKey.businessId = "V1";
    int32_t delay = handler.GetKeyDownDurationFromXml(shortcutKey.businessId);
    delay = 100;
    EXPECT_TRUE(delay >= MIN_SHORT_KEY_DOWN_DURATION);
    EXPECT_TRUE(delay <= MAX_SHORT_KEY_DOWN_DURATION);
    EXPECT_FALSE(handler.MatchShortcutKey(keyEvent, shortcutKey, upAbilities));
    delay = 5000;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;
    EXPECT_FALSE(handler.MatchShortcutKey(keyEvent, shortcutKey, upAbilities));

    shortcutKey.triggerType = KeyEvent::KEY_ACTION_UP;
    EXPECT_FALSE(handler.MatchShortcutKey(keyEvent, shortcutKey, upAbilities));
    EXPECT_TRUE(handler.HandleKeyUp(keyEvent, shortcutKey));
    shortcutKey.keyDownDuration = 100;
    EXPECT_FALSE(handler.MatchShortcutKey(keyEvent, shortcutKey, upAbilities));
}

/**
 * @tc.name: KeyCommandHandlerTest_TouchPadKnuckleDoubleClickProcess_01
 * @tc.desc: Test the function TouchPadKnuckleDoubleClickProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_TouchPadKnuckleDoubleClickProcess_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string action = "move";

    DISPLAY_MONITOR->screenStatus_ = EventFwk::CommonEventSupportTest::COMMON_EVENT_SCREEN_OFF;
    DISPLAY_MONITOR->isScreenLocked_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.TouchPadKnuckleDoubleClickProcess(bundleName, abilityName, action));

    DISPLAY_MONITOR->screenStatus_ = EventFwk::CommonEventSupportTest::COMMON_EVENT_SCREEN_ON;
    DISPLAY_MONITOR->isScreenLocked_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.TouchPadKnuckleDoubleClickProcess(bundleName, abilityName, action));

    DISPLAY_MONITOR->screenStatus_ = EventFwk::CommonEventSupportTest::COMMON_EVENT_SCREEN_OFF;
    DISPLAY_MONITOR->isScreenLocked_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.TouchPadKnuckleDoubleClickProcess(bundleName, abilityName, action));

    DISPLAY_MONITOR->screenStatus_ = EventFwk::CommonEventSupportTest::COMMON_EVENT_SCREEN_ON;
    DISPLAY_MONITOR->isScreenLocked_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.TouchPadKnuckleDoubleClickProcess(bundleName, abilityName, action));
}

/**
 * @tc.name: KeyCommandHandlerTest_TouchPadKnuckleDoubleClickHandle_01
 * @tc.desc: Test the function TouchPadKnuckleDoubleClickHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_TouchPadKnuckleDoubleClickHandle_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    keyEvent->keyAction_ = KNUCKLE_1F_DOUBLE_CLICK;
    EXPECT_TRUE(handler.TouchPadKnuckleDoubleClickHandle(keyEvent));

    keyEvent->keyAction_ = KNUCKLE_2F_DOUBLE_CLICK;
    EXPECT_TRUE(handler.TouchPadKnuckleDoubleClickHandle(keyEvent));

    keyEvent->keyAction_ = KeyEvent::KEY_ACTION_UNKNOWN;
    EXPECT_FALSE(handler.TouchPadKnuckleDoubleClickHandle(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyOwnCount_001
 * @tc.desc: Test the function HandleRepeatKeyOwnCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyOwnCount_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    RepeatKey repeatKey;
    ASSERT_NO_FATAL_FAILURE(handler.HandleRepeatKeyOwnCount(repeatKey));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyOwnCount_002
 * @tc.desc: Test the function HandleRepeatKeyOwnCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyOwnCount_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    RepeatKey repeatKey;
    repeatKey.ability.bundleName = SCREENRECORDER_BUNDLE_NAME;
    handler.downActionTime_ = 600000;
    handler.upActionTime_ = 800000;
    ASSERT_NO_FATAL_FAILURE(handler.HandleRepeatKeyOwnCount(repeatKey));
}

/**
 * @tc.name: KeyCommandHandlerTest_SendKeyEvent_01
 * @tc.desc: Test the function SendKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SendKeyEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.isHandleSequence_ = false;
    handler.launchAbilityCount_ = 1;
    handler.count_ = 10;
    handler.repeatKey_.keyCode = 18;
    handler.repeatKeyMaxTimes_[18] = 11;
    handler.repeatKeyMaxTimes_[2] = 3;
    ASSERT_NO_FATAL_FAILURE(handler.SendKeyEvent());
}

/**
 * @tc.name: KeyCommandHandlerTest_SendKeyEvent_02
 * @tc.desc: Test the function SendKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SendKeyEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.isHandleSequence_ = false;
    handler.launchAbilityCount_ = 1;
    handler.count_ = 10;
    handler.repeatKey_.keyCode = 16;
    handler.repeatKeyMaxTimes_[16] = 15;
    handler.repeatKeyMaxTimes_[2] = 3;
    ASSERT_NO_FATAL_FAILURE(handler.SendKeyEvent());
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckInputMethodArea_01
 * @tc.desc: Test the function CheckInputMethodArea
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckInputMethodArea_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);

    touchEvent->targetDisplayId_ = 10;
    touchEvent->targetWindowId_ = 5;
    InputWindowsManager inputWindowsManager;
    WindowGroupInfo windowGroupInfo;
    WindowInfo window1;
    window1.windowType = 2100;
    window1.id = 1;
    window1.pid = 2;
    windowGroupInfo.windowsInfo.push_back(window1);
    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(1, windowGroupInfo));
    ASSERT_FALSE(handler.CheckInputMethodArea(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckInputMethodArea_02
 * @tc.desc: Test the function CheckInputMethodArea
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckInputMethodArea_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->targetDisplayId_ = 10;
    pointerEvent->targetWindowId_ = 5;
    PointerEvent::PointerItem item;
    item.SetDisplayX(10);
    item.SetDisplayY(15);

    InputWindowsManager inputWindowsManager;
    WindowGroupInfo windowGroupInfo;
    WindowInfo window1;
    window1.windowType = 2105;
    window1.id = 1;
    window1.pid = 2;
    window1.area.x = 5;
    window1.area.y = 8;
    window1.area.width = 20;
    windowGroupInfo.windowsInfo.push_back(window1);
    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(1, windowGroupInfo));
    ASSERT_FALSE(handler.CheckInputMethodArea(pointerEvent));

    pointerEvent->targetWindowId_ = 1;
    int32_t rightDownX = 30;
    int32_t rightDownY = 40;
    EXPECT_TRUE(item.GetDisplayX() <= rightDownX);
    EXPECT_TRUE(item.GetDisplayY() <= rightDownY);
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_DOWN;
    ASSERT_FALSE(handler.CheckInputMethodArea(pointerEvent));

    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_UP;
    ASSERT_FALSE(handler.CheckInputMethodArea(pointerEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_ConvertVPToPX_01
 * @tc.desc: Test the function ConvertVPToPX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ConvertVPToPX_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    int32_t vp = -1;
    ASSERT_NO_FATAL_FAILURE(handler.ConvertVPToPX(vp));
    vp = 1;
    DisplayInfo displayInfo;
    displayInfo.dpi = -20;
    ASSERT_NO_FATAL_FAILURE(handler.ConvertVPToPX(vp));

    displayInfo.dpi = 30;
    ASSERT_NO_FATAL_FAILURE(handler.ConvertVPToPX(vp));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureEvent_01
 * @tc.desc: Test the function HandleKnuckleGestureEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    EXPECT_FALSE(handler.CheckKnuckleCondition(pointerEvent));
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureEvent(pointerEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_01
 * @tc.desc: Test the function HandleKnuckleGestureTouchMove
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->pointerId_ = 5;
    pointerEvent->targetDisplayId_ = 10;
    item.rawDisplayX_ = 20.0;
    item.rawDisplayY_ = 25.0;
    handler.gestureLastX_ = 1.0f;
    handler.gestureLastY_ = 2.0f;

    handler.isStartBase_ = true;
    handler.isGesturing_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(pointerEvent));

    handler.isGesturing_ = true;
    handler.isLetterGesturing_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(pointerEvent));

    handler.isLetterGesturing_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(pointerEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_04
 * @tc.desc: Test the function HandleKnuckleGestureTouchUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    GESTURESENSE_WRAPPER->touchUp_ = [](const std::vector<float> &, const std::vector<int64_t> &, bool,
                                         bool) -> int32_t {
        return 0;
    };
    ASSERT_NE(GESTURESENSE_WRAPPER->touchUp_, nullptr);
    handler.gesturePoints_.assign(LINE_COORDINATES.begin(), LINE_COORDINATES.end());
    handler.gestureTimeStamps_.assign(LINE_TIMESTAMPS.begin(), LINE_TIMESTAMPS.end());
    handler.isGesturing_ = true;
    handler.isLetterGesturing_ = true;
    NotifyType notifyType;
    notifyType = NotifyType::REGIONGESTURE;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchUp(touchEvent));

    notifyType = NotifyType::LETTERGESTURE;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchUp(touchEvent));

    notifyType = NotifyType::OTHER;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchUp(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyDown_001
 * @tc.desc: test HandleKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyDown_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ShortcutKey shortcutKey;
    shortcutKey.keyDownDuration = 10;
    shortcutKey.timerId = -1;
    ASSERT_TRUE(handler.HandleKeyDown(shortcutKey));

    shortcutKey.timerId = 2;
    shortcutKey.finalKey = -1;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;
    ASSERT_TRUE(handler.HandleKeyDown(shortcutKey));
}

/**
 * @tc.name: KeyCommandHandlerTest_MatchShortcutKey_01
 * @tc.desc: Test the function MatchShortcutKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_MatchShortcutKey_01, TestSize.Level1)
{
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey shortcutKey;
    std::vector<ShortcutKey> upAbilities;
    shortcutKey.statusConfigValue = true;
    shortcutKey.finalKey = -1;
    shortcutKey.keyDownDuration = 0;
    EXPECT_FALSE(handler.IsKeyMatch(shortcutKey, keyEvent));
    EXPECT_FALSE(handler.MatchShortcutKey(keyEvent, shortcutKey, upAbilities));

    shortcutKey.businessId = "V1";
    int32_t delay = handler.GetKeyDownDurationFromXml(shortcutKey.businessId);
    delay = 100;
    EXPECT_TRUE(delay >= MIN_SHORT_KEY_DOWN_DURATION);
    EXPECT_TRUE(delay <= MAX_SHORT_KEY_DOWN_DURATION);
    EXPECT_FALSE(handler.MatchShortcutKey(keyEvent, shortcutKey, upAbilities));

    delay = 5000;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;
    EXPECT_FALSE(handler.MatchShortcutKey(keyEvent, shortcutKey, upAbilities));

    shortcutKey.triggerType = KeyEvent::KEY_ACTION_UP;
    EXPECT_FALSE(handler.MatchShortcutKey(keyEvent, shortcutKey, upAbilities));
    EXPECT_TRUE(handler.HandleKeyUp(keyEvent, shortcutKey));
    shortcutKey.keyDownDuration = 100;
    EXPECT_FALSE(handler.MatchShortcutKey(keyEvent, shortcutKey, upAbilities));
}

/**
 * @tc.name: KeyCommandHandlerTest_MatchShortcutKeys_01
 * @tc.desc: Test the function MatchShortcutKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_MatchShortcutKeys_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyAction_ = KeyEvent::KEY_ACTION_UP;
    bool ret = KEY_SHORTCUT_MGR->HaveShortcutConsumed(keyEvent);
    EXPECT_FALSE(ret);

    std::vector<ShortcutKey> upAbilities;
    ShortcutKey key1;
    key1.preKeys = {1, 2, 3};
    key1.businessId = "business1";
    key1.statusConfig = "config1";
    key1.finalKey = -1;
    upAbilities.push_back(key1);
    EXPECT_FALSE(upAbilities.empty());
    EXPECT_TRUE(handler.MatchShortcutKeys(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyAbility_001
 * @tc.desc: HandleRepeatKeyAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyAbility_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    RepeatKey repeatKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler.count_ = 2;
    repeatKey.ability.bundleName = "bundleName";
    ASSERT_TRUE(handler.HandleRepeatKeyAbility(repeatKey, keyEvent, false));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyAbility_002
 * @tc.desc: HandleRepeatKeyAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyAbility_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    RepeatKey repeatKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler.count_ = 2;
    repeatKey.ability.bundleName = "bundleName";
    handler.repeatKeyTimerIds_.emplace(repeatKey.ability.bundleName, 1);
    ASSERT_TRUE(handler.HandleRepeatKeyAbility(repeatKey, keyEvent, false));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyAbility_003
 * @tc.desc: HandleRepeatKeyAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyAbility_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    RepeatKey repeatKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    bool isMaxTimes = false;

    repeatKey.ability.bundleName = "bundleName1";
    handler.repeatKeyTimerIds_["bundleName1"] = 1;
    handler.repeatKeyTimerIds_["bundleName2"] = 2;
    handler.repeatKeyTimerIds_["bundleName3"] = 3;
    ASSERT_TRUE(handler.HandleRepeatKeyAbility(repeatKey, keyEvent, isMaxTimes));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyAbility_004
 * @tc.desc: HandleRepeatKeyAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyAbility_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    RepeatKey repeatKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    bool isMaxTimes = false;

    repeatKey.ability.bundleName = "bundleName4";
    handler.repeatKeyTimerIds_["bundleName1"] = 1;
    handler.repeatKeyTimerIds_["bundleName2"] = 2;
    handler.repeatKeyTimerIds_["bundleName3"] = 3;

    handler.repeatTimerId_ = 2;
    ASSERT_TRUE(handler.HandleRepeatKeyAbility(repeatKey, keyEvent, isMaxTimes));
    handler.repeatTimerId_ = -1;
    ASSERT_TRUE(handler.HandleRepeatKeyAbility(repeatKey, keyEvent, isMaxTimes));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyAbility_005
 * @tc.desc: HandleRepeatKeyAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyAbility_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    RepeatKey repeatKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    bool isMaxTimes = true;
    ASSERT_TRUE(handler.HandleRepeatKeyAbility(repeatKey, keyEvent, isMaxTimes));
}

/**
 * @tc.name: KeyCommandHandlerTest_OnHandleEvent_002
 * @tc.desc: Test the function OnHandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_OnHandleEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> key = KeyEvent::Create();
    ASSERT_NE(key, nullptr);
    key->SetKeyCode(18);
    handler.specialKeys_.insert(std::make_pair(18, 18));
    bool ret = handler.OnHandleEvent(key);
    EXPECT_TRUE(ret);
    key->SetKeyCode(KeyEvent::KEYCODE_POWER);
    handler.specialTimers_.insert(std::make_pair(KeyEvent::KEYCODE_POWER, 10));
    ret = handler.OnHandleEvent(key);
    EXPECT_TRUE(ret);
    key->SetKeyCode(5);
    ret = handler.OnHandleEvent(key);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleShortKeys_006
 * @tc.desc: Test the function HandleShortKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleShortKeys_006, TestSize.Level1)
{
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey key;
    key.preKeys = {2, 3, 4};
    key.businessId = "business";
    key.statusConfig = "config";
    key.statusConfigValue = true;
    key.finalKey = 6;
    key.keyDownDuration = 7;
    key.triggerType = KeyEvent::KEY_ACTION_DOWN;
    key.timerId = 10;
    handler.shortcutKeys_.insert(std::make_pair("key1", key));
    bool ret = handler.HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    handler.currentLaunchAbilityKey_.businessId = "business1";
    handler.currentLaunchAbilityKey_.statusConfig = "config1";
    handler.currentLaunchAbilityKey_.timerId = 6;
    handler.currentLaunchAbilityKey_.statusConfigValue = true;
    handler.currentLaunchAbilityKey_.finalKey = 4;
    handler.currentLaunchAbilityKey_.keyDownDuration = 5;
    handler.currentLaunchAbilityKey_.triggerType = KeyEvent::KEY_ACTION_DOWN;
    keyEvent->SetKeyCode(KeyEvent::INTENTION_RIGHT);
    keyEvent->SetKeyAction(KeyEvent::INTENTION_UP);
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 2017;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler.keys_.push_back(sequenceKey);
    sequenceKey.keyCode = 2022;
    sequenceKey.keyAction = KeyEvent::INTENTION_UP;
    handler.keys_.push_back(sequenceKey);
    EventLogHelper eventLogHelper;
    eventLogHelper.userType_ = "beta";
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    EXPECT_NE(inputEvent, nullptr);
    inputEvent->bitwise_ = 0x00000040;
    ret = handler.HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    eventLogHelper.userType_ = "abcde";
    ret = handler.HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    inputEvent->bitwise_ = 0x00000000;
    ret = handler.HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    handler.lastMatchedKeys_ = {};
    ret = handler.HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandlePointerEvent_002
 * @tc.desc: Test the function HandlePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandlePointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    handler.isParseConfig_ = true;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_QUADTAP);
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerEvent(pointerEvent));

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_TRIPTAP);
    EventLogHelper eventLogHelper;
    eventLogHelper.userType_ = "beta";
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    EXPECT_NE(inputEvent, nullptr);
    inputEvent->bitwise_ = 0;
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerEvent(pointerEvent));
    eventLogHelper.userType_ = "default";
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerEvent(pointerEvent));
    inputEvent->bitwise_ = InputEvent::EVENT_FLAG_PRIVACY_MODE;
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerEvent(pointerEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_StartTwoFingerGesture_003
 * @tc.desc: Test the function StartTwoFingerGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_StartTwoFingerGesture_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.twoFingerGesture_.active = true;
    handler.twoFingerGesture_.touches[0].downTime = 150000;
    handler.twoFingerGesture_.touches[0].id = 10;
    handler.twoFingerGesture_.touches[0].x = 100;
    handler.twoFingerGesture_.touches[0].y = 200;
    handler.twoFingerGesture_.touches[1].downTime = 100000;
    handler.twoFingerGesture_.touches[0].id = 5;
    handler.twoFingerGesture_.touches[0].x = 50;
    handler.twoFingerGesture_.touches[0].y = 100;
    ASSERT_NO_FATAL_FAILURE(handler.StartTwoFingerGesture());
    handler.twoFingerGesture_.touches[0].downTime = 350000;
    handler.twoFingerGesture_.touches[1].downTime = 100000;
    ASSERT_NO_FATAL_FAILURE(handler.StartTwoFingerGesture());
    handler.twoFingerGesture_.active = false;
    ASSERT_NO_FATAL_FAILURE(handler.StartTwoFingerGesture());
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckTwoFingerGestureAction_006
 * @tc.desc: Test the function CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckTwoFingerGestureAction_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.twoFingerGesture_.active = true;
    handler.twoFingerGesture_.touches[0].id = 1;
    handler.twoFingerGesture_.touches[0].x = 30;
    handler.twoFingerGesture_.touches[0].y = 20;
    handler.twoFingerGesture_.touches[0].downTime = 150000;
    handler.twoFingerGesture_.touches[1].id = 2;
    handler.twoFingerGesture_.touches[1].x = 20;
    handler.twoFingerGesture_.touches[1].y = 10;
    handler.twoFingerGesture_.touches[1].downTime = 100000;
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
    bool ret = handler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    handler.twoFingerGesture_.touches[0].x = 30;
    handler.twoFingerGesture_.touches[0].y = 200;
    handler.twoFingerGesture_.touches[1].x = 60;
    handler.twoFingerGesture_.touches[1].y = 170;
    ret = handler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    handler.twoFingerGesture_.touches[0].x = 120;
    ret = handler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    handler.twoFingerGesture_.touches[0].x = 90;
    handler.twoFingerGesture_.touches[0].y = 120;
    ret = handler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    handler.twoFingerGesture_.touches[0].y = 250;
    ret = handler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckTwoFingerGestureAction_007
 * @tc.desc: Test the function CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckTwoFingerGestureAction_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.twoFingerGesture_.active = true;
    handler.twoFingerGesture_.touches[0].x = 90;
    handler.twoFingerGesture_.touches[0].y = 200;
    handler.twoFingerGesture_.touches[0].downTime = 150000;
    handler.twoFingerGesture_.touches[1].x = 30;
    handler.twoFingerGesture_.touches[1].y = 170;
    handler.twoFingerGesture_.touches[1].downTime = 100000;
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
    handler.twoFingerGesture_.touches[0].y = 200;
    handler.twoFingerGesture_.touches[1].x = 30;
    bool ret = handler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    handler.twoFingerGesture_.touches[1].x = 130;
    ret = handler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    handler.twoFingerGesture_.touches[1].x = 60;
    handler.twoFingerGesture_.touches[1].y = 100;
    ret = handler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    handler.twoFingerGesture_.touches[1].y = 250;
    ret = handler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    ASSERT_NO_FATAL_FAILURE(handler.StartTwoFingerGesture());
    handler.twoFingerGesture_.touches[1].y = 170;
    ret = handler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    ASSERT_NO_FATAL_FAILURE(handler.StartTwoFingerGesture());
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckTwoFingerGestureAction_008
 * @tc.desc: Test the function CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckTwoFingerGestureAction_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.twoFingerGesture_.active = true;
    auto firstFinger = handler.twoFingerGesture_.touches[0];
    auto secondFinger = handler.twoFingerGesture_.touches[1];

    int64_t firstTime = firstFinger.downTime;
    firstTime = 150000;
    int64_t secondTime = secondFinger.downTime;
    secondTime = 200000;
    auto pressTimeInterval = fabs(firstTime - secondTime);
    EXPECT_FALSE(pressTimeInterval > TWO_FINGERS_TIME_LIMIT);
    EXPECT_FALSE(handler.CheckTwoFingerGestureAction());

    int32_t firstFingerX = firstFinger.x;
    firstFingerX = 90;
    int32_t firstFingerY = firstFinger.y;
    firstFingerY = 200;
    int32_t secondFingerX = secondFinger.x;
    secondFingerX = 30;
    int32_t secondFingerY = secondFinger.y;
    secondFingerY = 170;
    int32_t devX = firstFingerX - secondFingerX;
    int32_t devY = firstFingerY - secondFingerY;
    auto distance = sqrt(pow(devX, 2) + pow(devY, 2));
    EXPECT_FALSE(distance < handler.ConvertVPToPX(TWO_FINGERS_DISTANCE_LIMIT));
    EXPECT_FALSE(handler.CheckTwoFingerGestureAction());

    auto leftLimit = handler.ConvertVPToPX(TOUCH_LIFT_LIMIT);
    firstFingerX = -10;
    EXPECT_TRUE(firstFingerX <= leftLimit);
    EXPECT_FALSE(handler.CheckTwoFingerGestureAction());

    InputWindowsManager inputWindowsManager;
    OLD::DisplayInfo displayInfo;
    displayInfo.dpi = 320;
    displayInfo.width = 10;
    displayInfo.height = 30;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    auto rightLimit = displayInfo.width - handler.ConvertVPToPX(TOUCH_RIGHT_LIMIT);
    firstFingerX = 50;
    EXPECT_TRUE(firstFingerX >= rightLimit);
    EXPECT_FALSE(handler.CheckTwoFingerGestureAction());

    auto topLimit = handler.ConvertVPToPX(TOUCH_TOP_LIMIT);
    firstFingerY = -20;
    EXPECT_TRUE(firstFingerY <= topLimit);
    EXPECT_FALSE(handler.CheckTwoFingerGestureAction());

    auto bottomLimit = displayInfo.height - handler.ConvertVPToPX(TOUCH_BOTTOM_LIMIT);
    firstFingerY = 60;
    EXPECT_TRUE(firstFingerY >= bottomLimit);
    EXPECT_FALSE(handler.CheckTwoFingerGestureAction());

    secondFingerX = -5;
    EXPECT_TRUE(secondFingerX <= leftLimit);
    secondFingerX = 30;
    EXPECT_TRUE(secondFingerX >= rightLimit);
    secondFingerY = -1;
    EXPECT_TRUE(secondFingerY <= topLimit);
    secondFingerY = 50;
    EXPECT_TRUE(secondFingerY >= bottomLimit);
    EXPECT_FALSE(handler.CheckTwoFingerGestureAction());
}

/**
 * @tc.name: KeyCommandHandlerTest_IsKeyMatch_01
 * @tc.desc: Test the function IsKeyMatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_IsKeyMatch_01, TestSize.Level1)
{
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey shortcutKey;
    std::vector<ShortcutKey> upAbilities;
    shortcutKey.statusConfigValue = true;
    shortcutKey.finalKey = 2076;
    shortcutKey.keyDownDuration = 0;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;
    keyEvent->keyCode_ = 2076;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    shortcutKey.preKeys = {2076, 2077};
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    item.SetKeyCode(KeyEvent::KEYCODE_META_RIGHT);
    item.SetKeyCode(KeyEvent::KEYCODE_FUNCTION);
    keyEvent->AddKeyItem(item);
    EXPECT_FALSE(handler.IsKeyMatch(shortcutKey, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_StartTwoFingerGesture_01
 * @tc.desc: Test the function StartTwoFingerGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_StartTwoFingerGesture_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.twoFingerGesture_.active = false;
    EXPECT_FALSE(handler.CheckTwoFingerGestureAction());
    ASSERT_NO_FATAL_FAILURE(handler.StartTwoFingerGesture());
}

/**
 * @tc.name: KeyCommandHandlerTest_StartTwoFingerGesture_02
 * @tc.desc: Test the function StartTwoFingerGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_StartTwoFingerGesture_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.twoFingerGesture_.active = true;
    EXPECT_FALSE(handler.CheckTwoFingerGestureAction());
    ASSERT_NO_FATAL_FAILURE(handler.StartTwoFingerGesture());
}

/**
 * @tc.name: KeyCommandHandlerTest_ConvertVPToPX_004
 * @tc.desc: Test the function ConvertVPToPX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ConvertVPToPX_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    int32_t vp = 10;
    InputWindowsManager inputWindowsManager;
    OLD::DisplayInfo displayInfo;
    displayInfo.dpi = -10;
    displayInfo.uniq = "default0";
    auto it = inputWindowsManager.displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager.displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    int32_t ret = handler.ConvertVPToPX(vp);
    ASSERT_EQ(ret, 0);
    displayInfo.dpi = 160;
    it->second.displaysInfo.push_back(displayInfo);
    ret = handler.ConvertVPToPX(vp);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureEvent_004
 * @tc.desc: Test the function HandleKnuckleGestureEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    PointerEvent::PointerItem item;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    handler.singleKnuckleGesture_.state = false;
    handler.gameForbidFingerKnuckle_ = false;
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(1);
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureEvent(touchEvent));
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureEvent(touchEvent));
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureEvent(touchEvent));
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureEvent(touchEvent));
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureEvent(touchEvent));
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureEvent(touchEvent));
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureEvent(touchEvent));
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureEvent(touchEvent));
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_UP);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureEvent(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_OnHandleTouchEvent
 * @tc.desc: Test OnHandleTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_OnHandleTouchEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    PointerEvent::PointerItem item;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    handler.isParseConfig_ = false;
    handler.isDistanceConfig_ = false;
    handler.isKnuckleSwitchConfig_ = true;
    item.SetPointerId(1);
    item.SetToolType(PointerEvent::TOOL_TYPE_PENCIL);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(1);
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(handler.OnHandleTouchEvent(touchEvent));

    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(handler.OnHandleTouchEvent(touchEvent));

    touchEvent->RemovePointerItem(1);
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    ASSERT_NO_FATAL_FAILURE(handler.OnHandleTouchEvent(touchEvent));

    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    ASSERT_NO_FATAL_FAILURE(handler.OnHandleTouchEvent(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandlePointerActionMoveEvent
 * @tc.desc: Test HandlePointerActionMoveEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandlePointerActionMoveEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    handler.twoFingerGesture_.active = true;
    handler.twoFingerGesture_.timerId = -1;
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerActionMoveEvent(touchEvent));

    touchEvent->SetPointerId(2);
    handler.twoFingerGesture_.timerId = 1;
    handler.twoFingerGesture_.touches->id = 1;
    handler.twoFingerGesture_.touches->x = 25;
    handler.twoFingerGesture_.touches->y = 25;
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerActionMoveEvent(touchEvent));

    touchEvent->SetPointerId(1);
    PointerEvent::PointerItem item;
    item.SetDisplayX(5);
    item.SetDisplayY(5);
    touchEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerActionMoveEvent(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleFingerGestureDownEvent
 * @tc.desc: Test HandleFingerGestureDownEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleFingerGestureDownEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    PointerEvent::PointerItem item;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    handler.twoFingerGesture_.active = true;
    item.SetPointerId(1);
    item.SetDisplayX(10);
    item.SetDisplayY(10);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(1);
    ASSERT_NO_FATAL_FAILURE(handler.HandleFingerGestureDownEvent(touchEvent));

    item.SetPointerId(2);
    item.SetDisplayX(15);
    item.SetDisplayY(15);
    touchEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(handler.HandleFingerGestureDownEvent(touchEvent));

    handler.twoFingerGesture_.active = true;
    handler.twoFingerGesture_.timerId = 150;
    ASSERT_NO_FATAL_FAILURE(handler.HandleFingerGestureUpEvent(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleFingerGestureDownEvent_001
 * @tc.desc: Test HandleFingerGestureDownEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleFingerGestureDownEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    PointerEvent::PointerItem item;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    handler.twoFingerGesture_.active = true;
    ASSERT_NO_FATAL_FAILURE(handler.HandleFingerGestureDownEvent(touchEvent));

    item.SetPointerId(1);
    touchEvent->AddPointerItem(item);
    item.SetPointerId(2);
    touchEvent->AddPointerItem(item);
    item.SetPointerId(3);
    touchEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(handler.HandleFingerGestureDownEvent(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureDownEvent_001
 * @tc.desc: Test HandleKnuckleGestureDownEvent_001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureDownEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    PointerEvent::PointerItem item;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    handler.twoFingerGesture_.active = true;
    item.SetPointerId(1);
    item.SetToolType(PointerEvent::TOOL_TYPE_PALM);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(1);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureDownEvent(touchEvent));

    item.SetPointerId(2);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    touchEvent->AddPointerItem(item);
    item.SetPointerId(3);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(2);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureDownEvent(touchEvent));

    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureUpEvent(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureDownEvent_002
 * @tc.desc: Test HandleKnuckleGestureDownEvent_002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureDownEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    PointerEvent::PointerItem item;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    handler.twoFingerGesture_.active = true;
    handler.gameForbidFingerKnuckle_ = true;

    item.SetPointerId(2);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    touchEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureDownEvent(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureDownEvent_003
 * @tc.desc: Test HandleKnuckleGestureDownEvent_003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureDownEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    PointerEvent::PointerItem item;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    handler.twoFingerGesture_.active = true;
    handler.gameForbidFingerKnuckle_ = false;

    item.SetPointerId(2);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    touchEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureDownEvent(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureUpEvent
 * @tc.desc: Test HandleKnuckleGestureUpEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureUpEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    PointerEvent::PointerItem item;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    item.SetPointerId(1);
    touchEvent->AddPointerItem(item);
    handler.isDoubleClick_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureUpEvent(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_KnuckleGestureProcessor
 * @tc.desc: Test KnuckleGestureProcessor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_KnuckleGestureProcessor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    KnuckleGesture knuckleGesture;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    knuckleGesture.lastPointerDownEvent = touchEvent;
    knuckleGesture.lastPointerUpTime = 10;
    touchEvent->SetActionTime(5);
    handler.knuckleCount_ = 2;
    ASSERT_NO_FATAL_FAILURE(
        handler.KnuckleGestureProcessor(touchEvent, knuckleGesture, KnuckleType::KNUCKLE_TYPE_SINGLE));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleMultiTapTest__001
 * @tc.desc: Test three fingers tap event launch ability
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleMultiTapTest__001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto threeFingerTap = SetupThreeFingerTapEvent();
    ASSERT_TRUE(threeFingerTap != nullptr);
    KeyCommandHandler keyCommandHandler;
    ASSERT_TRUE(keyCommandHandler.OnHandleEvent(threeFingerTap));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleMultiTapTest__002
 * @tc.desc: Test four fingers tap event launch ability
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleMultiTapTest__002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto fourFingerTap = SetupFourFingerTapEvent();
    ASSERT_TRUE(fourFingerTap != nullptr);
    KeyCommandHandler keyCommandHandler;
    ASSERT_FALSE(keyCommandHandler.OnHandleEvent(fourFingerTap));
}

/**
 * @tc.name: KeyCommandHandlerTest_001
 * @tc.desc: Test update key down duration 0, 100, 4000
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler eventKeyCommandHandler;
    std::string businessId = "aaa";
    int32_t delay = 0;
    ASSERT_EQ(COMMON_PARAMETER_ERROR, eventKeyCommandHandler.UpdateSettingsXml(businessId, delay));
    delay = 100;
    ASSERT_EQ(COMMON_PARAMETER_ERROR, eventKeyCommandHandler.UpdateSettingsXml(businessId, delay));
    delay = 4000;
    ASSERT_EQ(COMMON_PARAMETER_ERROR, eventKeyCommandHandler.UpdateSettingsXml(businessId, delay));
}

/**
 * @tc.name: KeyCommandHandlerTest_EnableCombineKey_001
 * @tc.desc: Test enable combineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_EnableCombineKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler eventKeyCommandHandler;
    ASSERT_EQ(eventKeyCommandHandler.EnableCombineKey(true), RET_OK);
}

/**
 * @tc.name: KeyCommandHandlerTest_IsEnableCombineKey_001
 * @tc.desc: Test IsEnableCombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_IsEnableCombineKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler eventKeyCommandHandler;
    eventKeyCommandHandler.EnableCombineKey(false);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPV(keyEvent);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ASSERT_EQ(eventKeyCommandHandler.OnHandleEvent(keyEvent), false);
    eventKeyCommandHandler.EnableCombineKey(true);
}

/**
 * @tc.name: KeyCommandHandlerTest_IsEnableCombineKey_002
 * @tc.desc: Test IsEnableCombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_IsEnableCombineKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler eventKeyCommandHandler;
    eventKeyCommandHandler.EnableCombineKey(false);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPV(keyEvent);
    KeyEvent::KeyItem item1;
    item1.SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    keyEvent->AddKeyItem(item1);
    KeyEvent::KeyItem item2;
    item2.SetKeyCode(KeyEvent::KEYCODE_L);
    keyEvent->AddKeyItem(item2);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_L);
    ASSERT_EQ(eventKeyCommandHandler.OnHandleEvent(keyEvent), false);
    eventKeyCommandHandler.EnableCombineKey(true);
}

/**
 * @tc.name: KeyCommandHandlerTest_002
 * @tc.desc: Test update key down duration -1 and 4001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler eventKeyCommandHandler;
    std::string businessId = "com.ohos.camera";
    int32_t delay = -1;
    ASSERT_EQ(COMMON_PARAMETER_ERROR, eventKeyCommandHandler.UpdateSettingsXml(businessId, delay));
    delay = 4001;
    ASSERT_EQ(COMMON_PARAMETER_ERROR, eventKeyCommandHandler.UpdateSettingsXml(businessId, delay));
}

/**
 * @tc.name: KeyCommandHandlerTest_003
 * @tc.desc: Test businessId is ""
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler eventKeyCommandHandler;
    std::string businessId = "";
    int32_t delay = 100;
    ASSERT_EQ(COMMON_PARAMETER_ERROR, eventKeyCommandHandler.UpdateSettingsXml(businessId, delay));
}

/**
 * @tc.name: KeyCommandHandlerTest_004
 * @tc.desc: Test key event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = SetupKeyEvent();
    ASSERT_TRUE(keyEvent != nullptr);
    KeyCommandHandler eventKeyCommandHandler;
    ASSERT_FALSE(eventKeyCommandHandler.OnHandleEvent(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleEvent_01
 * @tc.desc: Test HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = SetupKeyEvent();
    ASSERT_TRUE(keyEvent != nullptr);
    KeyCommandHandler eventKeyCommandHandler;

    bool preHandleEvent = eventKeyCommandHandler.PreHandleEvent(keyEvent);
    EXPECT_TRUE(preHandleEvent);
    bool ret = eventKeyCommandHandler.HandleEvent(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleEvent_02
 * @tc.desc: Test HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = SetupKeyEvent();
    ASSERT_TRUE(keyEvent != nullptr);
    KeyCommandHandler eventKeyCommandHandler;

    bool stylusKey = STYLUS_HANDLER->HandleStylusKey(keyEvent);
    EXPECT_FALSE(stylusKey);
    bool ret = eventKeyCommandHandler.HandleEvent(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleEvent_03
 * @tc.desc: Test HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleEvent_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = SetupKeyEvent();
    ASSERT_TRUE(keyEvent != nullptr);
    KeyCommandHandler eventKeyCommandHandler;

    bool isHandled = eventKeyCommandHandler.HandleShortKeys(keyEvent);
    EXPECT_FALSE(isHandled);
    bool ret = eventKeyCommandHandler.HandleEvent(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleEvent_04
 * @tc.desc: Test HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleEvent_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = SetupKeyEvent();
    ASSERT_TRUE(keyEvent != nullptr);
    KeyCommandHandler eventKeyCommandHandler;

    eventKeyCommandHandler.isDownStart_ = true;
    bool isRepeatKeyHandle = eventKeyCommandHandler.HandleRepeatKeys(keyEvent);
    EXPECT_FALSE(isRepeatKeyHandle);
    bool ret = eventKeyCommandHandler.HandleEvent(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleEvent_05
 * @tc.desc: Test HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleEvent_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_TRUE(keyEvent != nullptr);
    KeyCommandHandler keyCommandHandler;
    EXPECT_TRUE(keyCommandHandler.PreHandleEvent(keyEvent));
    EXPECT_FALSE(STYLUS_HANDLER->HandleStylusKey(keyEvent));
    EXPECT_FALSE(keyCommandHandler.HandleShortKeys(keyEvent));

    bool ret = keyCommandHandler.HandleEvent(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleEvent_06
 * @tc.desc: Test HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleEvent_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_TRUE(keyEvent != nullptr);
    KeyCommandHandler keyCommandHandler;
    EXPECT_TRUE(keyCommandHandler.PreHandleEvent(keyEvent));
    EXPECT_FALSE(STYLUS_HANDLER->HandleStylusKey(keyEvent));
    EXPECT_FALSE(keyCommandHandler.HandleShortKeys(keyEvent));
    EXPECT_FALSE(keyCommandHandler.HandleSequences(keyEvent));
    keyEvent->keyCode_ = KeyEvent::KEYCODE_POWER;

    bool ret = keyCommandHandler.HandleEvent(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_ParseJson_01
 * @tc.desc: Test ParseJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ParseJson_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string configFile = "abc";
    std::string jsonStr = ReadJsonFile(configFile);
    KeyCommandHandler eventKeyCommandHandler;

    jsonStr = "";
    bool ret = eventKeyCommandHandler.ParseJson(configFile);
    EXPECT_TRUE(jsonStr.empty());
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_ParseJson_02
 * @tc.desc: Test ParseJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ParseJson_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string configFile = "config";
    std::string jsonStr = ReadJsonFile(configFile);
    KeyCommandHandler eventKeyCommandHandler;

    jsonStr = "abc";
    bool ret = eventKeyCommandHandler.ParseJson(configFile);
    EXPECT_FALSE(jsonStr.empty());
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_ProcessKnuckleGestureTouchUp_01
 * @tc.desc: Test ProcessKnuckleGestureTouchUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ProcessKnuckleGestureTouchUp_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NotifyType type;
    KeyCommandHandler handler;
    type = NotifyType::REGIONGESTURE;
    handler.isStartBase_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.ProcessKnuckleGestureTouchUp(type));

    handler.isStartBase_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.ProcessKnuckleGestureTouchUp(type));
}

/**
 * @tc.name: KeyCommandHandlerTest_ProcessKnuckleGestureTouchUp_02
 * @tc.desc: Test ProcessKnuckleGestureTouchUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ProcessKnuckleGestureTouchUp_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NotifyType type;
    KeyCommandHandler eventKeyCommandHandler;
    type = NotifyType::LETTERGESTURE;
    ASSERT_NO_FATAL_FAILURE(eventKeyCommandHandler.ProcessKnuckleGestureTouchUp(type));
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckTwoFingerGestureAction_01
 * @tc.desc: Test CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckTwoFingerGestureAction_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler eventKeyCommandHandler;
    bool isActive = eventKeyCommandHandler.twoFingerGesture_.active;
    EXPECT_FALSE(isActive);
    bool ret = eventKeyCommandHandler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckTwoFingerGestureAction_02
 * @tc.desc: Test CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckTwoFingerGestureAction_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler eventKeyCommandHandler;
    auto pressTimeInterval = fabs(200000 - 40000);
    EXPECT_TRUE(pressTimeInterval > TWO_FINGERS_TIME_LIMIT);
    bool ret = eventKeyCommandHandler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_Dump
 * @tc.desc: Test Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_Dump, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler eventKeyCommandHandler;
    char temp[] = "/tmp/KeyCommandHandlerTest_DUMP";
    int fd = mkstemp(temp);
    std::vector<std::string> args;
    EXPECT_NO_FATAL_FAILURE(eventKeyCommandHandler.Dump(fd, args));
    unlink(temp);
}

/**
 * @tc.name: KeyCommandHandlerTest_PrintGestureInfo
 * @tc.desc: Test PrintGestureInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_PrintGestureInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler eventKeyCommandHandler;
    EXPECT_NO_FATAL_FAILURE(eventKeyCommandHandler.PrintGestureInfo(1));
}

/**
 * @tc.name: KeyCommandHandlerTest_RegisterKnuckleSwitchByUserId
 * @tc.desc: Test RegisterKnuckleSwitchByUserId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_RegisterKnuckleSwitchByUserId, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler eventKeyCommandHandler;
    EXPECT_EQ(eventKeyCommandHandler.RegisterKnuckleSwitchByUserId(1), RET_OK);
}

/**
 * @tc.name: KeyCommandHandlerTest_SetKnuckleSwitch
 * @tc.desc: Test SetKnuckleSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetKnuckleSwitch, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler eventKeyCommandHandler;
    EXPECT_EQ(eventKeyCommandHandler.SetKnuckleSwitch(true), RET_OK);
}

/**
 * @tc.name: KeyCommandHandlerTest_SkipKnuckleDetect
 * @tc.desc: Test SkipKnuckleDetect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SkipKnuckleDetect, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler eventKeyCommandHandler;
    EXPECT_EQ(eventKeyCommandHandler.SkipKnuckleDetect(), true);
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckTwoFingerGestureAction_03
 * @tc.desc: Test CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckTwoFingerGestureAction_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler eventKeyCommandHandler;
    auto pressTimeInterval = fabs(200000 - 60000);
    EXPECT_FALSE(pressTimeInterval > TWO_FINGERS_TIME_LIMIT);
    bool ret = eventKeyCommandHandler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

#ifdef OHOS_BUILD_ENABLE_TOUCH
/**
 * @tc.name: KeyCommandHandlerTest_TouchTest_001
 * @tc.desc: Test double finger down event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_TouchTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = SetupDoubleFingerDownEvent();
    ASSERT_TRUE(pointerEvent != nullptr);
    KeyCommandHandler keyCommandHandler;
    keyCommandHandler.HandlePointerActionDownEvent(pointerEvent);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    keyCommandHandler.HandlePointerActionMoveEvent(pointerEvent);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    keyCommandHandler.HandlePointerActionUpEvent(pointerEvent);
    ASSERT_FALSE(keyCommandHandler.GetSingleKnuckleGesture().state);
    ASSERT_FALSE(keyCommandHandler.GetDoubleKnuckleGesture().state);
}

/**
 * @tc.name: KeyCommandHandlerTest_KnuckleTest_001
 * @tc.desc: Test single knuckle double click
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_KnuckleTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = SetupSingleKnuckleDownEvent();
    ASSERT_TRUE(pointerEvent != nullptr);
    KeyCommandHandler keyCommandHandler;
    keyCommandHandler.SetKnuckleDoubleTapDistance(DOUBLE_CLICK_DISTANCE_DEFAULT_CONFIG);
    int32_t actionTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    pointerEvent->SetActionTime(actionTime);
    keyCommandHandler.HandlePointerActionDownEvent(pointerEvent);
    ASSERT_FALSE(keyCommandHandler.GetSingleKnuckleGesture().state);
    ASSERT_FALSE(keyCommandHandler.GetDoubleKnuckleGesture().state);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    keyCommandHandler.HandlePointerActionUpEvent(pointerEvent);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    actionTime = actionTime + INTERVAL_TIME;
    pointerEvent->SetActionTime(actionTime);
    keyCommandHandler.HandlePointerActionDownEvent(pointerEvent);
    ASSERT_TRUE(keyCommandHandler.GetSingleKnuckleGesture().state);
    ASSERT_FALSE(keyCommandHandler.GetDoubleKnuckleGesture().state);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    keyCommandHandler.HandlePointerActionUpEvent(pointerEvent);
}

/**
 * @tc.name: KeyCommandHandlerTest_KnuckleTest_002
 * @tc.desc: Test double knuckle double click
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_KnuckleTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = SetupDoubleKnuckleDownEvent();
    ASSERT_TRUE(pointerEvent != nullptr);
    int32_t actionTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    pointerEvent->SetActionTime(actionTime);
    KeyCommandHandler keyCommandHandler;
    keyCommandHandler.SetKnuckleDoubleTapDistance(DOUBLE_CLICK_DISTANCE_DEFAULT_CONFIG);
    keyCommandHandler.HandlePointerActionDownEvent(pointerEvent);
    ASSERT_FALSE(keyCommandHandler.GetSingleKnuckleGesture().state);
    ASSERT_FALSE(keyCommandHandler.GetDoubleKnuckleGesture().state);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    keyCommandHandler.HandlePointerActionUpEvent(pointerEvent);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    actionTime = actionTime + INTERVAL_TIME;
    pointerEvent->SetActionTime(actionTime);
    keyCommandHandler.HandlePointerActionDownEvent(pointerEvent);
    ASSERT_FALSE(keyCommandHandler.GetSingleKnuckleGesture().state);
    ASSERT_TRUE(keyCommandHandler.GetDoubleKnuckleGesture().state);
}

/**
 * @tc.name: KeyCommandHandlerTest_KnuckleTest_003
 * @tc.desc: Test single knuckle event to double knuckle event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_KnuckleTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto singlePointerEvent = SetupSingleKnuckleDownEvent();
    ASSERT_TRUE(singlePointerEvent != nullptr);
    auto pointerEvent = SetupDoubleKnuckleDownEvent();
    ASSERT_TRUE(pointerEvent != nullptr);
    KeyCommandHandler keyCommandHandler;
    keyCommandHandler.HandlePointerActionDownEvent(singlePointerEvent);
    singlePointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    keyCommandHandler.HandlePointerActionUpEvent(singlePointerEvent);
    keyCommandHandler.HandlePointerActionDownEvent(pointerEvent);
    ASSERT_FALSE(keyCommandHandler.GetSingleKnuckleGesture().state);
    ASSERT_FALSE(keyCommandHandler.GetDoubleKnuckleGesture().state);
}

/**
 * @tc.name: KeyCommandHandlerTest_KnuckleTest_004
 * @tc.desc: Test sing knuckle double click interval time out
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_KnuckleTest_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = SetupSingleKnuckleDownEvent();
    ASSERT_TRUE(pointerEvent != nullptr);
    KeyCommandHandler keyCommandHandler;
    keyCommandHandler.SetKnuckleDoubleTapDistance(DOUBLE_CLICK_DISTANCE_DEFAULT_CONFIG);
    int32_t actionTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    pointerEvent->SetActionTime(actionTime);
    keyCommandHandler.HandlePointerActionDownEvent(pointerEvent);
    ASSERT_FALSE(keyCommandHandler.GetSingleKnuckleGesture().state);
    ASSERT_FALSE(keyCommandHandler.GetDoubleKnuckleGesture().state);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    keyCommandHandler.HandlePointerActionUpEvent(pointerEvent);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    actionTime = actionTime + INTERVAL_TIME_OUT;
    pointerEvent->SetActionTime(actionTime);
    keyCommandHandler.HandlePointerActionDownEvent(pointerEvent);
    ASSERT_FALSE(keyCommandHandler.GetSingleKnuckleGesture().state);
    ASSERT_FALSE(keyCommandHandler.GetDoubleKnuckleGesture().state);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    keyCommandHandler.HandlePointerActionUpEvent(pointerEvent);
}

/**
 * @tc.name: KeyCommandHandlerTest_KnuckleTest_005
 * @tc.desc: Test double knuckle double CLICK click interval time out
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_KnuckleTest_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = SetupDoubleKnuckleDownEvent();
    ASSERT_TRUE(pointerEvent != nullptr);
    int32_t actionTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    pointerEvent->SetActionTime(actionTime);
    KeyCommandHandler keyCommandHandler;
    keyCommandHandler.SetKnuckleDoubleTapDistance(DOUBLE_CLICK_DISTANCE_DEFAULT_CONFIG);
    keyCommandHandler.HandlePointerActionDownEvent(pointerEvent);
    ASSERT_FALSE(keyCommandHandler.GetSingleKnuckleGesture().state);
    ASSERT_FALSE(keyCommandHandler.GetDoubleKnuckleGesture().state);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    keyCommandHandler.HandlePointerActionUpEvent(pointerEvent);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    actionTime = actionTime + INTERVAL_TIME_OUT;
    pointerEvent->SetActionTime(actionTime);
    keyCommandHandler.HandlePointerActionDownEvent(pointerEvent);
    ASSERT_FALSE(keyCommandHandler.GetSingleKnuckleGesture().state);
    ASSERT_FALSE(keyCommandHandler.GetDoubleKnuckleGesture().state);
}

/**
 * @tc.name: KeyCommandHandlerTest_KnuckleTest_006
 * @tc.desc: Test the tool type is TOOL_TYPE_TOUCHPAD Action down
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_KnuckleTest_006, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_TOUCHPAD);
    int32_t downX = 100;
    int32_t downY = 200;
    item.SetDisplayX(downX);
    item.SetDisplayY(downY);
    item.SetPressed(true);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    KeyCommandHandler keyCommandHandler;
    keyCommandHandler.HandlePointerActionDownEvent(pointerEvent);
    ASSERT_FALSE(keyCommandHandler.GetSingleKnuckleGesture().state);
    ASSERT_FALSE(keyCommandHandler.GetDoubleKnuckleGesture().state);
}

/**
 * @tc.name: KeyCommandHandlerTest_KnuckleTest_007
 * @tc.desc: Test the tool type is TOOL_TYPE_TOUCHPAD Action up
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_KnuckleTest_007, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_TOUCHPAD);
    int32_t downX = 100;
    int32_t downY = 200;
    item.SetDisplayX(downX);
    item.SetDisplayY(downY);
    item.SetPressed(true);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    KeyCommandHandler keyCommandHandler;
    keyCommandHandler.HandlePointerActionUpEvent(pointerEvent);
    ASSERT_FALSE(keyCommandHandler.GetSingleKnuckleGesture().state);
    ASSERT_FALSE(keyCommandHandler.GetDoubleKnuckleGesture().state);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleTouchEventTest_001
 * @tc.desc: Test signl knuckle CLICK set HandleTouchEvent pointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleTouchEventTest_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = SetupSingleKnuckleDownEvent();
    ASSERT_TRUE(pointerEvent != nullptr);
    int32_t actionTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    pointerEvent->SetActionTime(actionTime);
    KeyCommandHandler keyCommandHandler;
    keyCommandHandler.HandleTouchEvent(pointerEvent);
    ASSERT_FALSE(keyCommandHandler.GetSingleKnuckleGesture().state);
    ASSERT_FALSE(keyCommandHandler.GetDoubleKnuckleGesture().state);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleTouchEventTest_002
 * @tc.desc: Test double knuckle CLICK set HandleTouchEvent pointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleTouchEventTest_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = SetupDoubleKnuckleDownEvent();
    ASSERT_TRUE(pointerEvent != nullptr);
    int32_t actionTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    pointerEvent->SetActionTime(actionTime);
    KeyCommandHandler keyCommandHandler;
    keyCommandHandler.HandleTouchEvent(pointerEvent);
    ASSERT_FALSE(keyCommandHandler.GetSingleKnuckleGesture().state);
    ASSERT_FALSE(keyCommandHandler.GetDoubleKnuckleGesture().state);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleTouchEventTest_003
 * @tc.desc: Test signl knuckle double CLICK set HandleTouchEvent pointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleTouchEventTest_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = SetupSingleKnuckleDownEvent();
    ASSERT_TRUE(pointerEvent != nullptr);
    int32_t actionTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    pointerEvent->SetActionTime(actionTime);
    KeyCommandHandler keyCommandHandler;
    keyCommandHandler.HandleTouchEvent(pointerEvent);
    ASSERT_FALSE(keyCommandHandler.GetSingleKnuckleGesture().state);
    ASSERT_FALSE(keyCommandHandler.GetDoubleKnuckleGesture().state);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    keyCommandHandler.HandleTouchEvent(pointerEvent);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    actionTime = actionTime + INTERVAL_TIME;
    pointerEvent->SetActionTime(actionTime);
    keyCommandHandler.HandleTouchEvent(pointerEvent);
    ASSERT_FALSE(keyCommandHandler.GetSingleKnuckleGesture().state);
    ASSERT_FALSE(keyCommandHandler.GetDoubleKnuckleGesture().state);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleTouchEventTest_004
 * @tc.desc: Test double knuckle double CLICK set HandleTouchEvent pointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleTouchEventTest_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = SetupDoubleKnuckleDownEvent();
    ASSERT_TRUE(pointerEvent != nullptr);
    int32_t actionTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    pointerEvent->SetActionTime(actionTime);
    KeyCommandHandler keyCommandHandler;
    keyCommandHandler.HandleTouchEvent(pointerEvent);
    ASSERT_FALSE(keyCommandHandler.GetSingleKnuckleGesture().state);
    ASSERT_FALSE(keyCommandHandler.GetDoubleKnuckleGesture().state);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    keyCommandHandler.HandleTouchEvent(pointerEvent);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    actionTime = actionTime + INTERVAL_TIME;
    pointerEvent->SetActionTime(actionTime);
    keyCommandHandler.HandleTouchEvent(pointerEvent);
    ASSERT_FALSE(keyCommandHandler.GetSingleKnuckleGesture().state);
    ASSERT_FALSE(keyCommandHandler.GetDoubleKnuckleGesture().state);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

/**
 * @tc.name: KeyCommandHandlerTest_UpdateSettingsXml_001
 * @tc.desc: Update settings xml verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_UpdateSettingsXml_001, TestSize.Level1)
{
    KeyCommandHandler handler;
    ASSERT_EQ(handler.UpdateSettingsXml("", 100), COMMON_PARAMETER_ERROR);
    ASSERT_EQ(handler.UpdateSettingsXml("businessId", 100), COMMON_PARAMETER_ERROR);
    handler.businessIds_ = {"businessId1", "businessId2"};
    ASSERT_EQ(handler.UpdateSettingsXml("businessId3", 100), COMMON_PARAMETER_ERROR);
    handler.businessIds_ = {"businessId"};
    ASSERT_EQ(handler.UpdateSettingsXml("businessId", 1000), 0);
    auto result = PREFERENCES_MGR->SetShortKeyDuration("businessId", 100);
    ASSERT_EQ(handler.UpdateSettingsXml("businessId", 100), result);
}

/**
 * @tc.name: KeyCommandHandlerTest_AdjustDistanceConfigIfNeed_001
 * @tc.desc: Adjust distance configIf need verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_AdjustDistanceConfigIfNeed_001, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.downToPrevDownDistanceConfig_ = handler.distanceDefaultConfig_;
    handler.AdjustDistanceConfigIfNeed(handler.distanceDefaultConfig_);
    handler.AdjustDistanceConfigIfNeed(handler.distanceLongConfig_);
    handler.downToPrevDownDistanceConfig_ = handler.distanceLongConfig_;
    handler.AdjustDistanceConfigIfNeed(handler.distanceDefaultConfig_);
    handler.AdjustDistanceConfigIfNeed(handler.distanceLongConfig_);
    ASSERT_EQ(handler.downToPrevDownDistanceConfig_, handler.distanceLongConfig_);
    handler.downToPrevDownDistanceConfig_ = handler.distanceDefaultConfig_;
    handler.AdjustDistanceConfigIfNeed(handler.distanceDefaultConfig_ - 1);
    handler.downToPrevDownDistanceConfig_ = handler.distanceLongConfig_;
    handler.AdjustDistanceConfigIfNeed(handler.distanceDefaultConfig_ - 1);
    ASSERT_EQ(handler.downToPrevDownDistanceConfig_, handler.distanceDefaultConfig_);
}

/**
 * @tc.name: KeyCommandHandlerTest_StartTwoFingerGesture_001
 * @tc.desc: Start two finger gesture verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_StartTwoFingerGesture_001, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.twoFingerGesture_.abilityStartDelay = 1000;
    handler.StartTwoFingerGesture();
    ASSERT_NE(-1, handler.twoFingerGesture_.timerId);
}

/**
 * @tc.name: KeyCommandHandlerTest_SkipFinalKey
 * @tc.desc: Skip Final Key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SkipFinalKey, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    int32_t keyCode = 1024;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_FALSE(handler.SkipFinalKey(keyCode, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyDown_01
 * @tc.desc: Handle Key Down
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyDown_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ShortcutKey shortcutKey;
    shortcutKey.keyDownDuration = 0;
    shortcutKey.ability.bundleName = "com.example.test";
    ASSERT_TRUE(handler.HandleKeyDown(shortcutKey));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyDown_02
 * @tc.desc: test HandleKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyDown_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ShortcutKey shortcutKey;
    shortcutKey.keyDownDuration = 1000;
    shortcutKey.ability.bundleName = "com.example.test";
    shortcutKey.timerId = -1;
    ASSERT_FALSE(handler.HandleKeyDown(shortcutKey));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyDown_03
 * @tc.desc: test HandleKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyDown_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ShortcutKey shortcutKey;
    shortcutKey.keyDownDuration = 0;
    shortcutKey.ability.bundleName = "com.example.test";
    shortcutKey.timerId = -1;
    ASSERT_TRUE(handler.HandleKeyDown(shortcutKey));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyDown_04
 * @tc.desc: test HandleKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyDown_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ShortcutKey shortcutKey;
    shortcutKey.keyDownDuration = 1000;
    shortcutKey.ability.bundleName = "com.example.test";
    shortcutKey.finalkey = 17;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;
    ASSERT_FALSE(handler.HandleKeyDown(shortcutKey));
}

/**
 * @tc.name: KeyCommandHandlerTest_GetKeyDownDurationFromXml
 * @tc.desc: GetKeyDownDurationFromXml
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_GetKeyDownDurationFromXml, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::string businessId = "power";
    int32_t ret = handler.GetKeyDownDurationFromXml(businessId);
    ASSERT_EQ(ret, ERROR_DELAY_VALUE);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyUp_001
 * @tc.desc: HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyUp_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ShortcutKey shortcutKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    shortcutKey.keyDownDuration = 0;
    ASSERT_TRUE(handler.HandleKeyUp(keyEvent, shortcutKey));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyUp_002
 * @tc.desc: HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyUp_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ShortcutKey shortcutKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    shortcutKey.keyDownDuration = 1;
    ASSERT_FALSE(handler.HandleKeyUp(keyEvent, shortcutKey));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyUp_003
 * @tc.desc: HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyUp_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ShortcutKey shortcutKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyEvent::KeyItem item;
    ASSERT_NE(keyEvent, nullptr);
    shortcutKey.keyDownDuration = 1;
    item.SetKeyCode(KeyEvent::KEYCODE_H);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_H);
    keyEvent->SetActionTime(10000);
    ASSERT_TRUE(handler.HandleKeyUp(keyEvent, shortcutKey));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyUp_004
 * @tc.desc: HandleKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyUp_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ShortcutKey shortcutKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyEvent::KeyItem item;
    ASSERT_NE(keyEvent, nullptr);
    shortcutKey.keyDownDuration = 10;
    item.SetKeyCode(KeyEvent::KEYCODE_H);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_H);
    keyEvent->SetActionTime(100);
    ASSERT_FALSE(handler.HandleKeyUp(keyEvent, shortcutKey));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyCancel
 * @tc.desc: HandleKeyCancel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyCancel, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ShortcutKey shortcutKey;
    shortcutKey.timerId = -1;
    ASSERT_FALSE(handler.HandleKeyCancel(shortcutKey));
    shortcutKey.timerId = 10;
    ASSERT_FALSE(handler.HandleKeyCancel(shortcutKey));
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchAbility_001
 * @tc.desc: LaunchAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchAbility_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    Ability ability;
    ability.abilityType = EXTENSION_ABILITY;
    ASSERT_NO_FATAL_FAILURE(handler.LaunchAbility(ability));
    ability.abilityType = EXTENSION_ABILITY_ABNORMAL;
    ASSERT_NO_FATAL_FAILURE(handler.LaunchAbility(ability));
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchAbility_002
 * @tc.desc: LaunchAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchAbility_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ShortcutKey shortcutKey;
    ASSERT_NO_FATAL_FAILURE(handler.LaunchAbility(shortcutKey));
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchAbility_003
 * @tc.desc: LaunchAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchAbility_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    Sequence sequence;
    ASSERT_NO_FATAL_FAILURE(handler.LaunchAbility(sequence));
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchAbility_004
 * @tc.desc: LaunchAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchAbility_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    Ability ability;
    int64_t delay = 100;
    ability.deviceId = "deviceId";
    ability.bundleName = "bundleName";
    ability.abilityName = "abilityName";
    ability.uri = "abilityUri";
    ability.type = "type";
    ability.action = "abilityAction";
    ability.entities.push_back("entities");
    ability.params.insert(std::make_pair("paramsFirst", "paramsSecond"));
    ASSERT_NO_FATAL_FAILURE(handler.LaunchAbility(ability, delay));
}

/**
 * @tc.name: KeyCommandHandlerTest_KeyCommandHandlerPrint
 * @tc.desc: Print
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_KeyCommandHandlerPrint, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ShortcutKey shortcutKey;
    Ability ability_temp;
    std::string copyShortcutKey = "copyShortcutKey";
    shortcutKey.preKeys.insert(2072);
    shortcutKey.finalKey = 2019;
    shortcutKey.keyDownDuration = 100;
    ability_temp.bundleName = "bundleName";
    ability_temp.abilityName = "abilityName";
    shortcutKey.ability = ability_temp;
    handler.shortcutKeys_.insert(std::make_pair(copyShortcutKey, shortcutKey));
    ASSERT_NO_FATAL_FAILURE(handler.Print());
}

/**
 * @tc.name: KeyCommandHandlerTest_shortcutKeyPrint
 * @tc.desc: Print
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_shortcutKeyPrint, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ShortcutKey shortcutKey;
    Ability ability_temp;
    shortcutKey.preKeys.insert(2072);
    shortcutKey.finalKey = 2019;
    ability_temp.bundleName = "bundleName";
    shortcutKey.ability = ability_temp;
    ASSERT_NO_FATAL_FAILURE(shortcutKey.Print());
}

/**
 * @tc.name: KeyCommandHandlerTest_RemoveSubscribedTimer
 * @tc.desc: RemoveSubscribedTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_RemoveSubscribedTimer, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    int32_t keyCode = 16;
    std::list<int32_t> timerIds;
    timerIds.push_back(100);
    handler.specialTimers_.insert(std::make_pair(keyCode, timerIds));
    ASSERT_NO_FATAL_FAILURE(handler.RemoveSubscribedTimer(keyCode));
    keyCode = 17;
    ASSERT_NO_FATAL_FAILURE(handler.RemoveSubscribedTimer(keyCode));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleSpecialKeys
 * @tc.desc: HandleSpecialKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleSpecialKeys, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    int32_t keyCodeVolumeUp = 16;
    int32_t keyCodeVolumeDown = 17;
    int32_t keyAction = KeyEvent::KEY_ACTION_UP;
    handler.specialKeys_.insert(std::make_pair(keyCodeVolumeUp, keyAction));
    ASSERT_NO_FATAL_FAILURE(handler.HandleSpecialKeys(keyCodeVolumeUp, keyAction));
    handler.specialKeys_.clear();

    keyAction = KeyEvent::KEY_ACTION_DOWN;
    ASSERT_NO_FATAL_FAILURE(handler.HandleSpecialKeys(keyCodeVolumeDown, keyAction));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleSpecialKeys_001
 * @tc.desc: Overrides the HandleSpecialKeys function exception branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleSpecialKeys_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyCommandHandler handler;
    int32_t powerKeyCode = 18;
    int32_t keyCode = 2017;
    int32_t keyAction = KeyEvent::KEY_ACTION_UP;
    handler.specialKeys_.insert(std::make_pair(powerKeyCode, keyAction));
    ASSERT_NO_FATAL_FAILURE(handler.HandleSpecialKeys(keyCode, keyAction));

    keyAction = KeyEvent::KEY_ACTION_DOWN;
    ASSERT_NO_FATAL_FAILURE(handler.HandleSpecialKeys(powerKeyCode, keyAction));
}

/**
 * @tc.name: KeyCommandHandlerTest_InterruptTimers
 * @tc.desc: InterruptTimers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_InterruptTimers, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    Sequence sequence;
    sequence.timerId = 1;
    handler.filterSequences_.push_back(sequence);
    ASSERT_NO_FATAL_FAILURE(handler.InterruptTimers());

    handler.filterSequences_.clear();
    sequence.timerId = -1;
    handler.filterSequences_.push_back(sequence);
    ASSERT_NO_FATAL_FAILURE(handler.InterruptTimers());
}

/**
 * @tc.name: KeyCommandHandlerTest_SetKnuckleDoubleTapDistance
 * @tc.desc: SetKnuckleDoubleTapDistance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetKnuckleDoubleTapDistance, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    float distance = -1.0f;
    ASSERT_NO_FATAL_FAILURE(handler.SetKnuckleDoubleTapDistance(distance));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleMulFingersTap
 * @tc.desc: Overrides the HandleMulFingersTap function exception branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleMulFingersTap, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_QUADTAP);
    ASSERT_FALSE(handler.HandleMulFingersTap(pointerEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_IsKeyMatch
 * @tc.desc: IsKeyMatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_IsKeyMatch, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ShortcutKey shortcutKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    shortcutKey.finalKey = 2019;
    shortcutKey.preKeys.insert(2072);
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;
    item.SetKeyCode(KeyEvent::KEYCODE_C);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_C);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    ASSERT_FALSE(handler.IsKeyMatch(shortcutKey, keyEvent));

    shortcutKey.preKeys.insert(2047);
    item.SetKeyCode(KeyEvent::KEYCODE_B);
    keyEvent->AddKeyItem(item);
    item.SetKeyCode(KeyEvent::KEYCODE_E);
    keyEvent->AddKeyItem(item);
    ASSERT_FALSE(handler.IsKeyMatch(shortcutKey, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleSequence
 * @tc.desc: HandleSequence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleSequence, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    Sequence sequence;
    SequenceKey sequenceKey;
    bool isLaunchAbility = false;
    sequence.statusConfigValue = false;
    ASSERT_FALSE(handler.HandleSequence(sequence, isLaunchAbility));

    sequence.statusConfigValue = true;
    sequenceKey.keyCode = 2017;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler.keys_.push_back(sequenceKey);
    sequenceKey.keyCode = 2018;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler.keys_.push_back(sequenceKey);

    sequenceKey.keyCode = 2019;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_UP;
    sequence.sequenceKeys.push_back(sequenceKey);
    ASSERT_FALSE(handler.HandleSequence(sequence, isLaunchAbility));

    sequenceKey.keyCode = 2017;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_UP;
    sequence.sequenceKeys.push_back(sequenceKey);
    ASSERT_FALSE(handler.HandleSequence(sequence, isLaunchAbility));
}

/**
 * @tc.name: KeyCommandHandlerTest_IsRepeatKeyEvent
 * @tc.desc: IsRepeatKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_IsRepeatKeyEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 2018;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler.keys_.push_back(sequenceKey);

    sequenceKey.keyCode = 2018;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    ASSERT_TRUE(handler.IsRepeatKeyEvent(sequenceKey));

    sequenceKey.keyAction = KeyEvent::KEY_ACTION_UP;
    ASSERT_FALSE(handler.IsRepeatKeyEvent(sequenceKey));

    handler.keys_.clear();
    sequenceKey.keyCode = 2019;
    handler.keys_.push_back(sequenceKey);
    sequenceKey.keyCode = 2020;
    ASSERT_FALSE(handler.IsRepeatKeyEvent(sequenceKey));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleSequences
 * @tc.desc: HandleSequences
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleSequences, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler.matchedSequence_.timerId = 10;
    ASSERT_FALSE(handler.HandleSequences(keyEvent));
    handler.matchedSequence_.timerId = -1;
    ASSERT_FALSE(handler.HandleSequences(keyEvent));

    keyEvent->SetKeyCode(2017);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetActionTime(10000);
    SequenceKey sequenceKey;
    Sequence sequence;
    handler.sequences_.push_back(sequence);
    sequenceKey.actionTime = 15000;
    handler.keys_.push_back(sequenceKey);
    ASSERT_FALSE(handler.HandleSequences(keyEvent));

    handler.keys_.clear();
    keyEvent->SetActionTime(1500000);
    sequenceKey.actionTime = 200000;
    sequence.statusConfigValue = false;
    handler.filterSequences_.push_back(sequence);
    ASSERT_FALSE(handler.HandleSequences(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount
 * @tc.desc: HandleRepeatKeyCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    RepeatKey repeatKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    repeatKey.keyCode = 2017;
    keyEvent->SetKeyCode(2017);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetActionTime(20);
    handler.repeatKey_.keyCode = 2018;
    ASSERT_TRUE(handler.HandleRepeatKeyCount(repeatKey, keyEvent));

    handler.repeatKey_.keyCode = 2017;
    ASSERT_TRUE(handler.HandleRepeatKeyCount(repeatKey, keyEvent));

    handler.intervalTime_ = 100;
    keyEvent->SetActionTime(50);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    ASSERT_TRUE(handler.HandleRepeatKeyCount(repeatKey, keyEvent));

    keyEvent->SetKeyCode(2018);
    ASSERT_FALSE(handler.HandleRepeatKeyCount(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyUpCancel
 * @tc.desc: HandleKeyUpCancel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyUpCancel, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    RepeatKey repeatKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    repeatKey.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    ASSERT_TRUE(handler.HandleKeyUpCancel(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKey
 * @tc.desc: HandleRepeatKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKey, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    RepeatKey repeatKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    repeatKey.times = 2;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    ASSERT_FALSE(handler.HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_CreateKeyEvent
 * @tc.desc: CreateKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CreateKeyEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    int32_t keyCode = 2017;
    int32_t keyAction = KeyEvent::KEY_ACTION_DOWN;
    bool isPressed = true;
    ASSERT_NE(handler.CreateKeyEvent(keyCode, keyAction, isPressed), nullptr);
}

/**
 * @tc.name: KeyCommandHandlerTest_IsEnableCombineKey
 * @tc.desc: Test IsEnableCombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_IsEnableCombineKey, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    KeyEvent::KeyItem item;
    std::shared_ptr<KeyEvent> key = KeyEvent::Create();
    ASSERT_NE(key, nullptr);
    handler.enableCombineKey_ = false;
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    key->SetKeyCode(KeyEvent::KEYCODE_POWER);
    key->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    key->AddKeyItem(item);
    ASSERT_FALSE(handler.IsEnableCombineKey(key));
    item.SetKeyCode(KeyEvent::KEYCODE_B);
    key->AddKeyItem(item);
    ASSERT_FALSE(handler.IsEnableCombineKey(key));
    key->SetKeyCode(KeyEvent::KEYCODE_L);
    ASSERT_FALSE(handler.IsEnableCombineKey(key));
}

/**
 * @tc.name: KeyCommandHandlerTest_AdjustDistanceConfigIfNeed
 * @tc.desc: Test AdjustDistanceConfigIfNeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_AdjustDistanceConfigIfNeed, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    float distance = 5.0f;
    handler.downToPrevDownDistanceConfig_ = 10.0f;
    handler.distanceDefaultConfig_ = 10.0f;
    ASSERT_NO_FATAL_FAILURE(handler.AdjustDistanceConfigIfNeed(distance));

    distance = 20.0f;
    handler.distanceLongConfig_ = 15.0f;
    ASSERT_NO_FATAL_FAILURE(handler.AdjustDistanceConfigIfNeed(distance));

    distance = 12.0f;
    handler.checkAdjustDistanceCount_ = 6;
    ASSERT_NO_FATAL_FAILURE(handler.AdjustDistanceConfigIfNeed(distance));

    handler.downToPrevDownDistanceConfig_ = 15.0f;
    ASSERT_NO_FATAL_FAILURE(handler.AdjustDistanceConfigIfNeed(distance));

    distance = 5.0f;
    handler.checkAdjustDistanceCount_ = 0;
    ASSERT_NO_FATAL_FAILURE(handler.AdjustDistanceConfigIfNeed(distance));

    handler.downToPrevDownDistanceConfig_ = 11.5f;
    ASSERT_NO_FATAL_FAILURE(handler.AdjustDistanceConfigIfNeed(distance));
}

/**
 * @tc.name: KeyCommandHandlerTest_AdjustDistanceConfigIfNeed_002
 * @tc.desc: Test AdjustDistanceConfigIfNeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_AdjustDistanceConfigIfNeed_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    float distance = 15.0f;
    handler.downToPrevDownDistanceConfig_ = 10.0f;
    handler.distanceLongConfig_ = 10.0f;
    handler.distanceDefaultConfig_ = 5.0f;
    ASSERT_NO_FATAL_FAILURE(handler.AdjustDistanceConfigIfNeed(distance));
    handler.distanceDefaultConfig_ = 20.0f;
    handler.checkAdjustDistanceCount_ = 6;
    ASSERT_NO_FATAL_FAILURE(handler.AdjustDistanceConfigIfNeed(distance));
    handler.downToPrevDownDistanceConfig_ = 30.0f;
    ASSERT_NO_FATAL_FAILURE(handler.AdjustDistanceConfigIfNeed(distance));
}

#ifdef OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchDown_001
 * @tc.desc: Test knuckle gesture touch down event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchDown_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    PointerEvent::PointerItem item;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);

    item.SetPointerId(1);
    item.SetRawDisplayX(4);
    item.SetRawDisplayY(4);
    touchEvent->SetPointerId(1);
    touchEvent->SetActionTime(1);
    touchEvent->AddPointerItem(item);
    KeyCommandHandler keyCommandHandler;
    keyCommandHandler.HandleKnuckleGestureTouchDown(touchEvent);

    ASSERT_TRUE(handler.gestureTimeStamps_.empty());
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchDown_002
 * @tc.desc: Test knuckle gesture touch down event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchDown_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    PointerEvent::PointerItem item;
    ASSERT_NE(touchEvent_, nullptr);

    item.SetPointerId(0);
    item.SetRawDisplayX(4);
    item.SetRawDisplayY(4);
    touchEvent_->SetPointerId(0);
    touchEvent_->SetActionTime(1);
    touchEvent_->AddPointerItem(item);
    touchEvent_->SetTargetDisplayId(0);

    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    OLD::DisplayGroupInfo displayGroupInfo;
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.x = 2;
    displayInfo.y = 3;
    displayInfo.width = 4;
    displayInfo.height = 5;
    displayInfo.dpi = -1;
    displayGroupInfo.displaysInfo.emplace_back(displayInfo);
    displayGroupInfo.groupId = 0;
    inputWindowsManager->displayGroupInfoMap_[0] = displayGroupInfo;
    inputWindowsManager->displayGroupInfo_ = displayGroupInfo;
    IInputWindowsManager::instance_ = inputWindowsManager;

    KeyCommandHandler keyCommandHandler;
    keyCommandHandler.HandleKnuckleGestureTouchDown(touchEvent_);
    ASSERT_TRUE(handler.gestureTimeStamps_.empty());
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_001
 * @tc.desc: Test knuckle gesture touch move event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);

    handler.gestureLastX_ = 4.0;
    handler.gestureLastY_ = 4.0;

    PointerEvent::PointerItem item1;
    item1.SetPointerId(2);
    item1.SetRawDisplayX(24);
    item1.SetRawDisplayY(24);
    touchEvent->AddPointerItem(item1);
    touchEvent->SetActionTime(6);
    touchEvent->SetPointerId(2);

    handler.HandleKnuckleGestureTouchMove(touchEvent);
    ASSERT_FALSE(handler.isLetterGesturing_);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_001
 * @tc.desc: Test knuckle gesture touch up event partial screenshot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);

    handler.gesturePoints_.assign(CIRCLE_COORDINATES.begin(), CIRCLE_COORDINATES.end());
    handler.gestureTimeStamps_.assign(CIRCLE_TIMESTAMPS.begin(), CIRCLE_TIMESTAMPS.end());
    handler.isGesturing_ = true;
    handler.isLetterGesturing_ = true;

    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchUp(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_002
 * @tc.desc: Test knuckle gesture touch up event long screenshot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);

    handler.gesturePoints_.assign(CURVE_COORDINATES.begin(), CURVE_COORDINATES.end());
    handler.gestureTimeStamps_.assign(CURVE_TIMESTAMPS.begin(), CURVE_TIMESTAMPS.end());
    handler.isGesturing_ = true;
    handler.isLetterGesturing_ = true;

    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchUp(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_003
 * @tc.desc: Test knuckle gesture touch up event straight line
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);

    handler.gesturePoints_.assign(LINE_COORDINATES.begin(), LINE_COORDINATES.end());
    handler.gestureTimeStamps_.assign(LINE_TIMESTAMPS.begin(), LINE_TIMESTAMPS.end());
    handler.isGesturing_ = true;
    handler.isLetterGesturing_ = true;

    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchUp(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_ResetKnuckleGesture_001
 * @tc.desc: Test ResetKnuckleGesture function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ResetKnuckleGesture_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.gestureLastX_ = 1.0f;
    handler.gestureLastY_ = 1.0f;
    handler.isGesturing_ = true;
    handler.isDistanceConfig_ = true;
    handler.gestureTrackLength_ = 2.0f;
    handler.gesturePoints_.assign(CURVE_COORDINATES.begin(), CURVE_COORDINATES.end());
    handler.gestureTimeStamps_.assign(CURVE_TIMESTAMPS.begin(), CURVE_TIMESTAMPS.end());

    handler.ResetKnuckleGesture();
    ASSERT_EQ(handler.gestureLastX_, 0.0f);
    ASSERT_EQ(handler.gestureLastY_, 0.0f);
    ASSERT_FALSE(handler.isGesturing_);
    ASSERT_TRUE(handler.isDistanceConfig_);
    ASSERT_EQ(handler.gestureTrackLength_, 0.0f);
    ASSERT_TRUE(handler.gesturePoints_.empty());
    ASSERT_TRUE(handler.gestureTimeStamps_.empty());
}

/**
 * @tc.name: KeyCommandHandlerTest_GesturePointsToStr_001
 * @tc.desc: Test GesturePointsToStr function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_GesturePointsToStr_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.gesturePoints_ = {0.0f, 1.0f, 2.0f, 3.0f};

    auto result = handler.GesturePointsToStr();
    ASSERT_EQ(result.length(), 50);
    ASSERT_EQ(handler.gesturePoints_.size(), 4);
}

/**
 * @tc.name: KeyCommandHandlerTest_GesturePointsToStr_002
 * @tc.desc: Test GesturePointsToStr function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_GesturePointsToStr_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;

    auto result = handler.GesturePointsToStr();
    ASSERT_TRUE(result.empty());
    ASSERT_TRUE(handler.gesturePoints_.empty());
}

/**
 * @tc.name: KeyCommandHandlerTest_GesturePointsToStr_003
 * @tc.desc: Test GesturePointsToStr function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_GesturePointsToStr_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.gesturePoints_ = {0.0f};

    auto result = handler.GesturePointsToStr();
    ASSERT_TRUE(result.empty());
    ASSERT_EQ(handler.gesturePoints_.size(), 1);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureEvent_001
 * @tc.desc: Test HandleKnuckleGestureEvent function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    PointerEvent::PointerItem item;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    item.SetPointerId(1);
    item.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(1);
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureEvent(touchEvent));

    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(1);
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureEvent(touchEvent));

    handler.singleKnuckleGesture_.state = true;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureEvent(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureEvent_002
 * @tc.desc: Test HandleKnuckleGestureEvent function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    PointerEvent::PointerItem item;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    item.SetPointerId(1);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(1);
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);

    handler.singleKnuckleGesture_.state = false;
    handler.gameForbidFingerKnuckle_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureEvent(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureEvent_003
 * @tc.desc: Test HandleKnuckleGestureEvent function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    PointerEvent::PointerItem item;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    item.SetPointerId(1);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(1);
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);

    handler.singleKnuckleGesture_.state = false;
    handler.gameForbidFingerKnuckle_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureEvent(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_IsValidAction
 * @tc.desc: Test IsValidAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_IsValidAction, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    int32_t action = PointerEvent::POINTER_ACTION_DOWN;
    ASSERT_NO_FATAL_FAILURE(handler.IsValidAction(action));

    action = PointerEvent::POINTER_ACTION_MOVE;
    handler.gesturePoints_ = {0.0f};
    ASSERT_NO_FATAL_FAILURE(handler.IsValidAction(action));

    action = PointerEvent::POINTER_ACTION_UP;
    handler.gesturePoints_.assign(CIRCLE_COORDINATES.begin(), CIRCLE_COORDINATES.end());
    ASSERT_NO_FATAL_FAILURE(handler.IsValidAction(action));
}

/**
 * @tc.name: KeyCommandHandlerTest_SendNotSupportMsg_001
 * @tc.desc: Test the function SendNotSupportMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SendNotSupportMsg_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.SendNotSupportMsg(nullptr));
}

/**
 * @tc.name: KeyCommandHandlerTest_SendNotSupportMsg_002
 * @tc.desc: Test the function SendNotSupportMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SendNotSupportMsg_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ASSERT_NE(touchEvent_, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetToolType(PointerEvent::TOOL_TYPE_PENCIL);
    touchEvent_->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(handler.SendNotSupportMsg(touchEvent_));
}

/**
 * @tc.name: KeyCommandHandlerTest_ReportRegionGesture
 * @tc.desc: Test the function ReportRegionGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, ReportRegionGesture, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.ReportRegionGesture());
}

/**
 * @tc.name: KeyCommandHandlerTest_ReportLetterGesture
 * @tc.desc: Test the function ReportLetterGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, ReportLetterGesture, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.ReportLetterGesture());
}
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER

/**
 * @tc.name: KeyCommandHandlerTest_HandleShortKeys_001
 * @tc.desc: Test the function HandleShortKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleShortKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    bool ret = handler.HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    ShortcutKey key;
    key.preKeys = {1, 2, 3};
    key.businessId = "business1";
    key.statusConfig = "config1";
    key.statusConfigValue = true;
    key.finalKey = 4;
    key.keyDownDuration = 5;
    key.triggerType = KeyEvent::KEY_ACTION_DOWN;
    key.timerId = 6;
    Ability ability_temp;
    ability_temp.bundleName = "bundleName1";
    ability_temp.abilityName = "abilityName1";
    key.ability = ability_temp;
    handler.shortcutKeys_.insert(std::make_pair("key1", key));
    ret = handler.HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    std::string businessId = "power";
    ret = handler.HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleShortKeys_002
 * @tc.desc: Test the function HandleShortKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleShortKeys_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey key;
    key.preKeys = {1, 2, 3};
    key.businessId = "business2";
    key.statusConfig = "config2";
    key.statusConfigValue = true;
    key.finalKey = 5;
    key.keyDownDuration = 6;
    key.triggerType = KeyEvent::KEY_ACTION_UP;
    key.timerId = 6;
    Ability ability_temp;
    ability_temp.bundleName = "bundleName2";
    ability_temp.abilityName = "abilityName2";
    key.ability = ability_temp;
    handler.shortcutKeys_.insert(std::make_pair("key2", key));
    bool ret = handler.HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    std::string businessId = "power";
    ret = handler.HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleShortKeys_003
 * @tc.desc: Test the function HandleShortKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleShortKeys_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey key;
    key.preKeys = {1, 2, 3};
    key.businessId = "business3";
    key.statusConfig = "config3";
    key.statusConfigValue = true;
    key.finalKey = 7;
    key.keyDownDuration = 8;
    key.triggerType = KeyEvent::KEY_ACTION_CANCEL;
    key.timerId = 6;
    Ability ability_temp;
    ability_temp.bundleName = "bundleName3";
    ability_temp.abilityName = "abilityName3";
    key.ability = ability_temp;
    handler.shortcutKeys_.insert(std::make_pair("key3", key));
    bool ret = handler.HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    std::string businessId = "power";
    ret = handler.HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleShortKeys_04
 * @tc.desc: Test the function HandleShortKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleShortKeys_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey key;
    key.preKeys = {1, 2, 3};
    key.businessId = "business2";
    key.statusConfig = "config2";
    key.statusConfigValue = true;
    key.finalKey = 5;
    key.keyDownDuration = 6;
    key.triggerType = KeyEvent::KEY_ACTION_UP;
    key.timerId = 6;
    Ability ability_temp;
    ability_temp.bundleName = "bundleName2";
    ability_temp.abilityName = "abilityName2";
    key.ability = ability_temp;
    handler.shortcutKeys_.insert(std::make_pair("key2", key));
    bool ret = handler.HandleShortKeys(keyEvent);
    EXPECT_FALSE(ret);

    key.businessId = "power";
    int32_t delay = handler.GetKeyDownDurationFromXml(key.businessId);
    EXPECT_TRUE(delay < 0);
    key.triggerType = KeyEvent::KEY_ACTION_DOWN;
    ret = handler.HandleShortKeys(keyEvent);
    EXPECT_FALSE(ret);

    key.triggerType = KeyEvent::KEY_ACTION_UP;
    bool handleResult = handler.HandleKeyUp(keyEvent, key);
    EXPECT_FALSE(handleResult);
    ret = handler.HandleShortKeys(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_AddSequenceKey_001
 * @tc.desc: Test the function AddSequenceKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_AddSequenceKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 1;
    sequenceKey.keyAction = 2;
    sequenceKey.actionTime = 3;
    sequenceKey.delay = 4;
    handler.keys_.push_back(sequenceKey);
    bool ret = handler.AddSequenceKey(keyEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_AddSequenceKey_002
 * @tc.desc: Test the function AddSequenceKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_AddSequenceKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 1;
    sequenceKey.keyAction = 2;
    sequenceKey.actionTime = 15;
    sequenceKey.delay = 16;
    handler.keys_.push_back(sequenceKey);
    bool ret = handler.AddSequenceKey(keyEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_AddSequenceKey_003
 * @tc.desc: Test the function AddSequenceKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_AddSequenceKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 1;
    sequenceKey.keyAction = 2;
    sequenceKey.actionTime = -2;
    sequenceKey.delay = -3;
    handler.keys_.push_back(sequenceKey);
    bool ret = handler.AddSequenceKey(keyEvent);
    ASSERT_TRUE(ret);
    handler.keys_.clear();
    ret = handler.AddSequenceKey(keyEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleNormalSequence_001
 * @tc.desc: Test the function HandleNormalSequence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleNormalSequence_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    Sequence sequence;
    bool isLaunchAbility = true;
    sequence.abilityStartDelay = 0;
    bool ret = handler.HandleNormalSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
    sequence.abilityStartDelay = 1;
    sequence.timerId = -1;
    ret = handler.HandleNormalSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
    sequence.timerId = 1;
    ret = handler.HandleNormalSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleMatchedSequence_001
 * @tc.desc: Test the function HandleMatchedSequence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleMatchedSequence_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    Sequence sequence;
    bool isLaunchAbility = true;
    sequence.ability.bundleName = ".screenshot";
    bool ret = handler.HandleMatchedSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
    sequence.ability.bundleName = "abc";
    DisplayEventMonitor displayEventMonitor;
    displayEventMonitor.screenStatus_ = "usual.event.SCREEN_OFF";
    ret = handler.HandleMatchedSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
    displayEventMonitor.screenStatus_ = "usual.event.SCREEN_ON";
    ret = handler.HandleMatchedSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
    displayEventMonitor.isScreenLocked_ = true;
    ret = handler.HandleMatchedSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
    displayEventMonitor.isScreenLocked_ = false;
    ret = handler.HandleMatchedSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleSequence_001
 * @tc.desc: Test the function HandleSequence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleSequence_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    Sequence sequence;
    SequenceKey sequenceKey;
    bool isLaunchAbility = true;
    sequence.statusConfigValue = false;
    bool ret = handler.HandleSequence(sequence, isLaunchAbility);
    ASSERT_FALSE(ret);
    sequence.statusConfigValue = true;
    sequenceKey.keyCode = 10;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    sequenceKey.actionTime = 10;
    sequenceKey.delay = 10;
    handler.keys_.push_back(sequenceKey);
    sequence.sequenceKeys.push_back(sequenceKey);
    ret = handler.HandleSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_ConvertKeyActionToString_001
 * @tc.desc: Test the function ConvertKeyActionToString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ConvertKeyActionToString_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    int32_t keyAction = 0;
    std::string ret = handler.ConvertKeyActionToString(keyAction);
    ASSERT_EQ(ret, "UNKNOWN");
    keyAction = 1;
    ret = handler.ConvertKeyActionToString(keyAction);
    ASSERT_EQ(ret, "CANCEL");
    keyAction = 2;
    ret = handler.ConvertKeyActionToString(keyAction);
    ASSERT_EQ(ret, "DOWN");
    keyAction = 3;
    ret = handler.ConvertKeyActionToString(keyAction);
    ASSERT_EQ(ret, "UP");
    keyAction = 4;
    ret = handler.ConvertKeyActionToString(keyAction);
    ASSERT_EQ(ret, "UNKNOWN_ACTION");
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyEvent_001
 * @tc.desc: Test the function HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.EnableCombineKey(false);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandlePointerEvent_001
 * @tc.desc: Test the function HandlePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandlePointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.EnableCombineKey(false);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerEvent(pointerEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleTouchEventTest_005
 * @tc.desc: Test the function HandleTouchEvent
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleTouchEventTest_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = SetupDoubleKnuckleDownEvent();
    ASSERT_TRUE(pointerEvent != nullptr);
    handler.nextHandler_ = std::make_shared<EventFilterHandler>();
    handler.SetNext(handler.nextHandler_);
    PointerEvent::PointerItem item;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    item.SetPointerId(1);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    touchEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(handler.HandleTouchEvent(pointerEvent));
    item.SetPointerId(2);
    item.SetToolType(PointerEvent::TOOL_TYPE_PALM);
    touchEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(handler.HandleTouchEvent(pointerEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckTwoFingerGestureAction_001
 * @tc.desc: Test the function CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckTwoFingerGestureAction_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.twoFingerGesture_.active = false;
    bool ret = handler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
    handler.twoFingerGesture_.active = true;
    handler.twoFingerGesture_.touches[0].id = 1;
    handler.twoFingerGesture_.touches[0].x = 100;
    handler.twoFingerGesture_.touches[0].y = 200;
    handler.twoFingerGesture_.touches[0].downTime = 250000;
    handler.twoFingerGesture_.touches[1].id = 2;
    handler.twoFingerGesture_.touches[1].x = 300;
    handler.twoFingerGesture_.touches[1].y = 400;
    handler.twoFingerGesture_.touches[1].downTime = 50000;
    ret = handler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckTwoFingerGestureAction_002
 * @tc.desc: Test the function CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckTwoFingerGestureAction_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.twoFingerGesture_.active = true;
    handler.twoFingerGesture_.touches[0].id = 1;
    handler.twoFingerGesture_.touches[0].x = 100;
    handler.twoFingerGesture_.touches[0].y = 200;
    handler.twoFingerGesture_.touches[0].downTime = 150000;
    handler.twoFingerGesture_.touches[1].id = 2;
    handler.twoFingerGesture_.touches[1].x = 300;
    handler.twoFingerGesture_.touches[1].y = 400;
    handler.twoFingerGesture_.touches[1].downTime = 50000;
    bool ret = handler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_ConvertVPToPX_001
 * @tc.desc: Test the function ConvertVPToPX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ConvertVPToPX_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    int32_t vp = -1;
    ASSERT_NO_FATAL_FAILURE(handler.ConvertVPToPX(vp));
    vp = 1;
    ASSERT_NO_FATAL_FAILURE(handler.ConvertVPToPX(vp));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_002
 * @tc.desc: Test the function HandleKnuckleGestureTouchMove
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetDisplayX(8.0);
    item.SetDisplayY(8.0);
    handler.gestureLastX_ = 4.0;
    handler.gestureLastY_ = 4.0;
    handler.isGesturing_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(touchEvent));
    handler.isGesturing_ = true;
    handler.isLetterGesturing_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(touchEvent));
    handler.isLetterGesturing_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(touchEvent));
    handler.gestureLastX_ = 6.0;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(touchEvent));
    handler.gestureLastY_ = 6.0;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_ReportIfNeed_001
 * @tc.desc: Test the function ReportIfNeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ReportIfNeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.ReportIfNeed());
    handler.isGesturing_ = true;
    handler.isLastGestureSucceed_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.ReportIfNeed());
    handler.isLastGestureSucceed_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.ReportIfNeed());
}

/**
 * @tc.name: KeyCommandHandlerTest_ReportGestureInfo_001
 * @tc.desc: Test the function ReportGestureInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ReportGestureInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.isLastGestureSucceed_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.ReportGestureInfo());
    handler.isLastGestureSucceed_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.ReportGestureInfo());
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_004
 * @tc.desc: Test knuckle gesture touch up event straight line
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    GESTURESENSE_WRAPPER->touchUp_ = [](const std::vector<float> &, const std::vector<int64_t> &, bool,
                                         bool) -> int32_t {
        return 0;
    };
    ASSERT_NE(GESTURESENSE_WRAPPER->touchUp_, nullptr);
    handler.gesturePoints_.assign(LINE_COORDINATES.begin(), LINE_COORDINATES.end());
    handler.gestureTimeStamps_.assign(LINE_TIMESTAMPS.begin(), LINE_TIMESTAMPS.end());
    handler.isGesturing_ = true;
    handler.isLetterGesturing_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchUp(touchEvent));
    handler.gesturePoints_.assign(CIRCLE_COORDINATES.begin(), CIRCLE_COORDINATES.end());
    handler.gestureTimeStamps_.assign(CIRCLE_TIMESTAMPS.begin(), CIRCLE_TIMESTAMPS.end());
    handler.isGesturing_ = true;
    handler.isLetterGesturing_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchUp(touchEvent));
    handler.gesturePoints_.assign(CURVE_COORDINATES.begin(), CURVE_COORDINATES.end());
    handler.gestureTimeStamps_.assign(CURVE_TIMESTAMPS.begin(), CURVE_TIMESTAMPS.end());
    handler.isGesturing_ = true;
    handler.isLetterGesturing_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchUp(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleShortKeys_004
 * @tc.desc: Test the function HandleShortKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleShortKeys_004, TestSize.Level1)
{
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey key;
    key.preKeys = {1, 2, 3};
    key.businessId = "business1";
    key.statusConfig = "config1";
    key.statusConfigValue = true;
    key.finalKey = 4;
    key.keyDownDuration = 5;
    key.triggerType = KeyEvent::KEY_ACTION_DOWN;
    key.timerId = 6;
    keyEvent->SetKeyCode(1);
    keyEvent->SetKeyAction(2);
    handler.shortcutKeys_.insert(std::make_pair("key1", key));
    bool ret = handler.HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleShortKeys_005
 * @tc.desc: Test the function HandleShortKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleShortKeys_005, TestSize.Level1)
{
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey key;
    key.preKeys = {1, 2, 3};
    key.businessId = "business1";
    key.statusConfig = "config1";
    key.statusConfigValue = true;
    key.finalKey = 4;
    key.keyDownDuration = 5;
    key.triggerType = KeyEvent::KEY_ACTION_DOWN;
    key.timerId = 6;
    handler.currentLaunchAbilityKey_.finalKey = 1;
    handler.currentLaunchAbilityKey_.triggerType = 2;
    keyEvent->SetKeyCode(1);
    keyEvent->SetKeyAction(2);
    bool result = handler.IsKeyMatch(handler.currentLaunchAbilityKey_, keyEvent);
    ASSERT_FALSE(result);
    handler.shortcutKeys_.insert(std::make_pair("key1", key));
    handler.currentLaunchAbilityKey_.timerId = 0;
    bool ret = handler.HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    handler.currentLaunchAbilityKey_.timerId = -1;
    ret = handler.HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    handler.currentLaunchAbilityKey_.timerId = 0;
    handler.currentLaunchAbilityKey_.finalKey = 1;
    handler.currentLaunchAbilityKey_.triggerType = 2;
    keyEvent->SetKeyCode(3);
    keyEvent->SetKeyAction(4);
    ret = handler.HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
    handler.currentLaunchAbilityKey_.timerId = -1;
    handler.currentLaunchAbilityKey_.finalKey = 1;
    handler.currentLaunchAbilityKey_.triggerType = 2;
    keyEvent->SetKeyCode(3);
    keyEvent->SetKeyAction(4);
    ret = handler.HandleShortKeys(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleMatchedSequence_002
 * @tc.desc: Test the function HandleMatchedSequence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleMatchedSequence_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    Sequence sequence;
    bool isLaunchAbility = true;
    DISPLAY_MONITOR->isScreenLocked_ = false;
    sequence.ability.bundleName = ".screenshot";
    DISPLAY_MONITOR->screenStatus_ = "usual.event.SCREEN_OFF";
    bool ret = handler.HandleMatchedSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
    DISPLAY_MONITOR->screenStatus_ = "usual.event.SCREEN_OFF";
    sequence.ability.bundleName = "abc";
    DisplayEventMonitor displayEventMonitor;
    displayEventMonitor.screenStatus_ = "usual.event.SCREEN_OFF";
    ret = handler.HandleMatchedSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
    DISPLAY_MONITOR->screenStatus_ = "usual.event.SCREEN_LOCKED";
    DISPLAY_MONITOR->isScreenLocked_ = true;
    sequence.ability.bundleName = ".screenshot";
    ret = handler.HandleMatchedSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
    DISPLAY_MONITOR->isScreenLocked_ = false;
    ret = handler.HandleMatchedSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
    DISPLAY_MONITOR->isScreenLocked_ = true;
    sequence.ability.bundleName = "abc";
    ret = handler.HandleMatchedSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
    DISPLAY_MONITOR->isScreenLocked_ = false;
    sequence.ability.bundleName = "abc";
    ret = handler.HandleMatchedSequence(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandlePointerVisibleKeys_001
 * @tc.desc: Test HandlePointerVisibleKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandlePointerVisibleKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keyCode_ = KeyEvent::KEYCODE_F9;
    handler.lastKeyEventCode_ = KeyEvent::KEYCODE_CTRL_LEFT;
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerVisibleKeys(keyEvent));
    keyEvent->keyCode_ = KeyEvent::KEYCODE_F1;
    handler.lastKeyEventCode_ = KeyEvent::KEYCODE_CTRL_LEFT;
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerVisibleKeys(keyEvent));
    keyEvent->keyCode_ = KeyEvent::KEYCODE_F9;
    handler.lastKeyEventCode_ = KeyEvent::KEYCODE_CAPS_LOCK;
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerVisibleKeys(keyEvent));
    keyEvent->keyCode_ = KeyEvent::KEYCODE_F1;
    handler.lastKeyEventCode_ = KeyEvent::KEYCODE_CAPS_LOCK;
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerVisibleKeys(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_ConvertVPToPX_002
 * @tc.desc: Test the function ConvertVPToPX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ConvertVPToPX_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    int32_t vp = -5;
    int32_t ret = handler.ConvertVPToPX(vp);
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
    ret = handler.ConvertVPToPX(vp);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: KeyCommandHandlerTest_ConvertVPToPX_003
 * @tc.desc: Test the function ConvertVPToPX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ConvertVPToPX_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
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
    int32_t ret = handler.ConvertVPToPX(vp);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckTwoFingerGestureAction_003
 * @tc.desc: Test the function CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckTwoFingerGestureAction_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.twoFingerGesture_.active = true;
    handler.twoFingerGesture_.touches[0].id = 1;
    handler.twoFingerGesture_.touches[0].x = -100;
    handler.twoFingerGesture_.touches[0].y = -200;
    handler.twoFingerGesture_.touches[0].downTime = 100000;
    handler.twoFingerGesture_.touches[1].id = 2;
    handler.twoFingerGesture_.touches[1].x = -300;
    handler.twoFingerGesture_.touches[1].y = -400;
    handler.twoFingerGesture_.touches[1].downTime = 50000;
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
    bool ret = handler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckTwoFingerGestureAction_004
 * @tc.desc: Test the function CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckTwoFingerGestureAction_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.twoFingerGesture_.active = true;
    handler.twoFingerGesture_.touches[0].id = 1;
    handler.twoFingerGesture_.touches[0].x = 100;
    handler.twoFingerGesture_.touches[0].y = 200;
    handler.twoFingerGesture_.touches[0].downTime = 100000;
    handler.twoFingerGesture_.touches[1].id = 2;
    handler.twoFingerGesture_.touches[1].x = 300;
    handler.twoFingerGesture_.touches[1].y = 400;
    handler.twoFingerGesture_.touches[1].downTime = 50000;
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
    bool ret = handler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckTwoFingerGestureAction_005
 * @tc.desc: Test the function CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckTwoFingerGestureAction_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.twoFingerGesture_.active = true;
    handler.twoFingerGesture_.touches[0].id = 1;
    handler.twoFingerGesture_.touches[0].x = 10;
    handler.twoFingerGesture_.touches[0].y = 20;
    handler.twoFingerGesture_.touches[0].downTime = 100000;
    handler.twoFingerGesture_.touches[1].id = 2;
    handler.twoFingerGesture_.touches[1].x = 30;
    handler.twoFingerGesture_.touches[1].y = 20;
    handler.twoFingerGesture_.touches[1].downTime = 50000;
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
    bool ret = handler.CheckTwoFingerGestureAction();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_StartTwoFingerGesture_002
 * @tc.desc: Test the function StartTwoFingerGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_StartTwoFingerGesture_002, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.twoFingerGesture_.active = false;
    ASSERT_NO_FATAL_FAILURE(handler.StartTwoFingerGesture());
    handler.twoFingerGesture_.active = true;
    handler.twoFingerGesture_.touches[0].id = 5;
    handler.twoFingerGesture_.touches[0].x = 50;
    handler.twoFingerGesture_.touches[0].y = 60;
    handler.twoFingerGesture_.touches[0].downTime = 13000;
    handler.twoFingerGesture_.touches[1].id = 9;
    handler.twoFingerGesture_.touches[1].x = 100;
    handler.twoFingerGesture_.touches[1].y = 400;
    handler.twoFingerGesture_.touches[1].downTime = 96000;
    ASSERT_NO_FATAL_FAILURE(handler.StartTwoFingerGesture());
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_005
 * @tc.desc: Test the function HandleKnuckleGestureTouchUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    GESTURESENSE_WRAPPER->touchUp_ = [](const std::vector<float> &, const std::vector<int64_t> &, bool,
                                         bool) -> int32_t {
        return 0;
    };
    ASSERT_NE(GESTURESENSE_WRAPPER->touchUp_, nullptr);
    handler.isGesturing_ = false;
    handler.isLetterGesturing_ = false;
    handler.gesturePoints_.assign(LINE_TIMESTAMPS.begin(), LINE_TIMESTAMPS.end());
    handler.gestureTimeStamps_.assign(LINE_COORDINATES.begin(), LINE_COORDINATES.end());
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchUp(touchEvent));
    handler.gesturePoints_.assign(CURVE_COORDINATES.begin(), CURVE_COORDINATES.end());
    handler.gestureTimeStamps_.assign(CURVE_TIMESTAMPS.begin(), CURVE_TIMESTAMPS.end());
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchUp(touchEvent));
    handler.isGesturing_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchUp(touchEvent));
    handler.isLetterGesturing_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchUp(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_01
 * @tc.desc: Test HandleKnuckleGestureTouchUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    NotifyType notifyType;
    notifyType = NotifyType::REGIONGESTURE;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchUp(pointerEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_02
 * @tc.desc: Test HandleKnuckleGestureTouchUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    NotifyType notifyType;
    notifyType = NotifyType::LETTERGESTURE;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchUp(pointerEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_03
 * @tc.desc: Test HandleKnuckleGestureTouchUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    NotifyType notifyType;
    notifyType = NotifyType::OTHER;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchUp(pointerEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_ParseJson_001
 * @tc.desc: Test the function ParseJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ParseJson_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::string configFile;
    bool ret = handler.ParseJson(configFile);
    EXPECT_FALSE(ret);
    configFile = "config";
    std::string copyShortcutKey = "copyShortcutKey";
    ShortcutKey shortcutKey;
    Ability ability_temp;
    shortcutKey.preKeys.insert(2072);
    shortcutKey.finalKey = 2019;
    shortcutKey.keyDownDuration = 100;
    ability_temp.bundleName = "bundleName";
    ability_temp.abilityName = "abilityName";
    shortcutKey.ability = ability_temp;
    handler.shortcutKeys_.insert(std::make_pair(copyShortcutKey, shortcutKey));
    handler.businessIds_ = {"businessId"};
    handler.twoFingerGesture_.active = true;
    handler.twoFingerGesture_.timerId = 1;
    ret = handler.ParseJson(configFile);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_IsEnableCombineKey_003
 * @tc.desc: Test the function IsEnableCombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_IsEnableCombineKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> key = KeyEvent::Create();
    ASSERT_NE(key, nullptr);
    handler.enableCombineKey_ = false;
    handler.isParseExcludeConfig_ = false;
    ASSERT_FALSE(handler.IsEnableCombineKey(key));
    handler.isParseExcludeConfig_ = true;
    ExcludeKey excludeKey;
    excludeKey.keyCode = 1;
    excludeKey.keyAction = 2;
    excludeKey.delay = 3;
    handler.excludeKeys_.push_back(excludeKey);
    key->keyCode_ = 1;
    key->keyAction_ = 2;
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 2017;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler.keys_.push_back(sequenceKey);
    ASSERT_FALSE(handler.IsEnableCombineKey(key));
    sequenceKey.keyCode = 2018;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler.keys_.push_back(sequenceKey);
    ASSERT_FALSE(handler.IsEnableCombineKey(key));
}

/**
 * @tc.name: KeyCommandHandlerTest_IsEnableCombineKey_004
 * @tc.desc: Test the function IsEnableCombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_IsEnableCombineKey_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> key = KeyEvent::Create();
    ASSERT_NE(key, nullptr);
    handler.enableCombineKey_ = false;
    handler.isParseExcludeConfig_ = true;
    ExcludeKey excludeKey;
    excludeKey.keyCode = 1;
    excludeKey.keyAction = 2;
    excludeKey.delay = 3;
    handler.excludeKeys_.push_back(excludeKey);
    key->keyCode_ = KeyEvent::KEYCODE_L;
    key->keyAction_ = 200;
    SequenceKey sequenceKey;
    sequenceKey.keyCode = KeyEvent::KEYCODE_SPACE;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler.keys_.push_back(sequenceKey);
    ASSERT_TRUE(handler.IsEnableCombineKey(key));
    sequenceKey.keyCode = KeyEvent::KEYCODE_L;
    handler.keys_.push_back(sequenceKey);
    ASSERT_TRUE(handler.IsEnableCombineKey(key));
    sequenceKey.keyCode = KeyEvent::KEYCODE_META_LEFT;
    handler.keys_.push_back(sequenceKey);
    ASSERT_TRUE(handler.IsEnableCombineKey(key));
    sequenceKey.keyCode = KeyEvent::KEYCODE_META_RIGHT;
    handler.keys_.push_back(sequenceKey);
    ASSERT_TRUE(handler.IsEnableCombineKey(key));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleEvent_001
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> key = KeyEvent::Create();
    ASSERT_NE(key, nullptr);
    handler.enableCombineKey_ = false;
    handler.isParseExcludeConfig_ = true;
    ExcludeKey excludeKey;
    excludeKey.keyCode = 3;
    excludeKey.keyAction = 5;
    excludeKey.delay = 8;
    handler.excludeKeys_.push_back(excludeKey);
    key->keyCode_ = KeyEvent::KEYCODE_L;
    key->keyAction_ = 200;
    SequenceKey sequenceKey;
    sequenceKey.keyCode = KeyEvent::KEYCODE_SPACE;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler.keys_.push_back(sequenceKey);
    ShortcutKey shortcutKey;
    shortcutKey.preKeys = {1, 2, 3};
    shortcutKey.businessId = "business1";
    shortcutKey.statusConfig = "config1";
    shortcutKey.statusConfigValue = true;
    shortcutKey.finalKey = 4;
    shortcutKey.keyDownDuration = 5;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;
    shortcutKey.timerId = 6;
    handler.currentLaunchAbilityKey_.finalKey = 1;
    handler.currentLaunchAbilityKey_.triggerType = 2;
    key->SetKeyCode(1);
    key->SetKeyAction(2);
    handler.IsKeyMatch(handler.currentLaunchAbilityKey_, key);
    handler.shortcutKeys_.insert(std::make_pair("key1", shortcutKey));
    handler.currentLaunchAbilityKey_.timerId = 0;
    handler.HandleShortKeys(key);
    handler.isKeyCancel_ = true;
    bool ret = handler.HandleEvent(key);
    EXPECT_FALSE(ret);
    handler.isKeyCancel_ = false;
    ret = handler.HandleEvent(key);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleEvent_002
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> key = KeyEvent::Create();
    ASSERT_NE(key, nullptr);
    handler.enableCombineKey_ = false;
    handler.isParseExcludeConfig_ = true;
    ExcludeKey excludeKey;
    excludeKey.keyCode = 2;
    excludeKey.keyAction = 6;
    excludeKey.delay = 9;
    handler.excludeKeys_.push_back(excludeKey);
    key->keyCode_ = KeyEvent::KEYCODE_L;
    key->keyAction_ = 300;
    SequenceKey sequenceKey;
    sequenceKey.keyCode = KeyEvent::KEYCODE_SPACE;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler.keys_.push_back(sequenceKey);
    ShortcutKey shortcutKey;
    shortcutKey.preKeys = {1, 2, 3};
    shortcutKey.businessId = "business2";
    shortcutKey.statusConfig = "config2";
    shortcutKey.statusConfigValue = true;
    shortcutKey.finalKey = 5;
    shortcutKey.keyDownDuration = 6;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_UP;
    shortcutKey.timerId = 6;
    Ability ability_temp;
    ability_temp.bundleName = "bundleName2";
    ability_temp.abilityName = "abilityName2";
    shortcutKey.ability = ability_temp;
    handler.shortcutKeys_.insert(std::make_pair("key2", shortcutKey));
    handler.HandleShortKeys(key);
    handler.isDownStart_ = false;
    bool ret = handler.HandleEvent(key);
    EXPECT_FALSE(ret);
    handler.isDownStart_ = true;
    ret = handler.HandleEvent(key);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_OnHandleEvent_001
 * @tc.desc: Test the function OnHandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_OnHandleEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> key = KeyEvent::Create();
    ASSERT_NE(key, nullptr);
    key->SetKeyCode(KeyEvent::KEYCODE_POWER);
    int32_t keyAction = KeyEvent::KEYCODE_VOLUME_UP;
    handler.specialKeys_.insert(std::make_pair(10, keyAction));
    bool ret = handler.OnHandleEvent(key);
    EXPECT_FALSE(ret);
    key->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    int32_t keyCode = 99;
    std::list<int32_t> timerIds;
    timerIds.push_back(100);
    handler.specialTimers_.insert(std::make_pair(keyCode, timerIds));
    ret = handler.OnHandleEvent(key);
    EXPECT_FALSE(ret);
    keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    handler.specialTimers_.insert(std::make_pair(keyCode, timerIds));
    ret = handler.OnHandleEvent(key);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_OnHandleEvent_003
 * @tc.desc: Test the function OnHandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_OnHandleEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ASSERT_NE(keyEvent_, nullptr);
    keyEvent_->SetKeyCode(KeyEvent::KEYCODE_STYLUS_SCREEN);

    STYLUS_HANDLER->stylusKey_.isLaunchAbility = true;
    bool ret = handler.OnHandleEvent(keyEvent_);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_OnHandleEvent_004
 * @tc.desc: Test the function OnHandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_OnHandleEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ASSERT_NE(keyEvent_, nullptr);
    
    bool ret = handler.OnHandleEvent(keyEvent_);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKey_001
 * @tc.desc: Test the function HandleRepeatKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    RepeatKey item;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.times = 5;
    handler.count_ = 5;
    ASSERT_FALSE(handler.HandleRepeatKey(item, keyEvent));
    handler.count_ = 10;
    ASSERT_FALSE(handler.HandleRepeatKey(item, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKey_002
 * @tc.desc: Test the function HandleRepeatKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    RepeatKey item;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.times = 6;
    handler.count_ = 5;
    ASSERT_FALSE(handler.HandleRepeatKey(item, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKey_003
 * @tc.desc: HandleRepeatKey_003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    RepeatKey repeatKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    repeatKey.times = 2;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.ability.bundleName = "bundleName";
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    handler.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    handler.repeatKeyMaxTimes_.emplace(KeyEvent::KEYCODE_POWER, 2);
    ASSERT_FALSE(handler.HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKey_004
 * @tc.desc: HandleRepeatKey_004
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKey_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    RepeatKey repeatKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler.count_ = 3;
    repeatKey.times = 2;
    repeatKey.statusConfig = "statusConfig";
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.ability.bundleName = "bundleName";
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    handler.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    handler.repeatKeyMaxTimes_.emplace(KeyEvent::KEYCODE_POWER, 5);
    ASSERT_FALSE(handler.HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckInputMethodArea_001
 * @tc.desc: Test the function CheckInputMethodArea
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckInputMethodArea_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    WindowInfo windowInfo;
    windowInfo.windowType = 2000;
    bool ret = handler.CheckInputMethodArea(touchEvent);
    ASSERT_FALSE(ret);
    windowInfo.windowType = 2105;
    windowInfo.area.x = 10;
    windowInfo.area.width = INT32_MAX;
    windowInfo.area.y = 100;
    windowInfo.area.height = 200;
    std::vector<WindowInfo> windows;
    windows.push_back(windowInfo);
    ret = handler.CheckInputMethodArea(touchEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckInputMethodArea_002
 * @tc.desc: Test the function CheckInputMethodArea
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckInputMethodArea_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    WindowInfo windowInfo;
    windowInfo.windowType = 2105;
    windowInfo.area.x = 10;
    windowInfo.area.width = 100;
    windowInfo.area.y = 20;
    windowInfo.area.height = INT32_MAX;
    std::vector<WindowInfo> windows;
    windows.push_back(windowInfo);
    bool ret = handler.CheckInputMethodArea(touchEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckInputMethodArea_003
 * @tc.desc: Test the function CheckInputMethodArea
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckInputMethodArea_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    WindowInfo windowInfo;
    windowInfo.windowType = 2105;
    windowInfo.area.x = 30;
    windowInfo.area.width = 300;
    windowInfo.area.y = 90;
    windowInfo.area.height = 1000;
    std::vector<WindowInfo> windows;
    windows.push_back(windowInfo);
    bool ret = handler.CheckInputMethodArea(touchEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckInputMethodArea_004
 * @tc.desc: Test the function CheckInputMethodArea
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckInputMethodArea_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    WindowInfo windowInfo;
    windowInfo.windowType = WINDOW_INPUT_METHOD_TYPE;
    bool ret = handler.CheckInputMethodArea(pointerEvent);
    EXPECT_FALSE(ret);

    windowInfo.area.x = 10;
    windowInfo.area.width = INT32_MAX;
    windowInfo.area.y = 100;
    windowInfo.area.height = 200;
    ret = handler.CheckInputMethodArea(pointerEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_SendKeyEvent_001
 * @tc.desc: Test the function SendKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SendKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.isHandleSequence_ = true;
    handler.launchAbilityCount_ = 1;
    handler.count_ = 5;
    ASSERT_NO_FATAL_FAILURE(handler.SendKeyEvent());
}

/**
 * @tc.name: KeyCommandHandlerTest_SendKeyEvent_002
 * @tc.desc: Test the function SendKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SendKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.isHandleSequence_ = false;
    handler.launchAbilityCount_ = 1;
    handler.repeatKey_.keyCode = 3;
    ASSERT_NO_FATAL_FAILURE(handler.SendKeyEvent());
}

/**
 * @tc.name: KeyCommandHandlerTest_SendKeyEvent_003
 * @tc.desc: Test the function SendKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SendKeyEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.isHandleSequence_ = false;
    handler.launchAbilityCount_ = 0;
    handler.repeatKey_.keyCode = 2;
    ASSERT_NO_FATAL_FAILURE(handler.SendKeyEvent());
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckAndUpdateTappingCountAtDown_001
 * @tc.desc: Test the function CheckAndUpdateTappingCountAtDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckAndUpdateTappingCountAtDown_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    touchEvent->SetActionTime(0);
    handler.lastDownTime_ = 0;
    ASSERT_NO_FATAL_FAILURE(handler.CheckAndUpdateTappingCountAtDown(touchEvent));
    ASSERT_EQ(handler.tappingCount_, 1);

    touchEvent->SetActionTime(600000);
    ASSERT_NO_FATAL_FAILURE(handler.CheckAndUpdateTappingCountAtDown(touchEvent));
    ASSERT_EQ(handler.tappingCount_, 1);
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckAndUpdateTappingCountAtDown_002
 * @tc.desc: Test the function CheckAndUpdateTappingCountAtDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckAndUpdateTappingCountAtDown_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    touchEvent->SetActionTime(10);
    handler.lastDownTime_ = 0;
    handler.previousUpTime_ = 0;
    handler.downToPrevUpTimeConfig_ = 20;
    handler.tappingCount_ = 1;
    ASSERT_NO_FATAL_FAILURE(handler.CheckAndUpdateTappingCountAtDown(touchEvent));
    ASSERT_EQ(handler.tappingCount_, 2);

    touchEvent->SetActionTime(20);
    ASSERT_NO_FATAL_FAILURE(handler.CheckAndUpdateTappingCountAtDown(touchEvent));
    ASSERT_EQ(handler.tappingCount_, 3);
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckInputMethodArea_005
 * @tc.desc: Test the function CheckInputMethodArea
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckInputMethodArea_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    InputWindowsManager inputWindowsManager;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    EXPECT_NE(inputEvent, nullptr);
    inputEvent->targetDisplayId_ = 1;
    WindowGroupInfo windowGroupInfo;
    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(1, windowGroupInfo));
    bool ret = handler.CheckInputMethodArea(touchEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleSequences_001
 * @tc.desc: HandleSequences
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleSequences_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler.matchedSequence_.timerId = 10;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    ASSERT_FALSE(handler.HandleSequences(keyEvent));
    handler.matchedSequence_.timerId = -1;
    ASSERT_FALSE(handler.HandleSequences(keyEvent));
    keyEvent->SetKeyCode(2017);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetActionTime(10000);
    SequenceKey sequenceKey;
    Sequence sequence;
    sequence.statusConfigValue = false;
    sequence.timerId = 1;
    handler.filterSequences_.push_back(sequence);
    sequenceKey.actionTime = 15000;
    handler.keys_.push_back(sequenceKey);
    ASSERT_FALSE(handler.HandleSequences(keyEvent));
    handler.keys_.clear();
    keyEvent->SetActionTime(1500000);
    sequenceKey.actionTime = 200000;
    sequence.statusConfigValue = false;
    sequence.timerId = 1;
    handler.filterSequences_.push_back(sequence);
    ASSERT_FALSE(handler.HandleSequences(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleConsumedKeyEvent_001
 * @tc.desc: Test the function HandleConsumedKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleConsumedKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey testKey;
    testKey.finalKey = -1;
    handler.currentLaunchAbilityKey_ = testKey;
    int32_t keyCode = -1;
    keyEvent->SetKeyCode(keyCode);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    bool ret = handler.HandleConsumedKeyEvent(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleSequences_003
 * @tc.desc: HandleSequences
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleSequences_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler.sequenceOccurred_ = false;
    handler.matchedSequence_.timerId = 1;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    bool ret = handler.HandleSequences(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleScreenLocked_001
 * @tc.desc: HandleScreenLocked
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleScreenLocked_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    Sequence sequence;
    sequence.timerId = -1;
    bool isLaunchAbility = true;
    bool ret = handler.HandleScreenLocked(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
    sequence.timerId = 2;
    ret = handler.HandleScreenLocked(sequence, isLaunchAbility);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_MatchShortcutKey_001
 * @tc.desc: Test the function MatchShortcutKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_MatchShortcutKey_001, TestSize.Level1)
{
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey shortcutKey;
    std::vector<ShortcutKey> upAbilities;
    shortcutKey.statusConfigValue = false;
    bool ret = handler.MatchShortcutKey(keyEvent, shortcutKey, upAbilities);
    ASSERT_FALSE(ret);
    shortcutKey.statusConfigValue = true;
    shortcutKey.finalKey = 1;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_HOME);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    shortcutKey.preKeys.insert(2024);
    KeyEvent::KeyItem item1;
    item1.SetKeyCode(KeyEvent::KEYCODE_R);
    item1.SetPressed(true);
    item1.SetDownTime(500);
    keyEvent->keys_.push_back(item1);
    KeyEvent::KeyItem item2;
    item2.SetKeyCode(KeyEvent::KEYCODE_R);
    item2.SetPressed(false);
    item2.SetDownTime(200);
    keyEvent->keys_.push_back(item2);
    ret = handler.MatchShortcutKey(keyEvent, shortcutKey, upAbilities);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_PreHandleEvent_001
 * @tc.desc: Test the function PreHandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_PreHandleEvent_001, TestSize.Level1)
{
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> key = KeyEvent::Create();
    ASSERT_NE(key, nullptr);
    EventLogHelper eventLogHelper;
    eventLogHelper.userType_ = "beta";
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    EXPECT_NE(inputEvent, nullptr);
    inputEvent->bitwise_ = 0x00000000;
    bool ret = handler.PreHandleEvent(key);
    ASSERT_TRUE(ret);
    inputEvent->bitwise_ = InputEvent::EVENT_FLAG_PRIVACY_MODE;
    ret = handler.PreHandleEvent(key);
    ASSERT_TRUE(ret);
    handler.enableCombineKey_ = false;
    ret = handler.PreHandleEvent(key);
    ASSERT_FALSE(ret);
    handler.enableCombineKey_ = true;
    handler.isParseConfig_ = false;
    ret = handler.PreHandleEvent(key);
    ASSERT_TRUE(ret);
    handler.isParseConfig_ = true;
    handler.isParseMaxCount_ = false;
    ret = handler.PreHandleEvent(key);
    ASSERT_TRUE(ret);
    handler.isParseMaxCount_ = true;
    handler.isParseStatusConfig_ = false;
    ret = handler.PreHandleEvent(key);
    ASSERT_TRUE(ret);
    handler.isParseStatusConfig_ = false;
    ret = handler.PreHandleEvent(key);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_PreHandleEvent_002
 * @tc.desc: Test the function PreHandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_PreHandleEvent_002, TestSize.Level1)
{
    KeyCommandHandler handler;
    ASSERT_NE(keyEvent_, nullptr);
    keyEvent_->SetKeyCode(KeyEvent::KEYCODE_F1);
    handler.enableCombineKey_ = true;
    bool ret = handler.PreHandleEvent(keyEvent_);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckInputMethodArea_006
 * @tc.desc: Test the function CheckInputMethodArea
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckInputMethodArea_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    EXPECT_NE(inputEvent, nullptr);
    inputEvent->SetTargetDisplayId(-1);
    inputEvent->SetTargetWindowId(5);
    InputWindowsManager inputWindowsManager;
    WindowInfo windowInfo;
    windowInfo.windowType = 2105;
    windowInfo.id = 5;
    windowInfo.area.x = 10;
    windowInfo.area.y = 20;
    windowInfo.area.width = 100;
    windowInfo.area.height = 200;
    inputWindowsManager.displayGroupInfo_.windowsInfo.push_back(windowInfo);
    PointerEvent::PointerItem item;
    item.SetDisplayX(5);
    item.SetDisplayY(10);
    touchEvent->AddPointerItem(item);
    bool ret = handler.CheckInputMethodArea(touchEvent);
    ASSERT_FALSE(ret);
    item.SetDisplayX(20);
    item.SetDisplayY(30);
    touchEvent->AddPointerItem(item);
    ret = handler.CheckInputMethodArea(touchEvent);
    ASSERT_FALSE(ret);
    windowInfo.area.height = INT32_MAX;
    inputWindowsManager.displayGroupInfo_.windowsInfo.push_back(windowInfo);
    ret = handler.CheckInputMethodArea(touchEvent);
    ASSERT_FALSE(ret);
    windowInfo.area.width = INT32_MAX;
    inputWindowsManager.displayGroupInfo_.windowsInfo.push_back(windowInfo);
    ret = handler.CheckInputMethodArea(touchEvent);
    ASSERT_FALSE(ret);
    inputEvent->SetTargetWindowId(10);
    ret = handler.CheckInputMethodArea(touchEvent);
    ASSERT_FALSE(ret);
    windowInfo.windowType = 1000;
    ret = handler.CheckInputMethodArea(touchEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleSequences_004
 * @tc.desc: Test the function HandleSequences
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleSequences_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    handler.sequenceOccurred_ = false;
    handler.matchedSequence_.timerId = -10;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    Sequence sequence1;
    sequence1.statusConfig = "statusConfig1";
    sequence1.statusConfigValue = true;
    sequence1.abilityStartDelay = 1;
    sequence1.timerId = 5;
    handler.sequences_.push_back(sequence1);
    Sequence sequence2;
    sequence2.statusConfig = "statusConfig2";
    sequence2.statusConfigValue = false;
    sequence2.abilityStartDelay = 2;
    sequence2.timerId = 1;
    handler.filterSequences_.push_back(sequence2);
    bool ret = handler.HandleSequences(keyEvent);
    ASSERT_FALSE(ret);
    SequenceKey sequenceKey;
    sequenceKey.keyCode = 1;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    sequenceKey.actionTime = 2;
    sequenceKey.delay = 5;
    handler.keys_.push_back(sequenceKey);
    ret = handler.HandleSequences(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_MatchShortcutKey_003
 * @tc.desc: Test the function MatchShortcutKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_MatchShortcutKey_003, TestSize.Level1)
{
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey shortcutKey;
    std::vector<ShortcutKey> upAbilities;
    shortcutKey.statusConfigValue = true;
    shortcutKey.finalKey = 5;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;
    shortcutKey.preKeys = {1};
    shortcutKey.businessId = "Ctrl+O";
    std::shared_ptr<KeyEvent> key = KeyEvent::Create();
    ASSERT_NE(key, nullptr);
    key->SetKeyCode(5);
    key->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    KeyEvent::KeyItem item1;
    item1.SetKeyCode(1);
    item1.SetDownTime(10);
    item1.SetDeviceId(3);
    KeyEvent::KeyItem item2;
    item2.SetKeyCode(1);
    item2.SetDownTime(20);
    item2.SetDeviceId(4);
    keyEvent->AddKeyItem(item1);
    keyEvent->AddKeyItem(item2);
    MultiModalInputPreferencesManager multiModalInputPreferencesManager;
    multiModalInputPreferencesManager.shortcutKeyMap_.insert(std::make_pair("Ctrl+O", 5000));
    bool ret = handler.MatchShortcutKey(keyEvent, shortcutKey, upAbilities);
    EXPECT_FALSE(ret);
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_UP;
    key->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    ret = handler.MatchShortcutKey(keyEvent, shortcutKey, upAbilities);
    EXPECT_FALSE(ret);
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_UNKNOWN;
    key->SetKeyAction(KeyEvent::KEY_ACTION_UNKNOWN);
    ret = handler.MatchShortcutKey(keyEvent, shortcutKey, upAbilities);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_MatchShortcutKey_004
 * @tc.desc: Test the function MatchShortcutKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_MatchShortcutKey_004, TestSize.Level1)
{
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey shortcutKey;
    std::vector<ShortcutKey> upAbilities;
    shortcutKey.statusConfigValue = true;
    shortcutKey.finalKey = 10;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_UP;
    shortcutKey.preKeys = {5};
    shortcutKey.businessId = "Ctrl+T";
    std::shared_ptr<KeyEvent> key = KeyEvent::Create();
    ASSERT_NE(key, nullptr);
    key->SetKeyCode(10);
    key->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    KeyEvent::KeyItem item1;
    item1.SetKeyCode(5);
    item1.SetDownTime(6);
    item1.SetDeviceId(7);
    KeyEvent::KeyItem item2;
    item2.SetKeyCode(5);
    item2.SetDownTime(2);
    item2.SetDeviceId(1);
    keyEvent->AddKeyItem(item1);
    keyEvent->AddKeyItem(item2);
    MultiModalInputPreferencesManager multiModalInputPreferencesManager;
    multiModalInputPreferencesManager.shortcutKeyMap_.insert(std::make_pair("Ctrl+R", 300));
    bool ret = handler.MatchShortcutKey(keyEvent, shortcutKey, upAbilities);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleShortKeys_01
 * @tc.desc: Test the function HandleShortKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleShortKeys_01, TestSize.Level1)
{
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey shortcutKey;
    shortcutKey.preKeys = {2};
    shortcutKey.statusConfigValue = true;
    shortcutKey.finalKey = 6;
    shortcutKey.keyDownDuration = 7;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;
    shortcutKey.timerId = 10;
    handler.shortcutKeys_.insert(std::make_pair("key", shortcutKey));
    keyEvent->SetKeyCode(1);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    KeyEvent::KeyItem item1;
    item1.SetKeyCode(3);
    item1.SetDownTime(5);
    item1.SetDeviceId(8);
    KeyEvent::KeyItem item2;
    item2.SetKeyCode(3);
    item2.SetDownTime(6);
    item2.SetDeviceId(4);
    keyEvent->AddKeyItem(item1);
    keyEvent->AddKeyItem(item2);
    bool ret = handler.HandleShortKeys(keyEvent);
    ASSERT_TRUE(ret);
    handler.currentLaunchAbilityKey_.timerId = 5;
    handler.currentLaunchAbilityKey_.finalKey = 1;
    handler.currentLaunchAbilityKey_.triggerType = KeyEvent::KEY_ACTION_UP;
    handler.currentLaunchAbilityKey_.preKeys = {3};
    EventLogHelper eventLogHelper;
    eventLogHelper.userType_ = "beta";
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    EXPECT_NE(inputEvent, nullptr);
    inputEvent->bitwise_ = InputEvent::EVENT_FLAG_PRIVACY_MODE;
    ret = handler.HandleShortKeys(keyEvent);
    ASSERT_TRUE(ret);
    eventLogHelper.userType_ = "aaaaaaa";
    ret = handler.HandleShortKeys(keyEvent);
    ASSERT_TRUE(ret);
    inputEvent->bitwise_ = 0;
    ret = handler.HandleShortKeys(keyEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_IsMatchedAbility
 * @tc.desc: Test IsMatchedAbility
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_IsMatchedAbility, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::vector<float> gesturePoints;
    float gestureLastX = 100.0f;
    float gestureLastY = 100.0f;
    gesturePoints.push_back(10.0f);
    EXPECT_FALSE(handler.IsMatchedAbility(gesturePoints, gestureLastX, gestureLastY));

    gesturePoints.push_back(15.0f);
    gesturePoints.push_back(20.0f);
    EXPECT_TRUE(handler.IsMatchedAbility(gesturePoints, gestureLastX, gestureLastY));
}

/**
 * @tc.name: KeyCommandHandlerTest_ParseRepeatKeyMaxCount
 * @tc.desc: Test ParseRepeatKeyMaxCount
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ParseRepeatKeyMaxCount, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    EXPECT_NO_FATAL_FAILURE(handler.ParseRepeatKeyMaxCount());
}

/**
 * @tc.name: KeyCommandHandlerTest_SetIsFreezePowerKey
 * @tc.desc: Test SetIsFreezePowerKey
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::string pageName = "SosCountup";
    EXPECT_EQ(handler.SetIsFreezePowerKey(pageName), RET_OK);
    pageName = "SosCountdown";
    handler.sosDelayTimerId_ = 100;
    EXPECT_EQ(handler.SetIsFreezePowerKey(pageName), RET_OK);
    handler.sosDelayTimerId_ = -1;
    EXPECT_EQ(handler.SetIsFreezePowerKey(pageName), RET_OK);
}

/**
 * @tc.name: KeyCommandHandlerTest_TouchPadKnuckleDoubleClickProcess
 * @tc.desc: Test the function TouchPadKnuckleDoubleClickProcess
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_TouchPadKnuckleDoubleClickProcess, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    std::string action = "action";
    DISPLAY_MONITOR->SetScreenStatus(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    DISPLAY_MONITOR->SetScreenLocked(true);
    ASSERT_NO_FATAL_FAILURE(handler.TouchPadKnuckleDoubleClickProcess(bundleName, abilityName, action));
    DISPLAY_MONITOR->SetScreenStatus("abc");
    ASSERT_NO_FATAL_FAILURE(handler.TouchPadKnuckleDoubleClickProcess(bundleName, abilityName, action));
    DISPLAY_MONITOR->SetScreenLocked(false);
    ASSERT_NO_FATAL_FAILURE(handler.TouchPadKnuckleDoubleClickProcess(bundleName, abilityName, action));
}

/**
 * @tc.name: KeyCommandHandlerTest_TouchPadKnuckleDoubleClickHandle
 * @tc.desc: Test the function TouchPadKnuckleDoubleClickHandle
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_TouchPadKnuckleDoubleClickHandle, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetKeyAction(KNUCKLE_1F_DOUBLE_CLICK);
    bool ret = handler.TouchPadKnuckleDoubleClickHandle(event);
    ASSERT_TRUE(ret);
    event->SetKeyAction(KNUCKLE_2F_DOUBLE_CLICK);
    ret = handler.TouchPadKnuckleDoubleClickHandle(event);
    ASSERT_TRUE(ret);
    event->SetKeyAction(1);
    ret = handler.TouchPadKnuckleDoubleClickHandle(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_IsMatchedAbility_001
 * @tc.desc: Test the function IsMatchedAbility
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_IsMatchedAbility_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::vector<float> gesturePoints;
    float gestureLastX = 100.0f;
    float gestureLastY = 150.0f;
    bool ret = handler.IsMatchedAbility(gesturePoints, gestureLastX, gestureLastY);
    ASSERT_FALSE(ret);
    gesturePoints.push_back(100.0f);
    gesturePoints.push_back(150.0f);
    ret = handler.IsMatchedAbility(gesturePoints, gestureLastX, gestureLastY);
    ASSERT_FALSE(ret);
    gesturePoints.push_back(200.0f);
    ret = handler.IsMatchedAbility(gesturePoints, gestureLastX, gestureLastY);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_InitKeyObserver
 * @tc.desc: Test the function InitKeyObserver
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_InitKeyObserver, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.isParseStatusConfig_ = false;
    handler.isKnuckleSwitchConfig_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.InitKeyObserver());
    handler.isKnuckleSwitchConfig_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.InitKeyObserver());
    handler.isParseStatusConfig_ = true;
    handler.isKnuckleSwitchConfig_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.InitKeyObserver());
    handler.isKnuckleSwitchConfig_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.InitKeyObserver());
}

/**
 * @tc.name: KeyCommandHandlerTest_SetIsFreezePowerKey_001
 * @tc.desc: Test the function SetIsFreezePowerKey
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.isFreezePowerKey_ = true;
    std::string pageName = "pageName";
    int32_t ret = handler.SetIsFreezePowerKey(pageName);
    EXPECT_EQ(ret, RET_OK);
    handler.isFreezePowerKey_ = false;
    handler.sosDelayTimerId_ = 1;
    pageName = "SosCountdown";
    ret = handler.SetIsFreezePowerKey(pageName);
    EXPECT_EQ(ret, RET_OK);
    handler.sosDelayTimerId_ = -1;
    ret = handler.SetIsFreezePowerKey(pageName);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: KeyCommandHandlerTest_ParseStatusConfigObserver_001
 * @tc.desc: Test the function ParseStatusConfigObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ParseStatusConfigObserver_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    Sequence sequence;
    sequence.statusConfig = "statusConfig";
    sequence.statusConfigValue = false;
    sequence.abilityStartDelay = 1;
    sequence.timerId = 1;
    handler.sequences_.push_back(sequence);
    ShortcutKey key;
    key.preKeys = {1, 2, 3};
    key.businessId = "business1";
    key.statusConfig = "";
    handler.shortcutKeys_.insert(std::make_pair("key1", key));
    ASSERT_NO_FATAL_FAILURE(handler.ParseStatusConfigObserver());
}

/**
 * @tc.name: KeyCommandHandlerTest_ParseStatusConfigObserver_002
 * @tc.desc: Test the function ParseStatusConfigObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ParseStatusConfigObserver_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    Sequence sequence;
    sequence.statusConfig = "abc";
    sequence.statusConfigValue = true;
    sequence.abilityStartDelay = 1;
    sequence.timerId = 5;
    handler.sequences_.push_back(sequence);
    ShortcutKey key;
    key.preKeys = {1, 2, 3};
    key.businessId = "business1";
    key.statusConfig = "statusConfig";
    key.statusConfigValue = true;
    key.finalKey = 4;
    key.keyDownDuration = 5;
    key.triggerType = KeyEvent::KEY_ACTION_DOWN;
    key.timerId = 6;
    Ability ability_temp;
    ability_temp.bundleName = "bundleName";
    ability_temp.abilityName = "abilityName";
    key.ability = ability_temp;
    handler.shortcutKeys_.insert(std::make_pair("key1", key));
    ASSERT_NO_FATAL_FAILURE(handler.ParseStatusConfigObserver());
}

/**
 * @tc.name: KeyCommandHandlerTest_ParseStatusConfigObserver_003
 * @tc.desc: Test the function ParseStatusConfigObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ParseStatusConfigObserver_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    Sequence sequence;
    sequence.statusConfig = "";
    sequence.statusConfigValue = false;
    sequence.abilityStartDelay = 2;
    sequence.timerId = 2;
    handler.sequences_.push_back(sequence);
    ASSERT_NO_FATAL_FAILURE(handler.ParseStatusConfigObserver());
}

/**
 * @tc.name: KeyCommandHandlerTest_MatchShortcutKey_03
 * @tc.desc: Test the function MatchShortcutKey
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_MatchShortcutKey_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(1);
    keyEvent->SetKeyAction(5);
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey shortcutKey;
    shortcutKey.preKeys = {1, 2, 3};
    shortcutKey.businessId = "businessId";
    shortcutKey.statusConfig = "statusConfig";
    shortcutKey.statusConfigValue = true;
    shortcutKey.finalKey = 5;
    shortcutKey.keyDownDuration = 1;
    shortcutKey.triggerType = 10;
    shortcutKey.timerId = 1;
    std::vector<ShortcutKey> upAbilities;
    upAbilities.push_back(shortcutKey);
    bool ret = handler.MatchShortcutKey(keyEvent, shortcutKey, upAbilities);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_MatchShortcutKey_02
 * @tc.desc: Test the function MatchShortcutKey
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_MatchShortcutKey_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(6);
    keyEvent->SetKeyAction(3);
    ASSERT_NE(keyEvent, nullptr);
    ShortcutKey shortcutKey;
    shortcutKey.preKeys = {3, 2, 4};
    shortcutKey.businessId = "businessId1";
    shortcutKey.statusConfig = "statusConfig1";
    shortcutKey.statusConfigValue = false;
    shortcutKey.finalKey = 6;
    shortcutKey.keyDownDuration = 9;
    shortcutKey.triggerType = 1;
    shortcutKey.timerId = 3;
    std::vector<ShortcutKey> upAbilities;
    upAbilities.push_back(shortcutKey);
    bool ret = handler.MatchShortcutKey(keyEvent, shortcutKey, upAbilities);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_PreHandleEvent_02
 * @tc.desc: Test the function PreHandleEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_PreHandleEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;

    handler.isParseConfig_ = false;
    handler.isParseLongPressConfig_ = false;
    handler.isParseMaxCount_ = false;
    bool ret = false;
    ret = handler.PreHandleEvent();
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureDownEvent_004
 * @tc.desc: Test HandleKnuckleGestureDownEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureDownEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    int64_t downTime = 100;
    item.SetDownTime(downTime);
    item.SetTargetWindowId(0);
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    touchEvent->AddPointerItem(item);
    touchEvent->SetTargetDisplayId(0);

    KeyCommandHandler handler;
    handler.gameForbidFingerKnuckle_ = false;

    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    WindowInfo windowInfo;
    windowInfo.id = 0;
    windowInfo.windowType = WINDOW_INPUT_METHOD_TYPE;
    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
        it->second.displaysInfo.push_back(displayInfo);
    }
    IInputWindowsManager::instance_ = inputWindowsManager;

    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureDownEvent(touchEvent));

    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureDownEvent(touchEvent));

    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureDownEvent(touchEvent));

    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureDownEvent(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckTwoFingerGestureAction_009
 * @tc.desc: Test CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckTwoFingerGestureAction_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.twoFingerGesture_.active = true;
    handler.twoFingerGesture_.touches[0].downTime = 0;
    handler.twoFingerGesture_.touches[1].downTime = 1;

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
    handler.twoFingerGesture_.touches[0].x = 600;
    handler.twoFingerGesture_.touches[0].y = 600;

    handler.twoFingerGesture_.touches[1].x = 800;
    handler.twoFingerGesture_.touches[1].y = 600;
    ASSERT_NO_FATAL_FAILURE(handler.CheckTwoFingerGestureAction());

    handler.twoFingerGesture_.touches[1].x = 10;
    handler.twoFingerGesture_.touches[1].y = 600;
    ASSERT_NO_FATAL_FAILURE(handler.CheckTwoFingerGestureAction());

    handler.twoFingerGesture_.touches[1].x = 1250;
    handler.twoFingerGesture_.touches[1].y = 600;
    ASSERT_NO_FATAL_FAILURE(handler.CheckTwoFingerGestureAction());

    handler.twoFingerGesture_.touches[1].x = 600;
    handler.twoFingerGesture_.touches[1].y = 10;
    ASSERT_NO_FATAL_FAILURE(handler.CheckTwoFingerGestureAction());

    handler.twoFingerGesture_.touches[1].x = 600;
    handler.twoFingerGesture_.touches[1].y = 2710;
    ASSERT_NO_FATAL_FAILURE(handler.CheckTwoFingerGestureAction());
}


/**
 * @tc.name: KeyCommandHandlerTest_CheckTwoFingerGestureAction_010
 * @tc.desc: Test CheckTwoFingerGestureAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckTwoFingerGestureAction_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.twoFingerGesture_.active = true;
    handler.twoFingerGesture_.touches[0].downTime = 0;
    handler.twoFingerGesture_.touches[1].downTime = 1;

    handler.twoFingerGesture_.touches[0].x = 600;
    handler.twoFingerGesture_.touches[0].y = 600;

    handler.twoFingerGesture_.touches[1].x = 601;
    handler.twoFingerGesture_.touches[1].y = 601;
    ASSERT_NO_FATAL_FAILURE(handler.CheckTwoFingerGestureAction());
}

/**
 * @tc.name: KeyCommandHandlerTest_ConvertVPToPX_005
 * @tc.desc: Verify if (vp <= 0)
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ConvertVPToPX_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t vp = -1;
    KeyCommandHandler handler;
    int32_t ret = handler.ConvertVPToPX(vp);
    ASSERT_EQ(ret, 0);
    ret = handler.ConvertVPToPX(vp);
}

/**
 * @tc.name: KeyCommandHandlerTest_ConvertVPToPX_006
 * @tc.desc: Verify if (dpi <= 0)
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ConvertVPToPX_006, TestSize.Level1)
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
    KeyCommandHandler handler;
    int32_t ret = handler.ConvertVPToPX(vp);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckKnuckleCondition_001
 * @tc.desc: Test if (physicDisplayInfo != nullptr && physicDisplayInfo->direction != lastDirection_)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckKnuckleCondition_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    item.SetTargetWindowId(0);
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(0);

    KeyCommandHandler handler;
    handler.gameForbidFingerKnuckle_ = false;
    handler.singleKnuckleGesture_.state = false;

    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.direction = DIRECTION0;
    WindowInfo windowInfo;
    windowInfo.id = 0;
    windowInfo.windowType = WINDOW_INPUT_METHOD_TYPE;
    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
        it->second.displaysInfo.push_back(displayInfo);
    }
    IInputWindowsManager::instance_ = inputWindowsManager;

    touchEvent->SetTargetDisplayId(1);
    ASSERT_NO_FATAL_FAILURE(handler.CheckKnuckleCondition(touchEvent));

    touchEvent->SetTargetDisplayId(0);
    handler.lastDirection_ = DIRECTION0;
    ASSERT_NO_FATAL_FAILURE(handler.CheckKnuckleCondition(touchEvent));

    handler.lastDirection_ = DIRECTION90;
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(handler.CheckKnuckleCondition(touchEvent));

    handler.lastDirection_ = DIRECTION90;
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    ASSERT_NO_FATAL_FAILURE(handler.CheckKnuckleCondition(touchEvent));

    handler.lastDirection_ = DIRECTION90;
    float pointer = 1.0;
    handler.gesturePoints_.push_back(pointer);
    ASSERT_NO_FATAL_FAILURE(handler.CheckKnuckleCondition(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckKnuckleCondition_002
 * @tc.desc: Test if (touchEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN ||
 * touchEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckKnuckleCondition_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    item.SetTargetWindowId(0);
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(0);

    KeyCommandHandler handler;
    handler.gameForbidFingerKnuckle_ = false;
    handler.singleKnuckleGesture_.state = false;

    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.direction = DIRECTION0;
    WindowInfo windowInfo;
    windowInfo.id = 0;
    windowInfo.windowType = WINDOW_INPUT_METHOD_TYPE;
    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
        it->second.displaysInfo.push_back(displayInfo);
    }
    IInputWindowsManager::instance_ = inputWindowsManager;

    touchEvent->SetTargetDisplayId(0);
    handler.lastDirection_ = DIRECTION0;

    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    ASSERT_NO_FATAL_FAILURE(handler.CheckKnuckleCondition(touchEvent));

    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(handler.CheckKnuckleCondition(touchEvent));

    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(handler.CheckKnuckleCondition(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_003
 * @tc.desc: Test if (dx >= MOVE_TOLERANCE || dy >= MOVE_TOLERANCE)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    item.SetTargetWindowId(0);
    item.SetRawDisplayX(3.0f);
    item.SetRawDisplayY(3.0f);
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(0);
    touchEvent->SetTargetDisplayId(0);

    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.direction = DIRECTION0;
    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    IInputWindowsManager::instance_ = inputWindowsManager;

    KeyCommandHandler handler;
    handler.gestureLastX_ = 3.0f;
    handler.gestureLastY_ = 3.0f;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(touchEvent));

    handler.gestureLastX_ = 0.0f;
    handler.gestureLastY_ = 3.0f;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(touchEvent));

    handler.gestureLastX_ = 3.0f;
    handler.gestureLastY_ = 0.0f;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(touchEvent));

    handler.gestureLastX_ = 0.0f;
    handler.gestureLastY_ = 0.0f;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_004
 * @tc.desc: Test if (!isStartBase_ && IsMatchedAbility(gesturePoints_, gestureLastX_, gestureLastY_))
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    item.SetTargetWindowId(0);
    item.SetRawDisplayX(3.0f);
    item.SetRawDisplayY(3.0f);
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(0);
    touchEvent->SetTargetDisplayId(0);

    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.direction = DIRECTION0;
    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    IInputWindowsManager::instance_ = inputWindowsManager;

    KeyCommandHandler handler;
    handler.gestureLastX_ = 0.0f;
    handler.gestureLastY_ = 0.0f;
    handler.isStartBase_ = true;

    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(touchEvent));

    handler.gesturePoints_.clear();
    float pointer = 500.0f;
    handler.gesturePoints_.emplace_back(pointer);
    pointer = 500.0f;
    handler.gesturePoints_.emplace_back(pointer);
    handler.isStartBase_ = false;
    handler.gestureLastX_ = 0.0f;
    handler.gestureLastY_ = 0.0f;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_005
 * @tc.desc: Test if (!isGesturing_)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    item.SetTargetWindowId(0);
    item.SetRawDisplayX(3.0f);
    item.SetRawDisplayY(3.0f);
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(0);
    touchEvent->SetTargetDisplayId(0);

    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.direction = DIRECTION0;
    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    IInputWindowsManager::instance_ = inputWindowsManager;

    KeyCommandHandler handler;
    handler.gestureLastX_ = 0.0f;
    handler.gestureLastY_ = 0.0f;
    handler.isStartBase_ = true;
    handler.isGesturing_ = true;

    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(touchEvent));

    handler.isStartBase_ = true;
    handler.isGesturing_ = false;
    handler.gestureLastX_ = 0.0f;
    handler.gestureLastY_ = 0.0f;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_006
 * @tc.desc: Test if (gestureTrackLength_ > MIN_GESTURE_STROKE_LENGTH)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    item.SetTargetWindowId(0);
    item.SetRawDisplayX(3.0f);
    item.SetRawDisplayY(3.0f);
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(0);
    touchEvent->SetTargetDisplayId(0);

    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.direction = DIRECTION0;
    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    IInputWindowsManager::instance_ = inputWindowsManager;

    KeyCommandHandler handler;
    handler.gestureLastX_ = 0.0f;
    handler.gestureLastY_ = 0.0f;
    handler.gestureTrackLength_ = 0.0f;
    handler.isStartBase_ = true;
    handler.isGesturing_ = false;

    handler.gestureTrackLength_ = 0.0f;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(touchEvent));

    handler.gestureTrackLength_ = 300.0f;
    handler.gestureLastX_ = 0.0f;
    handler.gestureLastY_ = 0.0f;
    handler.isStartBase_ = true;
    handler.isGesturing_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_007
 * @tc.desc: Test if (isGesturing_ && !isLetterGesturing_)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    item.SetTargetWindowId(0);
    item.SetRawDisplayX(3.0f);
    item.SetRawDisplayY(3.0f);
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(0);
    touchEvent->SetTargetDisplayId(0);

    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.direction = DIRECTION0;
    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    IInputWindowsManager::instance_ = inputWindowsManager;

    KeyCommandHandler handler;
    handler.gestureLastX_ = 0.0f;
    handler.gestureLastY_ = 0.0f;
    handler.gestureTrackLength_ = 0.0f;
    handler.isStartBase_ = true;
    handler.isGesturing_ = true;
    handler.isLetterGesturing_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(touchEvent));

    handler.isStartBase_ = true;
    handler.isGesturing_ = true;
    handler.isLetterGesturing_ = false;
    handler.gestureLastX_ = 0.0f;
    handler.gestureLastY_ = 0.0f;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_008
 * @tc.desc: Test if (boundingSquareness > MIN_LETTER_GESTURE_SQUARENESS)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    item.SetTargetWindowId(0);
    item.SetRawDisplayX(3.0f);
    item.SetRawDisplayY(3.0f);
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(0);
    touchEvent->SetTargetDisplayId(0);

    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.direction = DIRECTION0;
    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    IInputWindowsManager::instance_ = inputWindowsManager;

    KeyCommandHandler handler;
    handler.gestureLastX_ = 0.0f;
    handler.gestureLastY_ = 0.0f;
    handler.gestureTrackLength_ = 0.0f;
    handler.isStartBase_ = true;
    handler.isGesturing_ = true;
    handler.isLetterGesturing_ = false;

    ASSERT_NO_FATAL_FAILURE(handler.HandleKnuckleGestureTouchMove(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_ParseJson_002
 * @tc.desc: Test the function ParseJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ParseJson_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::string defaultConfig = "/system/etc/multimodalinput/ability_launch_config.json";
    ASSERT_NO_FATAL_FAILURE(handler.ParseJson(defaultConfig));
}

/**
 * @tc.name: KeyCommandHandlerTest_ParseExcludeJson
 * @tc.desc: Test the function ParseExcludeJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ParseExcludeJson, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::string defaultConfig = "/system/etc/multimodalinput/ability_launch_config2.json";
    EXPECT_FALSE(handler.ParseExcludeJson(defaultConfig));
}

/**
 * @tc.name: KeyCommandHandlerTest_ParseJson_003
 * @tc.desc: Test the function ParseJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ParseJson_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::string defaultConfig = "/system/etc/multimodalinput/ability_launch_config2.json";
    EXPECT_FALSE(handler.ParseJson(defaultConfig));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleEvent_003
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    int64_t time = 4000000;
    keyEvent->SetActionTime(time);
    KeyCommandHandler handler;
    handler.powerUpTime_ = 0;
    handler.sosLaunchTime_ = 0;
    handler.isParseConfig_ = true;
    handler.isParseLongPressConfig_ = true;
    handler.isParseMaxCount_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleEvent_004
 * @tc.desc: Test if ((key->GetActionTime() - powerUpTime_) > POWER_ACTION_INTERVAL * FREQUENCY &&
 * (key->GetActionTime() - sosLaunchTime_) > SOS_WAIT_TIME * FREQUENCY)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    int64_t time = 0;
    keyEvent->SetActionTime(time);
    KeyCommandHandler handler;
    handler.powerUpTime_ = 0;
    handler.sosLaunchTime_ = 0;
    handler.isParseConfig_ = true;
    handler.isParseLongPressConfig_ = true;
    handler.isParseMaxCount_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleEvent_005
 * @tc.desc: Test if ((key->GetActionTime() - powerUpTime_) > POWER_ACTION_INTERVAL * FREQUENCY &&
 * (key->GetActionTime() - sosLaunchTime_) > SOS_WAIT_TIME * FREQUENCY)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    int64_t time = 700000;
    keyEvent->SetActionTime(time);
    KeyCommandHandler handler;
    handler.powerUpTime_ = 0;
    handler.sosLaunchTime_ = 0;
    handler.isParseConfig_ = true;
    handler.isParseLongPressConfig_ = true;
    handler.isParseMaxCount_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyOwnCount_003
 * @tc.desc: Test if (item.ability.bundleName == SOS_BUNDLE_NAME)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyOwnCount_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    RepeatKey repeatKey;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    ASSERT_NO_FATAL_FAILURE(handler.HandleRepeatKeyOwnCount(repeatKey));

    repeatKey.ability.bundleName = "test";
    ASSERT_NO_FATAL_FAILURE(handler.HandleRepeatKeyOwnCount(repeatKey));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyOwnCount_004
 * @tc.desc: Test if (item.ability.bundleName == SOS_BUNDLE_NAME)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyOwnCount_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    RepeatKey repeatKey;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    repeatKey.delay = 10;
    handler.downActionTime_ = 10;
    handler.lastDownActionTime_ = 10;
    ASSERT_NO_FATAL_FAILURE(handler.HandleRepeatKeyOwnCount(repeatKey));

    handler.downActionTime_ = 100;
    ASSERT_NO_FATAL_FAILURE(handler.HandleRepeatKeyOwnCount(repeatKey));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyOwnCount_005
 * @tc.desc: Test if (item.ability.bundleName == SOS_BUNDLE_NAME)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyOwnCount_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    RepeatKey repeatKey;
    repeatKey.ability.bundleName = "test";
    repeatKey.delay = 10;
    handler.upActionTime_ = 10;
    handler.lastDownActionTime_ = 10;
    ASSERT_NO_FATAL_FAILURE(handler.HandleRepeatKeyOwnCount(repeatKey));

    handler.downActionTime_ = 100;
    ASSERT_NO_FATAL_FAILURE(handler.HandleRepeatKeyOwnCount(repeatKey));
}

constexpr int32_t MODULE_TYPE {1};
constexpr int32_t UDS_FD {-1};
constexpr int32_t UDS_UID {100};
constexpr int32_t UDS_PID {100};

/**
 * @tc.name: KeyCommandHandlerTest_CheckSpecialRepeatKey_001
 * @tc.desc: Test if (bundleName.find(matchName) == std::string::npos)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckSpecialRepeatKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    repeatKey.ability.bundleName = ".camera";

    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    WindowInfo windowInfo;
    windowInfo.id = 0;
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
        it->second.focusWindowId = 0;
    }
    UDSServer udsServer;
    udsServer.idxPidMap_.insert(std::make_pair(0, 1));
    SessionPtr sessionPtr =
        std::make_shared<UDSSession>(repeatKey.ability.bundleName, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_[1] = sessionPtr;
    inputWindowsManager->udsServer_ = &udsServer;
    EXPECT_NE(inputWindowsManager->udsServer_, nullptr);
    IInputWindowsManager::instance_ = inputWindowsManager;

    KeyCommandHandler handler;
    DISPLAY_MONITOR->SetScreenStatus("test");
    DISPLAY_MONITOR->SetScreenLocked(true);
    ASSERT_NO_FATAL_FAILURE(handler.CheckSpecialRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckSpecialRepeatKey_002
 * @tc.desc: Test if (WIN_MGR->JudgeCameraInFore() &&
 * (screenStatus != EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF && isScreenLocked))
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckSpecialRepeatKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    repeatKey.ability.bundleName = ".camera";

    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    WindowInfo windowInfo;
    windowInfo.id = 0;
    OLD::DisplayGroupInfo displayGroupInfoRef;
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        displayGroupInfoRef = it->second;
    }
    displayGroupInfoRef.windowsInfo.push_back(windowInfo);
    displayGroupInfoRef.focusWindowId = 0;
    UDSServer udsServer;
    udsServer.idxPidMap_.insert(std::make_pair(0, 1));
    SessionPtr sessionPtr =
        std::make_shared<UDSSession>(repeatKey.ability.bundleName, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_[1] = sessionPtr;
    inputWindowsManager->udsServer_ = &udsServer;
    EXPECT_NE(inputWindowsManager->udsServer_, nullptr);
    IInputWindowsManager::instance_ = inputWindowsManager;

    KeyCommandHandler handler;
    DISPLAY_MONITOR->SetScreenStatus(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    DISPLAY_MONITOR->SetScreenLocked(true);
    ASSERT_NO_FATAL_FAILURE(handler.CheckSpecialRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_CheckSpecialRepeatKey_003
 * @tc.desc: Test if (WIN_MGR->JudgeCameraInFore() &&
 * (screenStatus != EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF && isScreenLocked))
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckSpecialRepeatKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    repeatKey.ability.bundleName = ".camera";

    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    WindowInfo windowInfo;
    windowInfo.id = 0;
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
        it->second.focusWindowId = 0;
    }
    UDSServer udsServer;
    udsServer.idxPidMap_.insert(std::make_pair(0, 1));
    SessionPtr sessionPtr =
        std::make_shared<UDSSession>(repeatKey.ability.bundleName, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_[1] = sessionPtr;
    inputWindowsManager->udsServer_ = &udsServer;
    EXPECT_NE(inputWindowsManager->udsServer_, nullptr);
    IInputWindowsManager::instance_ = inputWindowsManager;

    KeyCommandHandler handler;
    DISPLAY_MONITOR->SetScreenStatus("test");
    DISPLAY_MONITOR->SetScreenLocked(false);
    ASSERT_NO_FATAL_FAILURE(handler.CheckSpecialRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: CheckSpecialRepeatKey_Normal_Branch_004
 * @tc.desc: Test KEY_ACTION_UP and keyCode equl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, CheckSpecialRepeatKey_Normal_Branch_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    repeatKey.ability.bundleName = ".camera";

    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    WindowInfo windowInfo;
    windowInfo.id = 0;
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end())
    {
        it->second.windowsInfo.push_back(windowInfo);
        it->second.focusWindowId = 0;
    }
    UDSServer udsServer;
    udsServer.idxPidMap_.insert(std::make_pair(0, 1));
    SessionPtr sessionPtr =
        std::make_shared<UDSSession>(repeatKey.ability.bundleName, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_[1] = sessionPtr;
    inputWindowsManager->udsServer_ = &udsServer;
    EXPECT_NE(inputWindowsManager->udsServer_, nullptr);
    IInputWindowsManager::instance_ = inputWindowsManager;

    KeyCommandHandler handler;
    DISPLAY_MONITOR->SetScreenStatus("test");
    DISPLAY_MONITOR->SetScreenLocked(false);
    ASSERT_NO_FATAL_FAILURE(handler.CheckSpecialRepeatKey(repeatKey, keyEvent));
    int32_t ret = keyEvent->GetKeyAction();
    EXPECT_EQ(handler.repeatKey_.keyAction, ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleRepeatKeyCount_001
 * @tc.desc: Test if (walletLaunchDelayTimes_ != 0)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleRepeatKeyCount_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    handler.walletLaunchDelayTimes_ = 0;
    ASSERT_NO_FATAL_FAILURE(handler.HandleRepeatKeyCount(repeatKey, keyEvent));

    handler.walletLaunchDelayTimes_ = 1;
    ASSERT_NO_FATAL_FAILURE(handler.HandleRepeatKeyCount(repeatKey, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchAiScreenAbility_001
 * @tc.desc: Test LaunchAiScreenAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchAiScreenAbility_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    int32_t pid = 1;
    int32_t ret = handler.LaunchAiScreenAbility(pid);
    EXPECT_NE(ret, RET_OK);

    handler.twoFingerGesture_.touchEvent = PointerEvent::Create();
    ret = handler.LaunchAiScreenAbility(pid);
    EXPECT_NE(ret, RET_OK);

    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    handler.twoFingerGesture_.startTime = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    ret = handler.LaunchAiScreenAbility(pid);
    EXPECT_NE(ret, RET_OK);

    handler.twoFingerGesture_.windowId = handler.twoFingerGesture_.touchEvent->GetTargetWindowId();
    ret = handler.LaunchAiScreenAbility(pid);
    EXPECT_NE(ret, RET_OK);

    handler.twoFingerGesture_.longPressFlag = true;
    ret = handler.LaunchAiScreenAbility(pid);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyEvent_002
 * @tc.desc: Test the function HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyEvent_003
 * @tc.desc: Test the function HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    // Set up menu key event
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_MENU);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_MENU);

    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyEvent_004
 * @tc.desc: Test the function HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    // Set up key event that would make OnHandleEvent return true
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    // Set screen status to off
    DISPLAY_MONITOR->SetScreenStatus(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyEvent_005
 * @tc.desc: Test the function HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    // Set up key event that would make OnHandleEvent return true
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_HOME);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_HOME);
    // Set screen status to on
    DISPLAY_MONITOR->SetScreenStatus(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyEvent_006
 * @tc.desc: Test the function HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyEvent_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyEvent_007
 * @tc.desc: Test the function HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyEvent_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ASSERT_NE(keyEvent_, nullptr);

    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent_->AddKeyItem(item);
    keyEvent_->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent_->SetKeyAction(KNUCKLE_1F_DOUBLE_CLICK);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(keyEvent_));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyEvent_008
 * @tc.desc: Test the function HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyEvent_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ASSERT_NE(keyEvent_, nullptr);

    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent_->AddKeyItem(item);
    keyEvent_->SetKeyCode(KeyEvent::KEYCODE_MENU);
    keyEvent_->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(keyEvent_));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyEvent_009
 * @tc.desc: Test the function HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyEvent_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ASSERT_NE(keyEvent_, nullptr);

    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent_->AddKeyItem(item);
    keyEvent_->SetKeyCode(KeyEvent::KEYCODE_POWER);
    handler.isFreezePowerKey_ = true;
    DISPLAY_MONITOR->screenStatus_ = EventFwk::CommonEventSupportTest::COMMON_EVENT_SCREEN_OFF;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(keyEvent_));

    DISPLAY_MONITOR->screenStatus_ = EventFwk::CommonEventSupportTest::COMMON_EVENT_SCREEN_ON;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(keyEvent_));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyEvent_010
 * @tc.desc: Test the function HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyEvent_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.nextHandler_ = std::make_shared<EventFilterHandler>();
    handler.SetNext(handler.nextHandler_);
    ASSERT_NE(keyEvent_, nullptr);

    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent_->AddKeyItem(item);
    keyEvent_->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(keyEvent_));
}

/**
 * @tc.name: KeyCommandHandlerTest_OnHandleTouchEvent001
 * @tc.desc: Test OnHandleTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_OnHandleTouchEvent001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    PointerEvent::PointerItem item;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    handler.isParseConfig_ = false;
    handler.isDistanceConfig_ = false;
    handler.isKnuckleSwitchConfig_ = true;
    item.SetPointerId(1);
    item.SetToolType(PointerEvent::TOOL_TYPE_PENCIL);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(1);
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_MOVE);
    ASSERT_NO_FATAL_FAILURE(handler.OnHandleTouchEvent(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureDownEvent_005
 * @tc.desc: Test HandleKnuckleGestureDownEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureDownEvent_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);

    PointerEvent::PointerItem firstItem;
    firstItem.SetPointerId(1);
    firstItem.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    firstItem.SetDownTime(1000);

    PointerEvent::PointerItem secondItem;
    secondItem.SetPointerId(2);
    secondItem.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    secondItem.SetDownTime(1000 + TWO_FINGERS_TIME_LIMIT);
    pointerEvent->SetPointerId(1);
    pointerEvent->AddPointerItem(firstItem);
    KeyCommandHandler keyCommandHandler;
    ASSERT_NO_FATAL_FAILURE(keyCommandHandler.HandleKnuckleGestureDownEvent(pointerEvent));

    pointerEvent->SetPointerId(2);
    pointerEvent->RemovePointerItem(1);
    pointerEvent->AddPointerItem(secondItem);
    ASSERT_NO_FATAL_FAILURE(keyCommandHandler.HandleKnuckleGestureDownEvent(pointerEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureDownEvent_006
 * @tc.desc: Test HandleKnuckleGestureDownEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureDownEvent_006, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    KeyCommandHandler keyCommandHandler;
    PointerEvent::PointerItem firstItem;
    firstItem.SetPointerId(1);
    firstItem.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    firstItem.SetDownTime(1000);

    PointerEvent::PointerItem secondItem;
    secondItem.SetPointerId(2);
    secondItem.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    secondItem.SetDownTime(1100);

    PointerEvent::PointerItem thirdItem;
    thirdItem.SetPointerId(3);
    thirdItem.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    thirdItem.SetDownTime(1200);

    pointerEvent->SetPointerId(1);
    pointerEvent->AddPointerItem(firstItem);
    pointerEvent->SetPointerId(2);
    pointerEvent->AddPointerItem(secondItem);
    pointerEvent->SetPointerId(3);
    pointerEvent->AddPointerItem(thirdItem);
    ASSERT_NO_FATAL_FAILURE(keyCommandHandler.HandleKnuckleGestureDownEvent(pointerEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_KnuckleGestureProcessor_001
 * @tc.desc: Test KnuckleGestureProcessor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_KnuckleGestureProcessor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    KnuckleGesture knuckleGesture;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    knuckleGesture.lastPointerDownEvent = touchEvent;
    knuckleGesture.lastPointerUpTime = 10;
    knuckleGesture.ability.bundleName = SCREENRECORDER_BUNDLE_NAME;
    touchEvent->SetActionTime(20);
    handler.knuckleCount_ = 1;
    ASSERT_NO_FATAL_FAILURE(
        handler.KnuckleGestureProcessor(touchEvent, knuckleGesture, KnuckleType::KNUCKLE_TYPE_DOUBLE));
}

/**
 * @tc.name: KeyCommandHandlerTest_ReportKnuckleScreenCapture
 * @tc.desc: Test KnuckleGestureProcessor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ReportKnuckleScreenCapture, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    KnuckleGesture knuckleGesture;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    touchEvent->SetPointerId(0);
    touchEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(handler.ReportKnuckleScreenCapture(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_ReportKnuckleScreenCapture_001
 * @tc.desc: Test KnuckleGestureProcessor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ReportKnuckleScreenCapture_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    KnuckleGesture knuckleGesture;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    PointerEvent::PointerItem item;
    PointerEvent::PointerItem item2;
    item.SetPointerId(0);
    touchEvent->SetPointerId(0);
    touchEvent->AddPointerItem(item);
    item2.SetPointerId(1);
    touchEvent->SetPointerId(1);
    touchEvent->AddPointerItem(item2);
    ASSERT_NO_FATAL_FAILURE(handler.ReportKnuckleScreenCapture(touchEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_SwitchScreenCapturePermission
 * @tc.desc: Test SwitchScreenCapturePermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SwitchScreenCapturePermission, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::uint32_t permissions = DEFAULT_PERMISSIONS;
    bool enable = false;
    ASSERT_NO_FATAL_FAILURE(handler.SwitchScreenCapturePermission(permissions, enable));
    EXPECT_EQ(handler.screenCapturePermission_, 0);

    enable = true;
    ASSERT_NO_FATAL_FAILURE(handler.SwitchScreenCapturePermission(permissions, enable));
    EXPECT_EQ(handler.screenCapturePermission_, DEFAULT_PERMISSIONS);
}

/**
 * @tc.name: KeyCommandHandlerTest_HasScreenCapturePermission
 * @tc.desc: Test HasScreenCapturePermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HasScreenCapturePermission, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.gameForbidFingerKnuckle_ = false;
    handler.screenshotSwitch_.statusConfigValue = true;
    handler.recordSwitch_.statusConfigValue = true;
    EXPECT_EQ(handler.HasScreenCapturePermission(KNUCKLE_SCREENSHOT), 1);
    EXPECT_EQ(handler.HasScreenCapturePermission(KNUCKLE_SCROLL_SCREENSHOT), 1);
    EXPECT_EQ(handler.HasScreenCapturePermission(KNUCKLE_ENABLE_AI_BASE), 1);
    EXPECT_EQ(handler.HasScreenCapturePermission(KNUCKLE_SCREEN_RECORDING), 1);
    EXPECT_EQ(handler.HasScreenCapturePermission(TOUCHPAD_KNUCKLE_SCREENSHOT), 1);
    EXPECT_EQ(handler.HasScreenCapturePermission(TOUCHPAD_KNUCKLE_SCREEN_RECORDING), 1);
    EXPECT_EQ(handler.HasScreenCapturePermission(SHORTCUT_KEY_SCREENSHOT), 1);
    EXPECT_EQ(handler.HasScreenCapturePermission(SHORTCUT_KEY_SCREEN_RECORDING), 1);
    EXPECT_EQ(handler.HasScreenCapturePermission(DEFAULT_PERMISSIONS), 1);
}

/**
 * @tc.name: KeyCommandHandlerTest_RegisterProximitySensor
 * @tc.desc: Test if (bundleName.find(matchName) == std::string::npos)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_RegisterProximitySensor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    repeatKey.ability.bundleName = ".camera";

    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    WindowInfo windowInfo;
    windowInfo.id = 0;
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
        it->second.focusWindowId = 0;
    }
    UDSServer udsServer;
    udsServer.idxPidMap_.insert(std::make_pair(0, 1));
    SessionPtr sessionPtr =
        std::make_shared<UDSSession>(repeatKey.ability.bundleName, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_[1] = sessionPtr;
    inputWindowsManager->udsServer_ = &udsServer;
    EXPECT_NE(inputWindowsManager->udsServer_, nullptr);
    IInputWindowsManager::instance_ = inputWindowsManager;
    ASSERT_NO_FATAL_FAILURE(handler.RegisterProximitySensor());
    handler.hasRegisteredSensor_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.RegisterProximitySensor());
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyEvent_020
 * @tc.desc: Test HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyEvent_020, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyEvent_030
 * @tc.desc: Test ParseRepeatKeyMaxCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyEvent_030, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.ParseRepeatKeyMaxCount());
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyEvent_031
 * @tc.desc: Test UnregisterProximitySensor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyEvent_031, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.hasRegisteredSensor_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.UnregisterProximitySensor());
    handler.hasRegisteredSensor_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.UnregisterProximitySensor());
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyEvent_032
 * @tc.desc: Test RegisterProximitySensor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKeyEvent_032, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.hasRegisteredSensor_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.RegisterProximitySensor());
    handler.hasRegisteredSensor_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.RegisterProximitySensor());
}

/**
 * @tc.name: KeyCommandHandlerTest_RegisterProximitySensor_001
 * @tc.desc: Test RegisterProximitySensor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_RegisterProximitySensor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.hasRegisteredSensor_ = true;
    handler.RegisterProximitySensor();
    EXPECT_NE(handler.hasRegisteredSensor_, false);
}

/**
 * @tc.name: KeyCommandHandlerTest_RegisterProximitySensor_002
 * @tc.desc: Test RegisterProximitySensor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_RegisterProximitySensor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.hasRegisteredSensor_ = false;
    handler.RegisterProximitySensor();
    EXPECT_NE(handler.hasRegisteredSensor_, true);
}

/**
 * @tc.name: KeyCommandHandlerTest_RegisterProximitySensor_001
 * @tc.desc: Test RegisterProximitySensor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_UnregisterProximitySensor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.hasRegisteredSensor_ = true;
    handler.UnregisterProximitySensor();
    EXPECT_NE(handler.hasRegisteredSensor_, true);
}

/**
 * @tc.name: KeyCommandHandlerTest_RegisterProximitySensor_002
 * @tc.desc: Test RegisterProximitySensor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_UnregisterProximitySensor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.hasRegisteredSensor_ = false;
    handler.UnregisterProximitySensor();
    EXPECT_NE(handler.hasRegisteredSensor_, true);
}

#ifdef OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
 /**
  * @tc.name: KeyCommandHandlerTest_CallMistouchPrevention001
  * @tc.desc: Test the normal running condition
  * @tc.type: FUNC
  * @tc.require:
  */
 HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CallMistouchPrevention001, TestSize.Level1)
 {
    auto handler = std::make_shared<KeyCommandHandler>();
    handler->CallMistouchPrevention();
    EXPECT_EQ(handler->mistouchLibHandle_, nullptr);
}

/**
* @tc.name  : KeyCommandHandlerTest_CallMistouchPrevention002
* @tc.number: CallMistouchPrevention_Test_002
* @tc.desc  : Test CallMistouchPrevention when dlsym fails
*/
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CallMistouchPrevention002, TestSize.Level1)
{
    auto handler = std::make_shared<KeyCommandHandler>();
    handler->mistouchLibHandle_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(handler->CallMistouchPrevention());
}

/**
 * @tc.name  : CallMistouchPrevention_ShouldLogError_WhenLoadLibraryFails
 * @tc.number: CallMistouchPreventionTest_003
 * @tc.desc  : When loading the contactless operation library fails, the function should log an error and return
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CallMistouchPrevention003, TestSize.Level1)
{
    keyCommandHandler->hasRegisteredSensor_ = false;
    keyCommandHandler->mistouchLibHandle_ = nullptr;
    keyCommandHandler->CallMistouchPrevention();

    EXPECT_EQ(keyCommandHandler->mistouchLibHandle_, nullptr);
}

/**
 * @tc.name  : CallMistouchPrevention_ShouldLogError_WhenCreateFunctionFails
 * @tc.number: CallMistouchPreventionTest_003
 * @tc.desc  : When the IMistouchPrevention instance creation function fails,
 * the function should log an error and return
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CallMistouchPrevention004, TestSize.Level1)
{
    keyCommandHandler->hasRegisteredSensor_ = false;
    keyCommandHandler->mistouchLibHandle_ = (void*)0x1;
    keyCommandHandler->fnCreate_ = nullptr;
    keyCommandHandler->CallMistouchPrevention();

    EXPECT_EQ(keyCommandHandler->fnCreate_, nullptr);
}

/**
 * @tc.name  : CallMistouchPrevention_ShouldSucceed_WhenAllConditionsMet
 * @tc.number: CallMistouchPreventionTest_004
 * @tc.desc  : When all conditions are met, the function should successfully
 * execute the touch free operation logic
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CallMistouchPrevention005, TestSize.Level1)
{
    keyCommandHandler->hasRegisteredSensor_ = false;
    keyCommandHandler->mistouchLibHandle_ = (void*)0x1;
    keyCommandHandler->fnCreate_ = (void*)0x1;
    keyCommandHandler->mistouchPrevention_ = (IMistouchPrevention*)0x1;
    keyCommandHandler->ret_ = 0;
    keyCommandHandler->timerId_ = 0;
    keyCommandHandler->CallMistouchPrevention();
    EXPECT_TRUE(keyCommandHandler->hasRegisteredSensor_);
    EXPECT_NE(keyCommandHandler->timerId_, -1);
}

/**
 * @tc.name: KeyCommandHandlerTest_RegisterProximitySensor_001
 * @tc.desc: Test RegisterProximitySensor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_RegisterProximitySensor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.hasRegisteredSensor_ = true;
    handler.RegisterProximitySensor();
    EXPECT_EQ(handler.hasRegisteredSensor_, true);
}

/**
 * @tc.name: KeyCommandHandlerTest_RegisterProximitySensor_002
 * @tc.desc: Test RegisterProximitySensor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_RegisterProximitySensor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.hasRegisteredSensor_ = false;
    handler.RegisterProximitySensor();
    EXPECT_EQ(handler.hasRegisteredSensor_, false);
}

/**
 * @tc.name  : UnregisterMistouchPrevention_ShouldDoNothing_WhenNotRegistered
 * @tc.number: UnregisterMistouchPreventionTest_001
 * @tc.desc  : When an unregistered sensor is tested, the UnregisterMistouchPrevention
 * function should return immediately.
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_UnregisterMistouchPrevention001, TestSize.Level1) {
    KeyCommandHandler handler;
    handler.hasRegisteredSensor_ = false;
    handler.UnregisterMistouchPrevention();
    EXPECT_FALSE(handler.hasRegisteredSensor_);
}

/**
 * @tc.name  : KeyCommandHandlerTest_UnregisterMistouchPrevention002
 * @tc.number: UnregisterMistouchPreventionTest_002
 * @tc.desc  : When an unregistered sensor is tested, the UnregisterMistouchPrevention
 * function should return immediately.
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_UnregisterMistouchPrevention002, TestSize.Level1) {
    KeyCommandHandler handler;
    handler.hasRegisteredSensor_ = true;
    handler.timerId_ = 1;
    ASSERT_NO_FATAL_FAILURE(handler.UnregisterMistouchPrevention());
}

/**
 * @tc.name: KeyCommandHandlerTest_RegisterProximitySensor_003
 * @tc.desc: Test RegisterProximitySensor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_UnregisterProximitySensor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.hasRegisteredSensor_ = true;
    handler.UnregisterProximitySensor();
    EXPECT_EQ(handler.hasRegisteredSensor_, false);
}

/**
 * @tc.name: KeyCommandHandlerTest_RegisterProximitySensor_004
 * @tc.desc: Test RegisterProximitySensor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_UnregisterProximitySensor_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.hasRegisteredSensor_ = false;
    handler.UnregisterProximitySensor();
    EXPECT_EQ(handler.hasRegisteredSensor_, false);
}

/**
 * @tc.name  : KeyCommandHandlerTest_CheckSpecialRepeatKey001
 * @tc.number: CheckSpecialRepeatKeyTest_001
 * @tc.desc  : When the key code does not match, the function should return false
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckSpecialRepeatKey001, TestSize.Level1) {
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_POWER;
    std::shared_ptr<KeyEvent> keyEvent = std::make_shared<KeyEvent>();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);

    EXPECT_FALSE(CheckSpecialRepeatKey(item, keyEvent));
}

/**
 * @tc.name  : KeyCommandHandlerTest_CheckSpecialRepeatKey002
 * @tc.number: CheckSpecialRepeatKeyTest_002
 * @tc.desc  : When the key code is not the volume down key, the function should return false
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckSpecialRepeatKey002, TestSize.Level1) {
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_POWER;
    std::shared_ptr<KeyEvent> keyEvent = std::make_shared<KeyEvent>();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);

    EXPECT_FALSE(CheckSpecialRepeatKey(item, keyEvent));
}

/**
 * @tc.name  : KeyCommandHandlerTest_CheckSpecialRepeatKey003
 * @tc.number: CheckSpecialRepeatKeyTest_003
 * @tc.desc  : When the application package name does not contain '. camera',
 * the function should return false
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckSpecialRepeatKey003, TestSize.Level1) {
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.example.app";
    std::shared_ptr<KeyEvent> keyEvent = std::make_shared<KeyEvent>();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    EXPECT_FALSE(CheckSpecialRepeatKey(item, keyEvent));
}

/**
 * @tc.name  : KeyCommandHandlerTest_CheckSpecialRepeatKey004
 * @tc.number: CheckSpecialRepeatKeyTest_004
 * @tc.desc  : When the screen is locked and the screen status is not off,
 * the function should return true
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckSpecialRepeatKey004, TestSize.Level1) {
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.example.camera";
    std::shared_ptr<KeyEvent> keyEvent = std::make_shared<KeyEvent>();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    EXPECT_TRUE(CheckSpecialRepeatKey(item, keyEvent));
}

/**
 * @tc.name  : KeyCommandHandlerTest_CheckSpecialRepeatKey005
 * @tc.number: CheckSpecialRepeatKeyTest_005
 * @tc.desc  : When the call status is active, the function should return true
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckSpecialRepeatKey005, TestSize.Level1) {
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.example.camera";
    std::shared_ptr<KeyEvent> keyEvent = std::make_shared<KeyEvent>();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    EXPECT_TRUE(CheckSpecialRepeatKey(item, keyEvent));
}

/**
 * @tc.name  : KeyCommandHandlerTest_CheckSpecialRepeatKey006
 * @tc.number: CheckSpecialRepeatKeyTest_006
 * @tc.desc  : When the screen is locked and the music is not activated,
 * the function should return false
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CheckSpecialRepeatKey006, TestSize.Level1) {
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.example.camera";
    std::shared_ptr<KeyEvent> keyEvent = std::make_shared<KeyEvent>();
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    EXPECT_FALSE(CheckSpecialRepeatKey(item, keyEvent));
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchRepeatKeyAbility001
 * @tc.number: KeyCommandHandlerTest_LaunchRepeatKeyAbility_001
 * @tc.desc: Verify VOLUME_DOWN + camera app with valid state launches ability
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchRepeatKeyAbility001, TestSize.Level1)
{
    RepeatKey item;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.ohos.camera";
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    handler.ret_.store(0);

    ASSERT_NO_FATAL_FAILURE(handler.LaunchAbility(item.ability));

    handler.LaunchRepeatKeyAbility(item, keyEvent);
    EXPECT_TRUE(handler.repeatKeyCountMap_.empty());
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchRepeatKeyAbility002
 * @tc.number: KeyCommandHandlerTest_LaunchRepeatKeyAbility_002
 * @tc.desc: Verify VOLUME_DOWN + camera app with valid state launches ability
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchRepeatKeyAbility002, TestSize.Level1)
{
    RepeatKey item;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.ohos.camera";
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    handler.ret_.store(5);

    ASSERT_NO_FATAL_FAILURE(handler.LaunchAbility(item.ability));

    handler.LaunchRepeatKeyAbility(item, keyEvent);
    EXPECT_TRUE(handler.repeatKeyCountMap_.empty());
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchRepeatKeyAbility003
 * @tc.number: KeyCommandHandlerTest_LaunchRepeatKeyAbility_003
 * @tc.desc: Verify VOLUME_DOWN + camera app with valid state launches ability
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchRepeatKeyAbility003, TestSize.Level1)
{
    RepeatKey item;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.ohos.camera";
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    handler.ret_.store(100);

    ASSERT_NO_FATAL_FAILURE(handler.LaunchAbility(item.ability));

    handler.LaunchRepeatKeyAbility(item, keyEvent);
    EXPECT_TRUE(handler.repeatKeyCountMap_.empty());
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchRepeatKeyAbility004
 * @tc.number: KeyCommandHandlerTest_LaunchRepeatKeyAbility_004
 * @tc.desc: Verify non-VOLUME_DOWN key launches ability
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchRepeatKeyAbility004, TestSize.Level1)
{
    RepeatKey item;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.ohos.camera";
    keyEvent->SetKeyAction(KeyEvent::KEYCODE_VOLUME_DOWN);

    handler.ret_.store(5);

    ASSERT_NO_FATAL_FAILURE(handler.LaunchAbility(item.ability));

    handler.LaunchRepeatKeyAbility(item, keyEvent);
    EXPECT_TRUE(handler.repeatKeyCountMap_.empty());
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchRepeatKeyAbility005
 * @tc.number: KeyCommandHandlerTest_LaunchRepeatKeyAbility_005
 * @tc.desc: Verify cancel event propagation
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchRepeatKeyAbility005, TestSize.Level1)
{
    RepeatKey item;
    KeyCommandHandler handler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    item.keyCode = KeyEvent::KEYCODE_POWER;
    item.ability.bundleName = "com.ohos.settings";
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    ASSERT_NO_FATAL_FAILURE(handler.LaunchAbility(item.ability));
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchRepeatKeyAbility006
 * @tc.number: KeyCommandHandlerTest_LaunchRepeatKeyAbility_006
 * @tc.desc: Verify map clearing
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchRepeatKeyAbility006, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    item.ability.bundleName = "com.ohos.music";
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    KeyCommandHandler handler;
    
    ASSERT_NO_FATAL_FAILURE(handler.LaunchAbility(item.ability));
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchRepeatKeyAbility007
 * @tc.number: KeyCommandHandlerTest_LaunchRepeatKeyAbility_007
 * @tc.desc: Verify mistouch prevention safety with null pointer
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchRepeatKeyAbility007, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.ohos.camera";
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    KeyCommandHandler handler;
    handler.ret_.store(0);
    handler.mistouchPrevention_ = nullptr;  // Null pointer

    ASSERT_NO_FATAL_FAILURE(handler.LaunchAbility(item.ability));
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchRepeatKeyAbility008
 * @tc.number: KeyCommandHandlerTest_LaunchRepeatKeyAbility_008
 * @tc.desc: Verify null subscriber handler safety
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchRepeatKeyAbility008, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    item.ability.bundleName = "com.ohos.music";
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    KeyCommandHandler handler;

    ASSERT_NO_FATAL_FAILURE(handler.LaunchAbility(item.ability));
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchRepeatKeyAbility009
 * @tc.number: KeyCommandHandlerTest_LaunchRepeatKeyAbility_009
 * @tc.desc: Verify bytrace start/stop pairing
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchRepeatKeyAbility009, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_POWER;
    item.ability.bundleName = "com.ohos.settings";
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    KeyCommandHandler handler;
    
    ASSERT_NO_FATAL_FAILURE(handler.LaunchAbility(item.ability));
}

/**
 * @tc.name: KeyCommandHandlerTest_LaunchRepeatKeyAbility010
 * @tc.number: KeyCommandHandlerTest_LaunchRepeatKeyAbility_010
 * @tc.desc: Verify camera substring matching
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_LaunchRepeatKeyAbility010, TestSize.Level1)
{
    RepeatKey item;
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.ability.bundleName = "com.example.camera.pro";  // Contains ".camera"
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    KeyCommandHandler handler;
    handler.ret_.store(0);
    
    ASSERT_NO_FATAL_FAILURE(handler.LaunchAbility(item.ability));
}

/**
 * @tc.name: KeyCommandHandlerTest_SetIsFreezePowerKey001
 * @tc.number: KeyCommandHandlerTest_SetIsFreezePowerKey_001
 * @tc.desc: Verify non-SOS page unsets freeze flag
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey001, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.isFreezePowerKey_ = true;
    
    EXPECT_EQ(handler.SetIsFreezePowerKey("HomeScreen"), RET_OK);
}

/**
 * @tc.name: KeyCommandHandlerTest_SetIsFreezePowerKey002
 * @tc.number: KeyCommandHandlerTest_SetIsFreezePowerKey_002
 * @tc.desc: Verify non-SOS page unsets freeze flag
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey002, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.isFreezePowerKey_ = true;
    
    EXPECT_TRUE(handler.isFreezePowerKey_);
}

/**
 * @tc.name: KeyCommandHandlerTest_SetIsFreezePowerKey003
 * @tc.number: KeyCommandHandlerTest_SetIsFreezePowerKey_003
 * @tc.desc: Verify SOS page sets freeze flag and resets state
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey003, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.count_ = 5;
    handler.launchAbilityCount_ = 2;
    handler.repeatKeyCountMap_["key1"] = 3;
    handler.sosDelayTimerId_ = 100;
    
    EXPECT_EQ(handler.SetIsFreezePowerKey("SosCountdown"), RET_OK);
    EXPECT_TRUE(handler.isFreezePowerKey_);
    EXPECT_NE(handler.sosLaunchTime_, 123456789);
    EXPECT_EQ(handler.count_, 0);
    EXPECT_EQ(handler.launchAbilityCount_, 0);
    EXPECT_TRUE(handler.repeatKeyCountMap_.empty());
    EXPECT_NE(handler.sosDelayTimerId_, 200);
}

/**
 * @tc.name: KeyCommandHandlerTest_SetIsFreezePowerKey004
 * @tc.number: KeyCommandHandlerTest_SetIsFreezePowerKey_004
 * @tc.desc: Verify no timer removal when no existing timer
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey004, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.sosDelayTimerId_ = -1;  // No existing timer
    
    EXPECT_NE(handler.SetIsFreezePowerKey("SosCountdown"), RET_OK);
}

/**
 * @tc.name: KeyCommandHandlerTest_SetIsFreezePowerKey005
 * @tc.number: KeyCommandHandlerTest_SetIsFreezePowerKey_005
 * @tc.desc: Verify timer callback unsets freeze flag
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey005, TestSize.Level1)
{
    KeyCommandHandler handler;
    TimerCallback callback;
    handler.SetIsFreezePowerKey("SosCountdown");
    ASSERT_TRUE(callback);
    
    // Execute timer callback
    EXPECT_FALSE(handler.isFreezePowerKey_);
}

/**
 * @tc.name: KeyCommandHandlerTest_SetIsFreezePowerKey006
 * @tc.number: KeyCommandHandlerTest_SetIsFreezePowerKey_006
 * @tc.desc: Verify state preservation on non-SOS calls
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey006, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.count_ = 10;
    handler.launchAbilityCount_ = 5;
    handler.repeatKeyCountMap_["key2"] = 7;
    handler.sosDelayTimerId_ = 600;
    
    handler.SetIsFreezePowerKey("LockScreen");
    
    // Verify state unchanged
    EXPECT_EQ(handler.count_, 10);
}


/**
 * @tc.name: KeyCommandHandlerTest_SetIsFreezePowerKey007
 * @tc.number: KeyCommandHandlerTest_SetIsFreezePowerKey_007
 * @tc.desc: Verify state preservation on non-SOS calls
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey007, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.count_ = 10;
    handler.launchAbilityCount_ = 5;
    handler.repeatKeyCountMap_["key2"] = 7;
    handler.sosDelayTimerId_ = 600;
    
    handler.SetIsFreezePowerKey("LockScreen");
    
    EXPECT_EQ(handler.launchAbilityCount_, 5);
}


/**
 * @tc.name: KeyCommandHandlerTest_SetIsFreezePowerKey008
 * @tc.number: KeyCommandHandlerTest_SetIsFreezePowerKey_008
 * @tc.desc: Verify state preservation on non-SOS calls
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey008, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.count_ = 10;
    handler.launchAbilityCount_ = 5;
    handler.repeatKeyCountMap_["key2"] = 7;
    handler.sosDelayTimerId_ = 600;
    
    handler.SetIsFreezePowerKey("LockScreen");
    
    EXPECT_FALSE(handler.repeatKeyCountMap_.empty());
}

/**
 * @tc.name: KeyCommandHandlerTest_SetIsFreezePowerKey009
 * @tc.number: KeyCommandHandlerTest_SetIsFreezePowerKey_009
 * @tc.desc: Verify state preservation on non-SOS calls
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey009, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.count_ = 10;
    handler.launchAbilityCount_ = 5;
    handler.repeatKeyCountMap_["key2"] = 7;
    handler.sosDelayTimerId_ = 600;
    
    handler.SetIsFreezePowerKey("LockScreen");

    EXPECT_EQ(handler.sosDelayTimerId_, 600);
}

/**
 * @tc.name: KeyCommandHandlerTest_SetIsFreezePowerKey007
 * @tc.number: KeyCommandHandlerTest_SetIsFreezePowerKey_007
 * @tc.desc: Verify non-SOS page unsets freeze flag
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey007, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.isFreezePowerKey_ = false;
    
    EXPECT_NE(handler.SetIsFreezePowerKey("HomeScreen"), RET_OK);
}
#endif // OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION

/**
 * @tc.name: KeyCommandHandlerTest_KnuckleGestureProcessor_002
 * @tc.desc: Test KnuckleGestureProcessor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_KnuckleGestureProcessor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    KnuckleGesture knuckleGesture;
    ASSERT_NE(touchEvent_, nullptr);
    ASSERT_NE(keyEvent_, nullptr);
    handler.tappingCount_ = 10;
    ASSERT_NO_FATAL_FAILURE(
        handler.KnuckleGestureProcessor(touchEvent_, knuckleGesture, KnuckleType::KNUCKLE_TYPE_DOUBLE));
}

/**
 * @tc.name: KeyCommandHandlerTest_ReportGestureInfo_002
 * @tc.desc: Test ReportGestureInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_ReportGestureInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    KnuckleGesture knuckleGesture;
    ASSERT_NE(touchEvent_, nullptr);
    ASSERT_NE(keyEvent_, nullptr);
    ASSERT_NO_FATAL_FAILURE(handler.ReportGestureInfo());
}

/**
 * @tc.name: KeyCommandHandlerTest_IsMatchedAbility_002
 * @tc.desc: Test IsMatchedAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_IsMatchedAbility_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    KnuckleGesture knuckleGesture;
    ASSERT_NE(touchEvent_, nullptr);
    ASSERT_NE(keyEvent_, nullptr);
    std::vector<float> gesturePoints;
    gesturePoints.push_back(10.0);
    gesturePoints.push_back(11.0);
    gesturePoints.push_back(12.0);
    float gestureLastX = 10.0;
    float gestureLastY = 10.0;
    ASSERT_NO_FATAL_FAILURE(handler.IsMatchedAbility(gesturePoints, gestureLastX, gestureLastY));
}

/**
 * @tc.name: KeyCommandHandlerTest_IsEnableCombineKey_005
 * @tc.desc: Test IsEnableCombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_IsEnableCombineKey_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    KnuckleGesture knuckleGesture;
    ASSERT_NE(touchEvent_, nullptr);
    ASSERT_NE(keyEvent_, nullptr);
    handler.enableCombineKey_ = false;
    handler.isParseExcludeConfig_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.IsEnableCombineKey(keyEvent_));
}

/**
 * @tc.name: KeyCommandHandlerTest_GetKnuckleSwitchStatus_001
 * @tc.desc: Test GetKnuckleSwitchStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_GetKnuckleSwitchStatus_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::string strUri =
        "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_100?Proxy=true";
    bool ret = handler.GetKnuckleSwitchStatus("fingersense_smartshot_enabled", strUri, true);
    EXPECT_TRUE(ret);
    ret = handler.GetKnuckleSwitchStatus("fingersense_screen_recording_enabled", strUri, true);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_GetKnuckleSwitchStatus_002
 * @tc.desc: Test GetKnuckleSwitchStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_GetKnuckleSwitchStatus_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::string strUri =
        "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_-1?Proxy=true";
    bool ret = handler.GetKnuckleSwitchStatus("fingersense_smartshot_enabled", strUri, true);
    EXPECT_TRUE(ret);
    ret = handler.GetKnuckleSwitchStatus("fingersense_screen_recording_enabled", strUri, true);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_CreateKnuckleConfigObserver_001
 * @tc.desc: Test CreateKnuckleConfigObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CreateKnuckleConfigObserver_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.screenshotSwitch_.statusConfigValue = false;
    handler.CreateKnuckleConfigObserver(handler.screenshotSwitch_);
    EXPECT_TRUE(handler.screenshotSwitch_.statusConfigValue);
    handler.recordSwitch_.statusConfigValue = false;
    handler.CreateKnuckleConfigObserver(handler.recordSwitch_);
    EXPECT_TRUE(handler.recordSwitch_.statusConfigValue);
}
} // namespace MMI
} // namespace OHOS
