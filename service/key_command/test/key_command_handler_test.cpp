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
#include "mmi_log.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_preferences_manager.h"
#include "stylus_key_handler.h"
#include "system_info.h"
#define private public
#include "key_command_handler.h"
#undef private
#include "key_command_context.h"

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
constexpr int32_t TWO_FINGERS_TIME_LIMIT = 150000;
constexpr float DOUBLE_CLICK_DISTANCE_DEFAULT_CONFIG = 64.0;
constexpr int32_t WINDOW_INPUT_METHOD_TYPE = 2105;
constexpr int32_t MODULE_TYPE { 1 };
constexpr int32_t UDS_FD { -1 };
constexpr int32_t UDS_UID { 100 };
constexpr int32_t UDS_PID { 100 };

const std::string SCREENRECORDER_BUNDLE_NAME { "com.hmos.screenrecorder" };
const vector<float> CIRCLE_COORDINATES = {
    328.0f, 596.0f, 328.0f, 597.0f, 322.0f, 606.0f,
    306.0f, 635.0f, 291.0f, 665.0f, 283.0f, 691.0f,
    291.0f, 739.0f, 300.0f, 751.0f, 312.0f, 759.0f,
    327.0f, 765.0f, 343.0f, 768.0f, 361.0f, 769.0f,
    379.0f, 767.0f, 395.0f, 761.0f, 411.0f, 751.0f,
    425.0f, 737.0f, 439.0f, 718.0f, 449.0f, 709.0f,
    456.0f, 683.0f, 459.0f, 654.0f, 451.0f, 569.0f,
    437.0f, 552.0f, 418.0f, 542.0f, 392.0f, 540.0f,
    363.0f, 545.0f };
const vector<int64_t> CIRCLE_TIMESTAMPS = {
    71304451, 71377126, 71387783, 71398239, 71409629,
    71419392, 71461386, 71472044, 71483797, 71493077,
    71503426, 71514339, 71524715, 71535126, 71545652,
    71556329, 71566506, 71577283, 71587745, 71598921,
    71630319, 71642155, 71651090, 71662474, 71671657 };
const vector<float> CURVE_COORDINATES = {
    374.0f, 489.0f, 373.0f, 489.0f, 365.0f, 491.0f,
    341.0f, 503.0f, 316.0f, 519.0f, 300.0f, 541.0f,
    293.0f, 561.0f, 289.0f, 582.0f, 292.0f, 643.0f,
    301.0f, 657.0f, 317.0f, 668.0f, 336.0f, 681.0f,
    358.0f, 695.0f, 381.0f, 706.0f, 403.0f, 717.0f,
    423.0f, 715.0f, 441.0f, 727.0f, 458.0f, 739.0f,
    468.0f, 751.0f, 474.0f, 764.0f, 467.0f, 812.0f,
    455.0f, 828.0f, 435.0f, 844.0f, 412.0f, 860.0f,
    387.0f, 876.0f, 362.0f, 894.0f, 338.0f, 906.0f,
    317.0f, 913.0f, 296.0f, 918.0f };
const vector<int64_t> CURVE_TIMESTAMPS = {
    134900436, 134951403, 134962832, 134973234,
    134983492, 134995390, 135003876, 135014389,
    135045917, 135057774, 135067076, 135077688,
    135088139, 135098494, 135109130, 135119679,
    135130101, 135140670, 135151182, 135161672,
    135193739, 135203790, 135214272, 135224868,
    135236197, 135245828, 135256481, 135267186,
    135276939 };
const vector<float> LINE_COORDINATES = {
    390.0f, 340.0f, 390.0f, 348.0f, 390.0f, 367.0f,
    387.0f, 417.0f, 385.0f, 455.0f, 384.0f, 491.0f,
    382.0f, 516.0f, 381.0f, 539.0f, 380.0f, 564.0f,
    378.0f, 589.0f, 377.0f, 616.0f, 376.0f, 643.0f,
    375.0f, 669.0f, 375.0f, 694.0f, 374.0f, 718.0f,
    374.0f, 727.0f, 374.0f, 750.0f, 374.0f, 771.0f,
    374.0f, 791.0f, 374.0f, 811.0f, 375.0f, 831.0f,
    375.0f, 851.0f, 376.0f, 870.0f, 377.0f, 886.0f,
    377.0f, 902.0f, 379.0f, 918.0f, 379.0f, 934.0f,
    380.0f, 950.0f, 381.0f, 963.0f, 383.0f, 977.0f,
    385.0f, 992.0f, 387.0f, 1002.0f, 389.0f, 1016.0f,
    390.0f, 1030.0f, 390.0f, 1042.0f, 390.0f, 1052.0f,
    390.0f, 1061.0f, 391.0f, 1069.0f, 391.0f, 1075.0f,
    391.0f, 1080.0f, 391.0f, 1085.0f, 391.0f, 1089.0f,
    392.0f, 1095.0f, 393.0f, 1099.0f, 394.0f, 1103.0f,
    395.0f, 1111.0f, 395.0f, 1117.0f, 396.0f, 1124.0f,
    397.0f, 1130.0f, 397.0f, 1134.0f, 397.0f, 1138.0f };
const vector<int64_t> LINE_TIMESTAMPS = {
    70809086, 70912930, 70923294, 70933960,
    70944571, 70955130, 70965726, 70976076,
    70986620, 70997190, 71007517, 71017998,
    71028551, 71039171, 71049654, 71060120,
    71070809, 71082130, 71091709, 71102285,
    71112746, 71123402, 71133898, 71144469,
    71154894, 71165617, 71175944, 71186477,
    71197199, 71207737, 71218030, 71228652,
    71239243, 71249733, 71260291, 71270821,
    71281313, 71291919, 71302477, 71313573,
    71323426, 71333880, 71355034, 71376110,
    71418297, 71439219, 71449749, 71460268,
    71470874, 71481275, 71744747 };
} // namespace
class KeyCommandHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
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
    struct timespec time = { 0 };
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
 * @tc.name: KeyCommandHandlerTest_OnHandleEvent_002
 * @tc.desc: Test the funcation OnHandleEvent
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
    handler.context_.specialKeys_.insert(std::make_pair(18, 18));
    bool ret = handler.OnHandleEvent(key);
    EXPECT_TRUE(ret);
    key->SetKeyCode(KeyEvent::KEYCODE_POWER);
    handler.context_.specialTimers_.insert(std::make_pair(KeyEvent::KEYCODE_POWER, 10));
    ret = handler.OnHandleEvent(key);
    EXPECT_TRUE(ret);
    key->SetKeyCode(5);
    ret = handler.OnHandleEvent(key);
    EXPECT_FALSE(ret);
}



/**
 * @tc.name: KeyCommandHandlerTest_HandlePointerEvent_002
 * @tc.desc: Test the funcation HandlePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandlePointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    handler.context_.isParseConfig_ = true;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_QUADTAP);
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerEvent(pointerEvent));

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_TRIPTAP);
    EventLogHelper eventLogHelper;
    eventLogHelper.userType_ = "beta";
    pointerEvent->bitwise_ = 0;
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerEvent(pointerEvent));
    eventLogHelper.userType_ = "default";
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerEvent(pointerEvent));
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_PRIVACY_MODE;
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerEvent(pointerEvent));
}


/**
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureEvent_004
 * @tc.desc: Test the funcation HandleKnuckleGestureEvent
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
    handler.context_.isParseConfig_ = false;
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
    handler.context_.twoFingerGesture_.active = true;
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
    handler.context_.twoFingerGesture_.active = true;
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
    handler.context_.twoFingerGesture_.active = true;
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
    ASSERT_NO_FATAL_FAILURE(handler.KnuckleGestureProcessor(touchEvent,
        knuckleGesture, KnuckleType::KNUCKLE_TYPE_SINGLE));
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

    bool isHandled = eventKeyCommandHandler.shortkeyHandler_->HandleShortKeys(keyEvent);
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

    eventKeyCommandHandler.context_.isDownStart_ = true;
    bool isRepeatKeyHandle = eventKeyCommandHandler.repeatKeyHandler_->HandleRepeatKeys(keyEvent);
    EXPECT_FALSE(isRepeatKeyHandle);
    bool ret = eventKeyCommandHandler.HandleEvent(keyEvent);
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
    KeyCommandHandler eventKeyCommandHandler;
    type = NotifyType::REGIONGESTURE;
    ASSERT_NO_FATAL_FAILURE(eventKeyCommandHandler.ProcessKnuckleGestureTouchUp(type));
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
    keyCommandHandler.twoFingerGestureHandler_->HandlePointerActionMoveEvent(pointerEvent);
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
    handler.context_.businessIds_ = {"businessId1", "businessId2"};
    ASSERT_EQ(handler.UpdateSettingsXml("businessId3", 100), COMMON_PARAMETER_ERROR);
    handler.context_.businessIds_ = {"businessId"};
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
    ASSERT_EQ(handler.downToPrevDownDistanceConfig_, handler.distanceDefaultConfig_);
    handler.AdjustDistanceConfigIfNeed(handler.distanceLongConfig_);
    handler.downToPrevDownDistanceConfig_ = handler.distanceDefaultConfig_;
    handler.AdjustDistanceConfigIfNeed(handler.distanceDefaultConfig_ - 1);
    ASSERT_EQ(handler.downToPrevDownDistanceConfig_, handler.distanceLongConfig_);
    handler.downToPrevDownDistanceConfig_ = handler.distanceLongConfig_;
    handler.AdjustDistanceConfigIfNeed(handler.distanceDefaultConfig_ - 1);
    ASSERT_EQ(handler.downToPrevDownDistanceConfig_, handler.distanceDefaultConfig_);
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
    handler.context_.specialKeys_.insert(std::make_pair(keyCodeVolumeUp, keyAction));
    ASSERT_NO_FATAL_FAILURE(handler.HandleSpecialKeys(keyCodeVolumeUp, keyAction));
    handler.context_.specialKeys_.clear();

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
    handler.context_.specialKeys_.insert(std::make_pair(powerKeyCode, keyAction));
    ASSERT_NO_FATAL_FAILURE(handler.HandleSpecialKeys(keyCode, keyAction));

    keyAction = KeyEvent::KEY_ACTION_DOWN;
    ASSERT_NO_FATAL_FAILURE(handler.HandleSpecialKeys(powerKeyCode, keyAction));
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
    ASSERT_TRUE(handler.IsEnableCombineKey(key));
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
    handler.gesturePoints_ = { 0.0f, 1.0f, 2.0f, 3.0f };

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
    handler.gesturePoints_ = { 0.0f };

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
    handler.gesturePoints_ = { 0.0f };
    ASSERT_NO_FATAL_FAILURE(handler.IsValidAction(action));

    action = PointerEvent::POINTER_ACTION_UP;
    handler.gesturePoints_.assign(CIRCLE_COORDINATES.begin(), CIRCLE_COORDINATES.end());
    ASSERT_NO_FATAL_FAILURE(handler.IsValidAction(action));
}
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER

/**
 * @tc.name: KeyCommandHandlerTest_ConvertKeyActionToString_001
 * @tc.desc: Test the funcation ConvertKeyActionToString
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
 * @tc.desc: Test the funcation HandleKeyEvent
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
 * @tc.desc: Test the funcation HandlePointerEvent
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
 * @tc.desc: Test the funcation HandleTouchEvent
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
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchMove_002
 * @tc.desc: Test the funcation HandleKnuckleGestureTouchMove
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
 * @tc.desc: Test the funcation ReportIfNeed
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
 * @tc.desc: Test the funcation ReportGestureInfo
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
    GESTURESENSE_WRAPPER->touchUp_ = [](const std::vector<float> &, const std::vector<int64_t> &, bool, bool)
        -> int32_t {
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
 * @tc.name: KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_005
 * @tc.desc: Test the funcation HandleKnuckleGestureTouchUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleKnuckleGestureTouchUp_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    GESTURESENSE_WRAPPER->touchUp_ = [](const std::vector<float> &, const std::vector<int64_t> &, bool, bool)
        -> int32_t {
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
 * @tc.name: KeyCommandHandlerTest_IsEnableCombineKey_003
 * @tc.desc: Test the funcation IsEnableCombineKey
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
    handler.context_.isParseExcludeConfig_ = false;
    ASSERT_FALSE(handler.IsEnableCombineKey(key));
    handler.context_.isParseExcludeConfig_ = true;
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
    handler.sequenceHandler_->keys_.push_back(sequenceKey);
    ASSERT_FALSE(handler.IsEnableCombineKey(key));
    sequenceKey.keyCode = 2018;
    sequenceKey.keyAction = KeyEvent::KEY_ACTION_DOWN;
    handler.sequenceHandler_->keys_.push_back(sequenceKey);
    ASSERT_FALSE(handler.IsEnableCombineKey(key));
}

/**
 * @tc.name: KeyCommandHandlerTest_IsEnableCombineKey_004
 * @tc.desc: Test the funcation IsEnableCombineKey
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
    handler.context_.isParseExcludeConfig_ = true;
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
    handler.sequenceHandler_->keys_.push_back(sequenceKey);
    ASSERT_TRUE(handler.IsEnableCombineKey(key));
    sequenceKey.keyCode = KeyEvent::KEYCODE_L;
    handler.sequenceHandler_->keys_.push_back(sequenceKey);
    ASSERT_TRUE(handler.IsEnableCombineKey(key));
    sequenceKey.keyCode = KeyEvent::KEYCODE_META_LEFT;
    handler.sequenceHandler_->keys_.push_back(sequenceKey);
    ASSERT_TRUE(handler.IsEnableCombineKey(key));
    sequenceKey.keyCode = KeyEvent::KEYCODE_META_RIGHT;
    handler.sequenceHandler_->keys_.push_back(sequenceKey);
    ASSERT_TRUE(handler.IsEnableCombineKey(key));
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleEvent_001
 * @tc.desc: Test the funcation HandleEvent
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
    handler.context_.isParseExcludeConfig_ = true;
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
    handler.sequenceHandler_->keys_.push_back(sequenceKey);
    ShortcutKey shortcutKey;
    shortcutKey.preKeys = {1, 2, 3};
    shortcutKey.businessId = "business1";
    shortcutKey.statusConfig = "config1";
    shortcutKey.statusConfigValue = true;
    shortcutKey.finalKey = 4;
    shortcutKey.keyDownDuration = 5;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;
    shortcutKey.timerId = 6;
    handler.shortkeyHandler_->currentLaunchAbilityKey_.finalKey = 1;
    handler.shortkeyHandler_->currentLaunchAbilityKey_.triggerType = 2;
    key->SetKeyCode(1);
    key->SetKeyAction(2);
    handler.shortkeyHandler_->IsKeyMatch(handler.shortkeyHandler_->currentLaunchAbilityKey_, key);
    handler.context_.shortcutKeys_->insert(std::make_pair("key1", shortcutKey));
    handler.shortkeyHandler_->currentLaunchAbilityKey_.timerId = 0;
    handler.shortkeyHandler_->HandleShortKeys(key);
    handler.repeatKeyHandler_->isKeyCancel_ = true;
    bool ret = handler.HandleEvent(key);
    EXPECT_FALSE(ret);
    handler.repeatKeyHandler_->isKeyCancel_ = false;
    ret = handler.HandleEvent(key);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleEvent_002
 * @tc.desc: Test the funcation HandleEvent
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
    handler.context_.isParseExcludeConfig_ = true;
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
    handler.sequenceHandler_->keys_.push_back(sequenceKey);
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
    handler.shortkeyHandler_->HandleShortKeys(key);
    handler.context_.isDownStart_ = false;
    bool ret = handler.HandleEvent(key);
    EXPECT_FALSE(ret);
    handler.context_.isDownStart_ = true;
    ret = handler.HandleEvent(key);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_OnHandleEvent_001
 * @tc.desc: Test the funcation OnHandleEvent
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
    handler.context_.specialKeys_.insert(std::make_pair(10, keyAction));
    bool ret = handler.OnHandleEvent(key);
    EXPECT_FALSE(ret);
    key->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    int32_t keyCode = 99;
    std::list<int32_t> timerIds;
    timerIds.push_back(100);
    handler.context_.specialTimers_.insert(std::make_pair(keyCode, timerIds));
    ret = handler.OnHandleEvent(key);
    EXPECT_FALSE(ret);
    keyCode = KeyEvent::KEYCODE_VOLUME_UP;
    handler.context_.specialTimers_.insert(std::make_pair(keyCode, timerIds));
    ret = handler.OnHandleEvent(key);
    EXPECT_FALSE(ret);
}


/**
 * @tc.name: KeyCommandHandlerTest_CheckInputMethodArea_001
 * @tc.desc: Test the funcation CheckInputMethodArea
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
 * @tc.desc: Test the funcation CheckInputMethodArea
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
 * @tc.desc: Test the funcation CheckInputMethodArea
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
 * @tc.desc: Test the funcation CheckInputMethodArea
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
 * @tc.name: KeyCommandHandlerTest_CheckAndUpdateTappingCountAtDown_001
 * @tc.desc: Test the funcation CheckAndUpdateTappingCountAtDown
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
 * @tc.desc: Test the funcation CheckAndUpdateTappingCountAtDown
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
 * @tc.desc: Test the funcation CheckInputMethodArea
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
    touchEvent->targetDisplayId_ = 1;
    WindowGroupInfo windowGroupInfo;
    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(1, windowGroupInfo));
    bool ret = handler.CheckInputMethodArea(touchEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_OnHandleEvent_003
 * @tc.desc: Test the funcation OnHandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_OnHandleEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    handler.context_.isParseConfig_ = true;
    bool ret = handler.OnHandleEvent(pointerEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyCommandHandlerTest_UpdateSettingsXml_002
 * @tc.desc: Update settings xml verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_UpdateSettingsXml_002, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.context_.businessIds_ = {"businessId"};
    int32_t ret = handler.UpdateSettingsXml("businessId", -1);
    ASSERT_EQ(ret, 401);
    ret = handler.UpdateSettingsXml("businessId", 5000);
    ASSERT_EQ(ret, 401);
}

/**
 * @tc.name: KeyCommandHandlerTest_PreHandleEvent_001
 * @tc.desc: Test the funcation PreHandleEvent
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
    key->bitwise_ = 0x00000000;
    bool ret = handler.PreHandleEvent(key);
    ASSERT_TRUE(ret);
    key->bitwise_ = InputEvent::EVENT_FLAG_PRIVACY_MODE;
    ret = handler.PreHandleEvent(key);
    ASSERT_TRUE(ret);
    handler.enableCombineKey_ = false;
    ret = handler.PreHandleEvent(key);
    ASSERT_FALSE(ret);
    handler.enableCombineKey_ = true;
    handler.context_.isParseConfig_ = false;
    ret = handler.PreHandleEvent(key);
    ASSERT_TRUE(ret);
    handler.context_.isParseConfig_ = true;
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
 * @tc.name: KeyCommandHandlerTest_CalcDrawCoordinate_001
 * @tc.desc: Test CalcDrawCoordinate
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CalcDrawCoordinate_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    OLD::DisplayInfo displayInfo;
    PointerEvent::PointerItem pointerItem;
    int32_t physicalX = 1;
    int32_t physicalY = 1;
    pointerItem.SetRawDisplayX(physicalX);
    pointerItem.SetRawDisplayY(physicalY);
    auto retPair = handler.CalcDrawCoordinate(displayInfo, pointerItem);
    EXPECT_EQ(retPair.first, 1);
    EXPECT_EQ(retPair.second, 1);
}

/**
 * @tc.name: KeyCommandHandlerTest_CalcDrawCoordinate_002
 * @tc.desc: Test CalcDrawCoordinate
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CalcDrawCoordinate_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    OLD::DisplayInfo displayInfo = {
        .id = 0, .x = 0, .y = 0, .width = 100, .height = 200, .dpi = 240,
        .transform = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f}
    };
    PointerEvent::PointerItem pointerItem;
    int32_t physicalX = 10;
    int32_t physicalY = 10;
    pointerItem.SetRawDisplayX(physicalX);
    pointerItem.SetRawDisplayY(physicalY);
    auto retPair = handler.CalcDrawCoordinate(displayInfo, pointerItem);
    EXPECT_EQ(retPair.first, 21);
    EXPECT_EQ(retPair.second, 21);
}

/**
 * @tc.name: KeyCommandHandlerTest_TouchPadKnuckleDoubleClickProcess
 * @tc.desc: Test the funcation TouchPadKnuckleDoubleClickProcess
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
    DISPLAY_MONITOR-> SetScreenStatus(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    DISPLAY_MONITOR->SetScreenLocked(true);
    ASSERT_NO_FATAL_FAILURE(handler.TouchPadKnuckleDoubleClickProcess(bundleName, abilityName, action));
    DISPLAY_MONITOR-> SetScreenStatus("abc");
    ASSERT_NO_FATAL_FAILURE(handler.TouchPadKnuckleDoubleClickProcess(bundleName, abilityName, action));
    DISPLAY_MONITOR->SetScreenLocked(false);
    ASSERT_NO_FATAL_FAILURE(handler.TouchPadKnuckleDoubleClickProcess(bundleName, abilityName, action));
}
 
/**
 * @tc.name: KeyCommandHandlerTest_TouchPadKnuckleDoubleClickHandle
 * @tc.desc: Test the funcation TouchPadKnuckleDoubleClickHandle
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
 * @tc.desc: Test the funcation IsMatchedAbility
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
 * @tc.desc: Test the funcation InitKeyObserver
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
 * @tc.desc: Test the funcation SetIsFreezePowerKey
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_SetIsFreezePowerKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;
    handler.context_.isFreezePowerKey_ = true;
    std::string pageName = "pageName";
    int32_t ret = handler.SetIsFreezePowerKey(pageName);
    EXPECT_EQ(ret, RET_OK);
    handler.context_.isFreezePowerKey_ = false;
    handler.context_.sosDelayTimerId_ = 1;
    pageName = "SosCountdown";
    ret = handler.SetIsFreezePowerKey(pageName);
    EXPECT_EQ(ret, RET_OK);
    handler.context_.sosDelayTimerId_ = -1;
    ret = handler.SetIsFreezePowerKey(pageName);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: KeyCommandHandlerTest_ParseStatusConfigObserver_001
 * @tc.desc: Test the funcation ParseStatusConfigObserver
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
 * @tc.desc: Test the funcation ParseStatusConfigObserver
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
 * @tc.desc: Test the funcation ParseStatusConfigObserver
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
 * @tc.name: KeyCommandHandlerTest_PreHandleEvent_02
 * @tc.desc: Test the funcation PreHandleEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_PreHandleEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyCommandHandler handler;

    handler.context_.isParseConfig_ = false;
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
 * @tc.name: KeyCommandHandlerTest_HandleEvent_003
 * @tc.desc: Test the funcation HandleEvent
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
    handler.context_.isParseConfig_ = true;
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
    handler.context_.isParseConfig_ = true;
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
    handler.context_.isParseConfig_ = true;
    handler.isParseMaxCount_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.HandleEvent(keyEvent));
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

    handler.context_.twoFingerGesture_.touchEvent = PointerEvent::Create();
    ret = handler.LaunchAiScreenAbility(pid);
    EXPECT_NE(ret, RET_OK);

    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    handler.context_.twoFingerGesture_.startTime =
        std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    ret = handler.LaunchAiScreenAbility(pid);
    EXPECT_NE(ret, RET_OK);

    handler.context_.twoFingerGesture_.windowId =
        handler.context_.twoFingerGesture_.touchEvent->GetTargetWindowId();
    ret = handler.LaunchAiScreenAbility(pid);
    EXPECT_NE(ret, RET_OK);

    handler.context_.twoFingerGesture_.longPressFlag = true;
    ret = handler.LaunchAiScreenAbility(pid);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: KeyCommandHandlerTest_HandleKeyEvent_002
 * @tc.desc: Test the funcation HandleKeyEvent
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
 * @tc.desc: Test the funcation HandleKeyEvent
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
 * @tc.desc: Test the funcation HandleKeyEvent
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
 * @tc.desc: Test the funcation HandleKeyEvent
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
 * @tc.desc: Test the funcation HandleKeyEvent
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
    handler.context_.isParseConfig_ = false;
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
    ASSERT_NO_FATAL_FAILURE(handler.KnuckleGestureProcessor(touchEvent,
        knuckleGesture, KnuckleType::KNUCKLE_TYPE_DOUBLE));
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
    SessionPtr sessionPtr = std::make_shared<UDSSession>(repeatKey.ability.bundleName,
        MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
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
    EXPECT_EQ(handler.hasRegisteredSensor_, false);
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
 * @tc.name  : KeyCommandHandlerTest_CallMistouchPrevention003
 * @tc.number: CallMistouchPreventionTest_003
 * @tc.desc  : When hasRegisteredSensor_ is true, the function should return immediately.
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CallMistouchPrevention003, TestSize.Level1)
{
    auto handler = std::make_shared<KeyCommandHandler>();
    handler->hasRegisteredSensor_ = true;
    ASSERT_NO_FATAL_FAILURE(handler->CallMistouchPrevention());
}

/**
 * @tc.name  : KeyCommandHandlerTest_CallMistouchPrevention004
 * @tc.number: CallMistouchPreventionTest_004
 * @tc.desc  : When the touchless operation library fails to load,
 * the function should log the error and return.
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_CallMistouchPrevention004, TestSize.Level1)
{
    auto handler = std::make_shared<KeyCommandHandler>();
    handler->hasRegisteredSensor_ = false;
    handler->mistouchLibHandle_ = (void*)0x1;
    ASSERT_NO_FATAL_FAILURE(handler->CallMistouchPrevention());
}

/**
 * @tc.name  : UnregisterMistouchPrevention_ShouldDoNothing_WhenNotRegistered
 * @tc.number: UnregisterMistouchPreventionTest_001
 * @tc.desc  : When an unregistered sensor is tested, the UnregisterMistouchPrevention
 * function should return immediately.
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_UnregisterMistouchPrevention001, TestSize.Level1)
{
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
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_UnregisterMistouchPrevention002, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.hasRegisteredSensor_ = true;
    handler.timerId_ = 1;
    ASSERT_NO_FATAL_FAILURE(handler.UnregisterMistouchPrevention());
}
 
/**
 * @tc.name  : KeyCommandHandlerTest_UnregisterMistouchPrevention003
 * @tc.number: UnregisterMistouchPreventionTest_002
 * @tc.desc  : When an unregistered sensor is tested, the UnregisterMistouchPrevention
 * function should return immediately.
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_UnregisterMistouchPrevention003, TestSize.Level1)
{
    KeyCommandHandler handler;
    handler.hasRegisteredSensor_ = true;
    handler.timerId_ = -1;
    ASSERT_NO_FATAL_FAILURE(handler.UnregisterMistouchPrevention());
}
#endif // OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION

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
