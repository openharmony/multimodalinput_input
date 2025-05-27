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

#include <gtest/gtest.h>

#include "cJSON.h"
#include "util.h"

#include "ability_manager_client.h"
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
const std::string SOS_BUNDLE_NAME { "com.hmos.emergencycommunication" };
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

} // namespace MMI
} // namespace OHOS
