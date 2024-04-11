/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#define private public
#include "key_command_handler.h"
#undef private
#include "event_log_helper.h"
#include "input_handler_type.h"
#include "input_event_handler.h"
#include "mmi_log.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_preferences_manager.h"
#include "system_info.h"
#include "util.h"
#include "cJSON.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "KeyCommandHandlerTest" };
constexpr int32_t NANOSECOND_TO_MILLISECOND = 1000000;
constexpr int32_t SEC_TO_NANOSEC = 1000000000;
constexpr int32_t COMMON_PARAMETER_ERROR = 401;
constexpr int32_t INTERVAL_TIME = 100;
constexpr int64_t DOUBLE_CLICK_INTERVAL_TIME_DEFAULT = 250000;
constexpr float DOUBLE_CLICK_DISTANCE_DEFAULT_CONFIG = 64.0;
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
 * @tc.name: KeyCommandHandlerTest_HandleMultiTapTest__001
 * @tc.desc: Test three fingers tap event launch ability
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_HandleMultiTapTest__001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
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
    CALL_DEBUG_ENTER;
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
#ifdef OHOS_BUILD_ENABLE_TOUCH
/**
 * @tc.name: KeyCommandHandlerTest_TouchTest_001
 * @tc.desc: Test double finger down event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_TouchTest_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
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
    CALL_DEBUG_ENTER;
    auto pointerEvent = SetupSingleKnuckleDownEvent();
    ASSERT_TRUE(pointerEvent != nullptr);
    KeyCommandHandler keyCommandHandler;
    keyCommandHandler.SetKnuckleDoubleTapIntervalTime(DOUBLE_CLICK_INTERVAL_TIME_DEFAULT);
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
    CALL_DEBUG_ENTER;
    auto pointerEvent = SetupDoubleKnuckleDownEvent();
    ASSERT_TRUE(pointerEvent != nullptr);
    int32_t actionTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    pointerEvent->SetActionTime(actionTime);
    KeyCommandHandler keyCommandHandler;
    keyCommandHandler.SetKnuckleDoubleTapIntervalTime(DOUBLE_CLICK_INTERVAL_TIME_DEFAULT);
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
    CALL_DEBUG_ENTER;
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
    ASSERT_EQ(handler.UpdateSettingsXml("businessId", 1000), COMMON_PARAMETER_ERROR);
    auto result = PreferencesMgr->SetShortKeyDuration("businessId", 100);
    ASSERT_EQ(handler.UpdateSettingsXml("businessId", 100), result);
}

/**
 * @tc.name: KeyCommandHandlerTest_AdjustTimeIntervalConfigIfNeed_001
 * @tc.desc: Adjust timeInterval configIf need verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyCommandHandlerTest, KeyCommandHandlerTest_AdjustTimeIntervalConfigIfNeed_001, TestSize.Level1)
{
    KeyCommandHandler handler;
    int64_t DOUBLE_CLICK_INTERVAL_TIME_SLOW = 450000;
    handler.downToPrevUpTimeConfig_ = DOUBLE_CLICK_INTERVAL_TIME_DEFAULT;
    handler.AdjustTimeIntervalConfigIfNeed(DOUBLE_CLICK_INTERVAL_TIME_SLOW);
    ASSERT_EQ(handler.downToPrevUpTimeConfig_, DOUBLE_CLICK_INTERVAL_TIME_SLOW);
    handler.downToPrevUpTimeConfig_ = DOUBLE_CLICK_INTERVAL_TIME_SLOW;
    handler.AdjustTimeIntervalConfigIfNeed(DOUBLE_CLICK_INTERVAL_TIME_DEFAULT);
    ASSERT_EQ(handler.downToPrevUpTimeConfig_, DOUBLE_CLICK_INTERVAL_TIME_DEFAULT);
    handler.downToPrevUpTimeConfig_ = DOUBLE_CLICK_INTERVAL_TIME_DEFAULT;
    handler.AdjustTimeIntervalConfigIfNeed(DOUBLE_CLICK_INTERVAL_TIME_DEFAULT);
    ASSERT_EQ(handler.downToPrevUpTimeConfig_, DOUBLE_CLICK_INTERVAL_TIME_DEFAULT);
    handler.downToPrevUpTimeConfig_ = DOUBLE_CLICK_INTERVAL_TIME_SLOW;
    handler.AdjustTimeIntervalConfigIfNeed(DOUBLE_CLICK_INTERVAL_TIME_SLOW);
    ASSERT_EQ(handler.downToPrevUpTimeConfig_, DOUBLE_CLICK_INTERVAL_TIME_SLOW);
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
    ASSERT_EQ(handler.downToPrevDownDistanceConfig_, handler.distanceDefaultConfig_);
    handler.AdjustDistanceConfigIfNeed(handler.distanceLongConfig_);
    ASSERT_EQ(handler.downToPrevDownDistanceConfig_, handler.distanceDefaultConfig_);
    handler.downToPrevDownDistanceConfig_ = handler.distanceLongConfig_;
    handler.AdjustDistanceConfigIfNeed(handler.distanceDefaultConfig_);
    ASSERT_EQ(handler.downToPrevDownDistanceConfig_, handler.distanceDefaultConfig_);
    handler.AdjustDistanceConfigIfNeed(handler.distanceLongConfig_);
    ASSERT_EQ(handler.downToPrevDownDistanceConfig_, handler.distanceLongConfig_);
    handler.downToPrevDownDistanceConfig_ = handler.distanceDefaultConfig_;
    handler.AdjustDistanceConfigIfNeed(handler.distanceDefaultConfig_ - 1);
    ASSERT_EQ(handler.downToPrevDownDistanceConfig_, handler.distanceLongConfig_);
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
} // namespace MMI
} // namespace OHOS