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
constexpr int32_t MODULE_TYPE { 1 };
constexpr int32_t UDS_FD { -1 };
constexpr int32_t UDS_UID { 100 };
constexpr int32_t UDS_PID { 100 };
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
    ASSERT_FALSE(handler.IsEnableCombineKey(key));
    item.SetKeyCode(KeyEvent::KEYCODE_B);
    key->AddKeyItem(item);
    ASSERT_FALSE(handler.IsEnableCombineKey(key));
    key->SetKeyCode(KeyEvent::KEYCODE_L);
    ASSERT_FALSE(handler.IsEnableCombineKey(key));
}

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
    ASSERT_NO_FATAL_FAILURE(handler.InitKeyObserver());
    handler.isParseStatusConfig_ = true;
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
    item.SetPointerId(1);
    item.SetToolType(PointerEvent::TOOL_TYPE_PENCIL);
    touchEvent->AddPointerItem(item);
    touchEvent->SetPointerId(1);
    touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_MOVE);
    ASSERT_NO_FATAL_FAILURE(handler.OnHandleTouchEvent(touchEvent));
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
    std::uint32_t permissions = DEFAULT_PERMISSIONS & ~(KNUCKLE_ALL_PERMISSIONS);
    bool enable = false;
    ASSERT_NO_FATAL_FAILURE(handler.SwitchScreenCapturePermission(permissions, enable));
    EXPECT_EQ(handler.screenCapturePermission_, 0);
 
    enable = true;
    ASSERT_NO_FATAL_FAILURE(handler.SwitchScreenCapturePermission(permissions, enable));
    EXPECT_EQ(handler.screenCapturePermission_, permissions);
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
    EXPECT_EQ(handler.HasScreenCapturePermission(TOUCHPAD_KNUCKLE_SCREENSHOT), true);
    EXPECT_EQ(handler.HasScreenCapturePermission(TOUCHPAD_KNUCKLE_SCREEN_RECORDING), true);
    EXPECT_EQ(handler.HasScreenCapturePermission(SHORTCUT_KEY_SCREENSHOT), true);
    EXPECT_EQ(handler.HasScreenCapturePermission(SHORTCUT_KEY_SCREEN_RECORDING), true);
    EXPECT_EQ(handler.HasScreenCapturePermission(DEFAULT_PERMISSIONS), false);
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
} // namespace MMI
} // namespace OHOS
