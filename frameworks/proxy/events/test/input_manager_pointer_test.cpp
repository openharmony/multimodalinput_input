/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "define_multimodal.h"
#include "event_util_test.h"
#include "input_manager_util.h"
#include "pixel_map.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputManagerPointerTest"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t TIME_WAIT_FOR_OP = 100;
constexpr int32_t SIZE_TYPE_CASE = 3;
constexpr int32_t POINTER_ITEM_DISPLAY_X_ONE = 222;
constexpr int32_t POINTER_ITEM_DISPLAY_X_TWO = 444;
constexpr int32_t POINTER_ITEM_DISPLAY_X_THREE = 555;
constexpr int32_t POINTER_ITEM_DISPLAY_X_FOUR = 666;
constexpr int32_t POINTER_ITEM_DISPLAY_X_FIVE = 923;
constexpr int32_t POINTER_ITEM_DISPLAY_Y_ONE = 223;
constexpr int32_t POINTER_ITEM_DISPLAY_Y_TWO = 333;
constexpr int32_t POINTER_ITEM_DISPLAY_Y_THREE = 555;
constexpr int32_t POINTER_ITEM_DISPLAY_Y_FOUR = 777;
constexpr int32_t POINTER_ITEM_DISPLAY_Y_FIVE = 793;
constexpr int32_t MOVE_MOUSE_OFFSET_ONE = -2000;
constexpr int32_t MOVE_MOUSE_OFFSET_TWO = 50;
constexpr int32_t MOVE_MOUSE_OFFSET_THREE = 100;
constexpr int32_t MOVE_MOUSE_OFFSET_FOUR = 150;
constexpr int32_t MOVE_MOUSE_OFFSET_FIVE = 300;
constexpr int32_t MOVE_MOUSE_OFFSET_SIX = 350;
constexpr int32_t MOVE_MOUSE_OFFSET_SEVEN = 400;
constexpr int32_t MOVE_MOUSE_OFFSET_EIGHT = 450;
constexpr int32_t MOVE_MOUSE_OFFSET_NINE = 500;
constexpr int32_t MOVE_MOUSE_OFFSET_TEN = 550;
constexpr int32_t MOVE_MOUSE_OFFSET_ELEVEN = 700;
constexpr int32_t MOVE_MOUSE_OFFSET_TWELVE = 1000;
constexpr int32_t MOVE_MOUSE_OFFSET_THIRTEEN = -1000;
constexpr int32_t POINTER_SPEED_ONE = 4;
constexpr int32_t POINTER_SPEED_TWO = 5;
constexpr int32_t POINTER_SPEED_THREE = 9;
constexpr int32_t POINTER_SPEED_FOUR = 11;
constexpr int32_t POINTER_SPEED_FIVE = 20;
constexpr int32_t RIGHT_CLICK_TYPE = 2;
constexpr int32_t INVAID_VALUE = -1;
constexpr int32_t MOUSE_ICON_HOT_SPOT = 20;
constexpr int64_t POINTER_ITEM_DOWNTIME_ONE = 9999;
constexpr int64_t POINTER_ITEM_DOWNTIME_TWO = 10001;
constexpr int64_t POINTER_ITEM_DOWNTIME_THREE = 10003;
constexpr int64_t POINTER_ITEM_DOWNTIME_FOUR = 10009;
constexpr int64_t POINTER_ITEM_DOWNTIME_FIVE = 10010;

HapInfoParams infoManagerTestInfoParms = {
    .userID = 1,
    .bundleName = "InputManagerPointerTest",
    .instIndex = 0,
    .appIDDesc = "test",
    .isSystemApp = true
};

PermissionDef infoManagerTestPermDef = {
    .permissionName = "ohos.permission.test",
    .bundleName = "InputManagerPointerTest",
    .grantMode = 1,
    .availableLevel = APL_SYSTEM_CORE,
    .label = "label",
    .labelId = 1,
    .description = "test pointer event",
    .descriptionId = 1,
};

PermissionStateFull infoManagerTestState = {
    .permissionName = "ohos.permission.test",
    .isGeneral = true,
    .resDeviceID = { "local" },
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .grantFlags = { 1 },
};

HapPolicyParams infoManagerTestPolicyPrams = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test.domain",
    .permList = { infoManagerTestPermDef },
    .permStateList = { infoManagerTestState }
};
} // namespace

class AccessToken {
public:
    AccessToken()
    {
        currentID_ = GetSelfTokenID();
        AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(infoManagerTestInfoParms, infoManagerTestPolicyPrams);
        accessID_ = tokenIdEx.tokenIDEx;
        SetSelfTokenID(accessID_);
    }
    ~AccessToken()
    {
        AccessTokenKit::DeleteToken(accessID_);
        SetSelfTokenID(currentID_);
    }
private:
    uint64_t currentID_ = 0;
    uint64_t accessID_ = 0;
};

class InputManagerPointerTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void TearDownTestCase();
    std::string GetEventDump();

private:
    int32_t prePointerSpeed_ { 5 };
    int32_t prePrimaryButton_ { 0 };
    int32_t preScrollRows_ { 3 };
    int32_t preTouchpadPointerSpeed_ { 9 };
    int32_t preRightClickType_ { 1 };
    int32_t prePointerSize_ { 1 };
    int32_t prePointerColor_ { -1 };
    bool preHoverScrollState_ { true };
    bool preScrollSwitch_ { true };
    bool preScrollDirection_ { true };
    bool preTapSwitch_ { true };
    bool prePinchSwitch_ { true };
    bool preSwipeSwitch_ { true };
    bool preRotateSwitch_ { true };
};

void InputManagerPointerTest::SetUpTestCase()
{
    ASSERT_TRUE(TestUtil->Init());
}

void InputManagerPointerTest::TearDownTestCase(void)
{
}

void InputManagerPointerTest::SetUp()
{
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_FOCUS);
    InputManager::GetInstance()->GetPointerSpeed(prePointerSpeed_);
    InputManager::GetInstance()->GetMousePrimaryButton(prePrimaryButton_);
    InputManager::GetInstance()->GetHoverScrollState(preHoverScrollState_);
    InputManager::GetInstance()->GetMouseScrollRows(preScrollRows_);
    InputManager::GetInstance()->GetTouchpadScrollSwitch(preScrollSwitch_);
    InputManager::GetInstance()->GetTouchpadScrollDirection(preScrollDirection_);
    InputManager::GetInstance()->GetTouchpadTapSwitch(preTapSwitch_);
    InputManager::GetInstance()->GetTouchpadPointerSpeed(preTouchpadPointerSpeed_);
    InputManager::GetInstance()->GetTouchpadPinchSwitch(prePinchSwitch_);
    InputManager::GetInstance()->GetTouchpadSwipeSwitch(preSwipeSwitch_);
    InputManager::GetInstance()->GetTouchpadRightClickType(preRightClickType_);
    InputManager::GetInstance()->GetTouchpadRotateSwitch(preRotateSwitch_);
    InputManager::GetInstance()->GetPointerSize(prePointerSize_);
    InputManager::GetInstance()->GetPointerColor(prePointerColor_);
    InputManager::GetInstance()->GetTouchpadThreeFingersTapSwitch(threeFingerSwitch_);
}

void InputManagerPointerTest::TearDown()
{
    TestUtil->AddEventDump("");
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->SetPointerSpeed(prePointerSpeed_);
    InputManager::GetInstance()->SetMousePrimaryButton(prePrimaryButton_);
    InputManager::GetInstance()->SetHoverScrollState(preHoverScrollState_);
    InputManager::GetInstance()->SetMouseScrollRows(preScrollRows_);
    InputManager::GetInstance()->SetTouchpadScrollSwitch(preScrollSwitch_);
    InputManager::GetInstance()->SetTouchpadScrollDirection(preScrollDirection_);
    InputManager::GetInstance()->SetTouchpadTapSwitch(preTapSwitch_);
    InputManager::GetInstance()->SetTouchpadPointerSpeed(preTouchpadPointerSpeed_);
    InputManager::GetInstance()->SetTouchpadPinchSwitch(prePinchSwitch_);
    InputManager::GetInstance()->SetTouchpadSwipeSwitch(preSwipeSwitch_);
    InputManager::GetInstance()->SetTouchpadRotateSwitch(preRotateSwitch_);
    InputManager::GetInstance()->SetTouchpadRightClickType(preRightClickType_);
    InputManager::GetInstance()->SetPointerSize(prePointerSize_);
    InputManager::GetInstance()->SetPointerColor(prePointerColor_);
    InputManager::GetInstance()->SetTouchpadThreeFingersTapSwitch(threeFingerSwitch_);
}

std::string InputManagerPointerTest::GetEventDump()
{
    return TestUtil->GetEventDump();
}

/**
 * @tc.name: InputManagerPointerTest_MouseEventEnterAndLeave_001
 * @tc.desc: Verify that the mouse moves away from the window
 * @tc.type: FUNC
 * @tc.require: I5HMF3 I5HMEF
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_MouseEventEnterAndLeave_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent{InputManagerUtil::SetupPointerEvent014()};
    ASSERT_NE(pointerEvent, nullptr);
#ifdef OHOS_BUILD_ENABLE_POINTER
    AccessToken accessToken;
    SimulateInputEventUtilTest(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER
}

/**
 * @tc.name: InputManagerPointerTest_MouseEventEnterAndLeave_002
 * @tc.desc: Verify return mouse away from the window
 * @tc.type: FUNC
 * @tc.require: I5HMF3 I5HMEF
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_MouseEventEnterAndLeave_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent{InputManagerUtil::SetupKeyEvent002()};
    ASSERT_NE(keyEvent, nullptr);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    AccessToken accessToken;
    SimulateInputEventUtilTest(keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

/**
 * @tc.name: InputManagerPointerTest_MouseEventEnterAndLeave_003
 * @tc.desc: Verify that the home button and mouse leave the window
 * @tc.type: FUNC
 * @tc.require: I5HMF3 I5HMEF
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_MouseEventEnterAndLeave_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent{InputManagerUtil::SetupKeyEvent003()};
    ASSERT_NE(keyEvent, nullptr);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    AccessToken accessToken;
    SimulateInputEventUtilTest(keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

/**
 * @tc.name: InputManagerPointerTest_MouseEventEnterAndLeave_004
 * @tc.desc: Verify that the mouse moves to the navigation bar to leave the window
 * @tc.type: FUNC
 * @tc.require: I5HMF3 I5HMEF
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_MouseEventEnterAndLeave_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent{InputManagerUtil::SetupPointerEvent015()};
    ASSERT_NE(pointerEvent, nullptr);
#ifdef OHOS_BUILD_ENABLE_POINTER
    AccessToken accessToken;
    SimulateInputEventUtilTest(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER
}

/**
 * @tc.name: InputManagerPointerTest_AddMonitor_001
 * @tc.desc: Verify pointerevent monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_AddMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEventFun = [](std::shared_ptr<PointerEvent> event) { MMI_HILOGD("Add monitor success"); };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(pointerEventFun);
#if (defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)) && defined(OHOS_BUILD_ENABLE_MONITOR)
    ASSERT_NE(monitorId, INVALID_HANDLER_ID);
#else
    ASSERT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR ||  OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerPointerTest_AddMonitor_002
 * @tc.desc: Verify keyevent monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_AddMonitor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEventFun = [](std::shared_ptr<KeyEvent> event) { MMI_HILOGD("Add monitor success"); };
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(keyEventFun);
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_MONITOR)
    ASSERT_NE(monitorId, INVALID_HANDLER_ID);
#else
    ASSERT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_KEYBOARD || OHOS_BUILD_ENABLE_MONITOR
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerPointerTest_OnAddScreenMonitor_001
 * @tc.desc: Verify touchscreen down event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_OnAddScreenMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = InputManagerUtil::SetupPointerEvent001();
    ASSERT_NE(pointerEvent, nullptr);

    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = InputManagerUtil::TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManagerUtil::TestMonitor(monitorId, pointerEvent);
    InputManagerUtil::TestRemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerPointerTest_OnAddScreenMonitor_002
 * @tc.desc: Verify touchscreen move event multiple monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_OnAddScreenMonitor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_MONITOR);
    const std::vector<int32_t>::size_type N_TEST_CASES{SIZE_TYPE_CASE};
    std::vector<int32_t> ids(N_TEST_CASES);
    std::vector<std::shared_ptr<InputEventCallback>> cbs(N_TEST_CASES);

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; i++) {
        cbs[i] = GetPtr<InputEventCallback>();
        ASSERT_TRUE(cbs[i] != nullptr);
        ids[i] = InputManagerUtil::TestAddMonitor(cbs[i]);
#ifdef OHOS_BUILD_ENABLE_MONITOR
        EXPECT_TRUE(IsValidHandlerId(ids[i]));
#else
        EXPECT_EQ(ids[i], ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    auto pointerEvent = InputManagerUtil::SetupPointerEvent002();
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    for (const auto &id : ids) {
        std::string sPointerEs = GetEventDump();
        MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
        ASSERT_TRUE(!sPointerEs.empty());
#else
        ASSERT_TRUE(sPointerEs.empty());
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
        if (IsValidHandlerId(id)) {
            InputManagerUtil::TestRemoveMonitor(id);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; i++) {
        InputManagerUtil::TestRemoveMonitor(ids[i]);
    }
}

/**
 * @tc.name: InputManagerPointerTest_OnAddScreenMonitor_003
 * @tc.desc: Verify touchscreen up event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_OnAddScreenMonitor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = InputManagerUtil::SetupPointerEvent003();
    ASSERT_NE(pointerEvent, nullptr);

    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = InputManagerUtil::TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    TestSimulateInputEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR

    if (IsValidHandlerId(monitorId)) {
        InputManagerUtil::TestRemoveMonitor(monitorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
    InputManagerUtil::TestRemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerPointerTest_OnAddTouchPadMonitor_001
 * @tc.desc: Verify touchpad down event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_OnAddTouchPadMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetDownTime(POINTER_ITEM_DOWNTIME_THREE);
    item.SetPressed(true);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_ONE);
    item.SetDeviceId(1);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_TWO);
    item.SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = InputManagerUtil::TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManagerUtil::TestMonitor(monitorId, pointerEvent);
    InputManagerUtil::TestRemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerPointerTest_OnAddTouchPadMonitor_002
 * @tc.desc: Verify touchpad move event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_OnAddTouchPadMonitor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(POINTER_ITEM_DOWNTIME_TWO);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_TWO);
    item.SetPressed(true);
    item.SetDeviceId(1);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_THREE);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = InputManagerUtil::TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManagerUtil::TestMonitor(monitorId, pointerEvent);
    InputManagerUtil::TestRemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerPointerTest_OnAddTouchPadMonitor_003
 * @tc.desc: Verify touchpad up event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_OnAddTouchPadMonitor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetDownTime(POINTER_ITEM_DOWNTIME_ONE);
    item.SetPointerId(0);
    item.SetPressed(true);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_FOUR);
    item.SetDeviceId(1);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_FOUR);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = InputManagerUtil::TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManagerUtil::TestMonitor(monitorId, pointerEvent);
    InputManagerUtil::TestRemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerPointerTest_OnAddTouchPadMonitor_004
 * @tc.desc: Verify touchpad multiple monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_OnAddTouchPadMonitor_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_MONITOR);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetDownTime(POINTER_ITEM_DOWNTIME_FOUR);
    item.SetDeviceId(1);
    item.SetPointerId(0);
    item.SetPressed(true);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_THREE);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_FIVE);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    const std::vector<int32_t>::size_type N_TEST_CASES{SIZE_TYPE_CASE};
    std::vector<int32_t> ids(N_TEST_CASES);
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        ids[i] = InputManagerUtil::TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
        EXPECT_TRUE(IsValidHandlerId(ids[i]));
#else
        EXPECT_EQ(ids[i], ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    for (const auto &id : ids) {
        std::string sPointerEs = GetEventDump();
        MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_MONITOR)
        ASSERT_TRUE(!sPointerEs.empty());
#else
        ASSERT_TRUE(sPointerEs.empty());
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_MONITOR
        if (IsValidHandlerId(id)) {
            InputManagerUtil::TestRemoveMonitor(id);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        InputManagerUtil::TestRemoveMonitor(ids[i]);
    }
}

/**
 * @tc.name: InputManagerPointerTest_OnAddTouchPadMonitor_005
 * @tc.desc: Verify touchpad monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_OnAddTouchPadMonitor_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetDownTime(POINTER_ITEM_DOWNTIME_FIVE);
    item.SetPointerId(0);
    item.SetDeviceId(1);
    item.SetPressed(true);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_FIVE);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_ONE);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = InputManagerUtil::TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManagerUtil::TestMonitor(monitorId, pointerEvent);
    InputManagerUtil::TestRemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerPointerTest_AddMouseMonitor_001
 * @tc.desc: Verify mouse down event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_AddMouseMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_NE(callbackPtr, nullptr);
    int32_t monitorId = InputManagerUtil::TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    auto pointerEvent = InputManagerUtil::SetupPointerEvent005();
    InputManagerUtil::TestMonitor(monitorId, pointerEvent);
    InputManagerUtil::TestRemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerPointerTest_AddMouseMonitor_003
 * @tc.desc: Verify mouse up event monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_AddMouseMonitor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    int32_t monitorId = InputManagerUtil::TestAddMonitor(callbackPtr);
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(IsValidHandlerId(monitorId));
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    auto pointerEvent = InputManagerUtil::SetupPointerEvent007();
    ASSERT_TRUE(pointerEvent != nullptr);
    InputManagerUtil::TestMonitor(monitorId, pointerEvent);
    InputManagerUtil::TestRemoveMonitor(monitorId);
}

/**
 * @tc.name: InputManagerPointerTest_AddMouseMonitor_004
 * @tc.desc: Verify monitor upper limit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_AddMouseMonitor_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_MONITOR);
    const std::vector<int32_t>::size_type N_TEST_CASES{MAX_N_INPUT_HANDLERS - 1};
    std::vector<int32_t> ids;
    int32_t maxMonitor = 0;

    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        auto callbackPtr = GetPtr<InputEventCallback>();
        ASSERT_TRUE(callbackPtr != nullptr);
        maxMonitor = InputManagerUtil::TestAddMonitor(callbackPtr);
        if (IsValidHandlerId(maxMonitor)) {
            ids.push_back(maxMonitor);
            std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        }
    }

    auto pointerEvent = InputManagerUtil::SetupPointerEvent007();
    pointerEvent->AddFlag(PointerEvent::EVENT_FLAG_NO_INTERCEPT);
    ASSERT_TRUE(pointerEvent != nullptr);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    maxMonitor = 0;
    for (const auto &id : ids) {
        if (!GetEventDump().empty()) {
            maxMonitor++;
        }
        if (IsValidHandlerId(id)) {
            InputManagerUtil::TestRemoveMonitor(id);
            std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        }
    }
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_MONITOR)
    ASSERT_EQ(maxMonitor, ids.size());
#else
    ASSERT_EQ(maxMonitor, 0);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_MONITOR
}

/**
 * @tc.name: InputManagerPointerTest_OnAddKeyboardMonitor_001
 * @tc.desc: Verify Keyboard multiple monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_OnAddKeyboardMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_MONITOR);
    const std::vector<int32_t>::size_type N_TEST_CASES{SIZE_TYPE_CASE};
    std::vector<int32_t> ids;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        int32_t id = InputManagerUtil::TestAddMonitor(callbackPtr);
        if (IsValidHandlerId(id)) {
            ids.push_back(id);
            std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        }
    }

    auto injectEvent = InputManagerUtil::SetupKeyEvent001();
    ASSERT_TRUE(injectEvent != nullptr);
    InputManager::GetInstance()->SimulateInputEvent(injectEvent);

    for (const auto &id : ids) {
        std::string sPointerEs = GetEventDump();
        MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_MONITOR)
        ASSERT_TRUE(!sPointerEs.empty());
#else
        ASSERT_TRUE(sPointerEs.empty());
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_MONITOR
        if (IsValidHandlerId(id)) {
            InputManagerUtil::TestRemoveMonitor(id);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManagerPointerTest_OnAddKeyboardMonitor_002
 * @tc.desc: Verify Keyboard multiple monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_OnAddKeyboardMonitor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const std::vector<int32_t>::size_type N_TEST_CASES{SIZE_TYPE_CASE};
    std::vector<int32_t> ids;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_TRUE(callbackPtr != nullptr);
    for (std::vector<int32_t>::size_type i = 0; i < N_TEST_CASES; ++i) {
        int32_t id = InputManagerUtil::TestAddMonitor(callbackPtr);
        if (IsValidHandlerId(id)) {
            ids.push_back(id);
            std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        }
    }

    auto injectEvent = InputManagerUtil::SetupKeyEvent001();
    ASSERT_TRUE(injectEvent != nullptr);
    injectEvent->SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    InputManager::GetInstance()->SimulateInputEvent(injectEvent);

    for (const auto &id : ids) {
        std::string sPointerEs = GetEventDump();
        MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
        ASSERT_TRUE(sPointerEs.empty());
        if (IsValidHandlerId(id)) {
            InputManagerUtil::TestRemoveMonitor(id);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: InputManagerPointerTest_SetWindowInputEventConsumer_001
 * @tc.desc: Verify pointerEvent report eventHandler
 * @tc.type: FUNC
 * @tc.require: I5HMDY
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetWindowInputEventConsumer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto runner = AppExecFwk::EventRunner::Create("cooperateHdrTest");
    ASSERT_TRUE(runner != nullptr);
    auto eventHandler = std::make_shared<AppExecFwk::EventHandler>(runner);
    ASSERT_TRUE(eventHandler != nullptr);
    uint64_t runnerThreadId = 0;

    auto fun = [&runnerThreadId]() {
        runnerThreadId = GetThisThreadId();
        MMI_HILOGD("Create eventHandler is threadId:%{public}" PRIu64, runnerThreadId);
        ASSERT_TRUE(runnerThreadId != 0);
    };
    eventHandler->PostSyncTask(fun, AppExecFwk::EventHandler::Priority::IMMEDIATE);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    auto consumer = GetPtr<WindowEventConsumer>();
    ASSERT_TRUE(consumer != nullptr);
    MMI::InputManager::GetInstance()->SetWindowInputEventConsumer(consumer, eventHandler);
    auto pointerEvent = InputManagerUtil::SetupPointerEvent005();
    pointerEvent->AddFlag(PointerEvent::EVENT_FLAG_NO_INTERCEPT);
    ASSERT_TRUE(pointerEvent != nullptr);
    AccessToken accessToken;
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    uint64_t consumerThreadId = consumer->GetConsumerThreadId();
#ifdef OHOS_BUILD_ENABLE_POINTER
    EXPECT_EQ(runnerThreadId, consumerThreadId);
#else
    ASSERT_TRUE(runnerThreadId != consumerThreadId);
#endif // OHOS_BUILD_ENABLE_POINTER
}

/**
 * @tc.name: InputManagerPointerTest_SetWindowInputEventConsumer_002
 * @tc.desc: Verify keyEvent report eventHandler
 * @tc.type: FUNC
 * @tc.require: I5HMDY
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetWindowInputEventConsumer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const std::string threadTest = "threadNameTest";
    auto runner = AppExecFwk::EventRunner::Create(threadTest);
    ASSERT_TRUE(runner != nullptr);
    auto eventHandler = std::make_shared<AppExecFwk::EventHandler>(runner);
    ASSERT_TRUE(eventHandler != nullptr);
    uint64_t runnerThreadId = 0;

    auto fun = [&runnerThreadId]() {
        runnerThreadId = GetThisThreadId();
        MMI_HILOGD("Create eventHandler is threadId:%{public}" PRIu64, runnerThreadId);
        ASSERT_TRUE(runnerThreadId != 0);
    };
    eventHandler->PostSyncTask(fun, AppExecFwk::EventHandler::Priority::IMMEDIATE);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    auto consumer = GetPtr<WindowEventConsumer>();
    ASSERT_TRUE(consumer != nullptr);
    MMI::InputManager::GetInstance()->SetWindowInputEventConsumer(consumer, eventHandler);
    auto keyEvent = InputManagerUtil::SetupKeyEvent001();
    ASSERT_TRUE(keyEvent != nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    AccessToken accessToken;
    InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    uint64_t consumerThreadId = consumer->GetConsumerThreadId();
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    EXPECT_EQ(runnerThreadId, consumerThreadId);
#else
    ASSERT_TRUE(runnerThreadId != consumerThreadId);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

/**
 * @tc.name: InputManagerPointerTest_MoveMouse_01
 * @tc.desc: Verify move mouse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_MoveMouse_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_TWO, MOVE_MOUSE_OFFSET_TWO));
}

/**
 * @tc.name: InputManagerPointerTest_MoveMouse_02
 * @tc.desc: Verify move mouse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_MoveMouse_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(
        InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_THIRTEEN, MOVE_MOUSE_OFFSET_THREE));
}

/**
 * @tc.name: InputManagerPointerTest_MouseHotArea_001
 * @tc.desc: Mouse event Search window by pointerHotAreas
 * @tc.type: FUNC
 * @tc.require: I5HMCB
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_MouseHotArea_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent{InputManagerUtil::SetupMouseEvent001()};
    ASSERT_TRUE(pointerEvent != nullptr);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    ASSERT_EQ(pointerEvent->GetSourceType(), PointerEvent::SOURCE_TYPE_MOUSE);
}

/**
 * @tc.name: InputManagerPointerTest_MouseHotArea_002
 * @tc.desc: Mouse event Search window by pointerHotAreas
 * @tc.type: FUNC
 * @tc.require: I5HMCB
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_MouseHotArea_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent{InputManagerUtil::SetupMouseEvent002()};
    ASSERT_TRUE(pointerEvent != nullptr);
    ASSERT_EQ(pointerEvent->GetSourceType(), PointerEvent::SOURCE_TYPE_MOUSE);
}

/**
 * @tc.name: InputManagerPointerTest_SetPointerLocation_001
 * @tc.desc: Sets the absolute coordinate of mouse.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetPointerLocation_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t x = 0;
    int32_t y = 0;
    ASSERT_NO_FATAL_FAILURE(InputManager::GetInstance()->SetPointerLocation(x, y));
}

/**
 * @tc.name: InputManagerPointerTest_SetPointerLocation_002
 * @tc.desc: Sets the absolute coordinate of mouse.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetPointerLocation_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t x = 300;
    int32_t y = 300;
    ASSERT_TRUE(InputManager::GetInstance()->SetPointerLocation(x, y) == RET_OK);
}

/**
 * @tc.name: InputManagerPointerTest_SetPointerVisible_001
 * @tc.desc: Sets whether the pointer icon is visible
 * @tc.type: FUNC
 * @tc.require: I530VT
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetPointerVisible_001, TestSize.Level1)
{
    bool isVisible{true};
    if (InputManager::GetInstance()->SetPointerVisible(isVisible) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->IsPointerVisible() == isVisible);
    }
}

/**
 * @tc.name: InputManagerPointerTest_SetPointerVisible_002
 * @tc.desc: Sets whether the pointer icon is visible
 * @tc.type: FUNC
 * @tc.require: I530VT
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetPointerVisible_002, TestSize.Level1)
{
    bool isVisible{false};
    if (InputManager::GetInstance()->SetPointerVisible(isVisible) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->IsPointerVisible() == isVisible);
    }
}

/**
 * @tc.name: InputManagerPointerTest_SetPointSpeed_001
 * @tc.desc: Abnormal speed value processing
 * @tc.type: FUNC
 * @tc.require: I530XP I530UX
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetPointSpeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const int32_t speed = INVAID_VALUE;
    InputManager::GetInstance()->SetPointerSpeed(speed);
    int32_t speed1;
    InputManager::GetInstance()->GetPointerSpeed(speed1);
    ASSERT_EQ(speed1, 1);
    InputManager::GetInstance()->MoveMouse(-MOVE_MOUSE_OFFSET_ONE, MOVE_MOUSE_OFFSET_ONE);
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_TWO, MOVE_MOUSE_OFFSET_TWO);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_THREE, MOVE_MOUSE_OFFSET_FOUR);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_FIVE, MOVE_MOUSE_OFFSET_SIX);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_SEVEN, MOVE_MOUSE_OFFSET_EIGHT);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_NINE, MOVE_MOUSE_OFFSET_TEN);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_ELEVEN, MOVE_MOUSE_OFFSET_TWELVE);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name: InputManagerPointerTest_SetPointSpeed_002
 * @tc.desc: Normal speed value processing
 * @tc.type: FUNC
 * @tc.require: I530XP I530UX
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetPointSpeed_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const int32_t speed = 1;
    InputManager::GetInstance()->SetPointerSpeed(speed);
    int32_t speed1;
    InputManager::GetInstance()->GetPointerSpeed(speed1);
    ASSERT_EQ(speed1, speed);
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_ONE, MOVE_MOUSE_OFFSET_ONE);
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_TWO, MOVE_MOUSE_OFFSET_TWO);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_THREE, MOVE_MOUSE_OFFSET_FOUR);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_FIVE, MOVE_MOUSE_OFFSET_SIX);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_SEVEN, MOVE_MOUSE_OFFSET_EIGHT);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_NINE, MOVE_MOUSE_OFFSET_TEN);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_ELEVEN, MOVE_MOUSE_OFFSET_TWELVE);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name: InputManagerPointerTest_SetPointSpeed_003
 * @tc.desc: Normal speed value processing
 * @tc.type: FUNC
 * @tc.require: I530XP I530UX
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetPointSpeed_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const int32_t speed = POINTER_SPEED_ONE;
    InputManager::GetInstance()->SetPointerSpeed(speed);
    int32_t speed1;
    InputManager::GetInstance()->GetPointerSpeed(speed1);
    ASSERT_EQ(speed1, speed);
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_ONE, MOVE_MOUSE_OFFSET_ONE);
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_TWO, MOVE_MOUSE_OFFSET_TWO);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_THREE, MOVE_MOUSE_OFFSET_FOUR);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_FIVE, MOVE_MOUSE_OFFSET_SIX);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_SEVEN, MOVE_MOUSE_OFFSET_EIGHT);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_NINE, MOVE_MOUSE_OFFSET_TEN);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_ELEVEN, MOVE_MOUSE_OFFSET_TWELVE);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name: InputManagerPointerTest_SetPointSpeed_004
 * @tc.desc: Normal speed value processing
 * @tc.type: FUNC
 * @tc.require: I530XP I530UX
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetPointSpeed_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const int32_t speed = POINTER_SPEED_FOUR;
    InputManager::GetInstance()->SetPointerSpeed(speed);
    int32_t speed1;
    InputManager::GetInstance()->GetPointerSpeed(speed1);
    ASSERT_EQ(speed1, speed);
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_ONE, MOVE_MOUSE_OFFSET_ONE);
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_TWO, MOVE_MOUSE_OFFSET_TWO);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_THREE, MOVE_MOUSE_OFFSET_FOUR);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_FIVE, MOVE_MOUSE_OFFSET_SIX);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_SEVEN, MOVE_MOUSE_OFFSET_EIGHT);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_NINE, MOVE_MOUSE_OFFSET_TEN);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_ELEVEN, MOVE_MOUSE_OFFSET_TWELVE);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name: InputManagerPointerTest_SetPointSpeed_005
 * @tc.desc: Abnormal speed value processing
 * @tc.type: FUNC
 * @tc.require: I530XP I530UX
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetPointSpeed_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const int32_t speed = POINTER_SPEED_FIVE;
    InputManager::GetInstance()->SetPointerSpeed(speed);
    int32_t speed1;
    InputManager::GetInstance()->GetPointerSpeed(speed1);
    ASSERT_EQ(speed1, POINTER_SPEED_FOUR);
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_ONE, MOVE_MOUSE_OFFSET_ONE);
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_TWO, MOVE_MOUSE_OFFSET_TWO);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_THREE, MOVE_MOUSE_OFFSET_FOUR);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_FIVE, MOVE_MOUSE_OFFSET_SIX);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_SEVEN, MOVE_MOUSE_OFFSET_EIGHT);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_NINE, MOVE_MOUSE_OFFSET_TEN);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->MoveMouse(MOVE_MOUSE_OFFSET_ELEVEN, MOVE_MOUSE_OFFSET_TWELVE);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

/**
 * @tc.name: InputManagerPointerTest_SetHoverScrollState_001
 * @tc.desc: Sets mouse hover scroll state in inactive window
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetHoverScrollState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_TRUE(InputManager::GetInstance()->SetHoverScrollState(false) == RET_OK);
    InputManager::GetInstance()->SetHoverScrollState(true);
}

/**
 * @tc.name: InputManagerPointerTest_SetHoverScrollState_002
 * @tc.desc: Sets mouse hover scroll state in inactive window
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetHoverScrollState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_TRUE(InputManager::GetInstance()->SetHoverScrollState(true) == RET_OK);
}

/**
 * @tc.name: InputManagerPointerTest_GetHoverScrollState_001
 * @tc.desc: Gets mouse hover scroll state in inactive window
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_GetHoverScrollState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool state = true;
    if (InputManager::GetInstance()->SetHoverScrollState(state) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetHoverScrollState(state) == RET_OK);
        ASSERT_TRUE(state);
    }
}

/**
 * @tc.name: InputManagerPointerTest_SetMousePrimaryButton_001
 * @tc.desc: Sets mouse primary button
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetMousePrimaryButton_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t primaryButton = 1;
    ASSERT_TRUE(InputManager::GetInstance()->SetMousePrimaryButton(primaryButton) == RET_OK);
    primaryButton = 0;
    ASSERT_TRUE(InputManager::GetInstance()->SetMousePrimaryButton(primaryButton) == RET_OK);
}

/**
 * @tc.name: InputManagerPointerTest_SetMousePrimaryButton_002
 * @tc.desc: Sets mouse primary button
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetMousePrimaryButton_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t primaryButton = INVAID_VALUE;
    ASSERT_TRUE(InputManager::GetInstance()->SetMousePrimaryButton(primaryButton) == RET_ERR);
}

/**
 * @tc.name: InputManagerPointerTest_GetMousePrimaryButton_001
 * @tc.desc: Gets mouse primary button
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_GetMousePrimaryButton_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t primaryButton = 1;
    if (InputManager::GetInstance()->SetMousePrimaryButton(primaryButton) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetMousePrimaryButton(primaryButton) == RET_OK);
        ASSERT_EQ(primaryButton, PrimaryButton::RIGHT_BUTTON);
    }
}

/**
 * @tc.name: InputManagerPointerTest_SetMouseScrollRows_001
 * @tc.desc: Sets mouse scroll rows
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetMouseScrollRows_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t rows = 1;
    ASSERT_TRUE(InputManager::GetInstance()->SetMouseScrollRows(rows) == RET_OK);
}

/**
 * @tc.name: InputManagerPointerTest_GetMouseScrollRows_001
 * @tc.desc: Sets mouse scroll rows
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_GetMouseScrollRows_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t rows = 50;
    int32_t newRows = 3;
    if (InputManager::GetInstance()->SetMouseScrollRows(rows) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetMouseScrollRows(newRows) == RET_OK);
        ASSERT_EQ(rows, newRows);
    }
}

/**
 * @tc.name: InputManagerPointerTest_SetMouseIcon_001
 * @tc.desc: Set the mouse icon for linux window
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetMouseIcon_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto window = WindowUtilsTest::GetInstance()->GetWindow();
    CHKPV(window);
    uint32_t windowId = window->GetWindowId();
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    PointerStyle pointerStyle;
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = InputManagerUtil::SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    pointerStyle.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    if (InputManager::GetInstance()->SetMouseIcon(windowId, (void *)pixelMap.get()) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle) == RET_OK);
        ASSERT_EQ(pointerStyle.id, MOUSE_ICON::DEVELOPER_DEFINED_ICON);
    } else if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        ASSERT_FALSE(false);  // errors occur
    } else {
        ASSERT_TRUE(false);
    }
}

/**
 * @tc.name: InputManagerPointerTest_SetMouseIcon_002
 * @tc.desc: Set the mouse icon for linux window
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetMouseIcon_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto window = WindowUtilsTest::GetInstance()->GetWindow();
    CHKPV(window);
    uint32_t windowId = window->GetWindowId();
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/Zoom_Out.svg";
    PointerStyle pointerStyle;
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = InputManagerUtil::SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    pointerStyle.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    if (InputManager::GetInstance()->SetMouseIcon(windowId, (void *)pixelMap.get()) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle) == RET_OK);
        ASSERT_EQ(pointerStyle.id, MOUSE_ICON::DEVELOPER_DEFINED_ICON);
    } else if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        ASSERT_FALSE(false);  // errors occur
    } else {
        ASSERT_TRUE(false);
    }
}

/**
 * @tc.name: InputManagerPointerTest_SetMouseIcon_003
 * @tc.desc: Set the mouse icon for linux window
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetMouseIcon_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto window = WindowUtilsTest::GetInstance()->GetWindow();
    CHKPV(window);
    uint32_t windowId = window->GetWindowId();
    PointerStyle pointerStyle;
    pointerStyle.id = MOUSE_ICON::DEFAULT;
    int32_t ret = InputManager::GetInstance()->SetPointerStyle(windowId, pointerStyle);
    ASSERT_TRUE(ret == RET_OK);
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/Zoom_Out.svg";
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = InputManagerUtil::SetMouseIconTest(iconPath);
    ASSERT_TRUE(pixelMap != nullptr);
    pointerStyle.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    ret = InputManager::GetInstance()->SetMouseIcon(INVAID_VALUE, (void *)pixelMap.get());
    ASSERT_EQ(ret, RET_ERR);
    ASSERT_TRUE(InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle) == RET_OK);
    ASSERT_EQ(pointerStyle.id, MOUSE_ICON::DEFAULT);
}

/**
 * @tc.name: InputManagerPointerTest_SetMouseHotSpot_001
 * @tc.desc: Set the mouse icon hot spot for linux window
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetMouseHotSpot_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto window = WindowUtilsTest::GetInstance()->GetWindow();
    CHKPV(window);
    uint32_t windowId = window->GetWindowId();
    PointerStyle pointerStyle;
    pointerStyle.id = MOUSE_ICON::CROSS;
    if (InputManager::GetInstance()->SetPointerStyle(windowId, pointerStyle) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle) == RET_OK);
        ASSERT_EQ(pointerStyle.id, MOUSE_ICON::CROSS);
    }
    ASSERT_FALSE(
        InputManager::GetInstance()->SetMouseHotSpot(windowId, MOUSE_ICON_HOT_SPOT, MOUSE_ICON_HOT_SPOT) == RET_OK);
}

/**
 * @tc.name: InputManagerPointerTest_SetMouseHotSpot_002
 * @tc.desc: Set the mouse icon hot spot for linux window
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetMouseHotSpot_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto window = WindowUtilsTest::GetInstance()->GetWindow();
    CHKPV(window);
    uint32_t windowId = window->GetWindowId();
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/Default.svg";
    PointerStyle pointerStyle;
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = InputManagerUtil::SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    pointerStyle.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    if (InputManager::GetInstance()->SetMouseIcon(windowId, (void *)pixelMap.get()) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle) == RET_OK);
        ASSERT_EQ(pointerStyle.id, MOUSE_ICON::DEVELOPER_DEFINED_ICON);
        ASSERT_TRUE(
            InputManager::GetInstance()->SetMouseHotSpot(windowId, MOUSE_ICON_HOT_SPOT, MOUSE_ICON_HOT_SPOT) == RET_OK);
    } else {
        ASSERT_FALSE(
            InputManager::GetInstance()->SetMouseHotSpot(windowId, MOUSE_ICON_HOT_SPOT, MOUSE_ICON_HOT_SPOT) == RET_OK);
    }
}

/**
 * @tc.name: InputManagerPointerTest_SetPointerStyle_001
 * @tc.desc: Sets the pointer style of the window
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto window = WindowUtilsTest::GetInstance()->GetWindow();
    CHKPV(window);
    uint32_t windowId = window->GetWindowId();
    PointerStyle pointerStyle;
    pointerStyle.id = MOUSE_ICON::CROSS;
    if (InputManager::GetInstance()->SetPointerStyle(windowId, pointerStyle) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle) == RET_OK);
        ASSERT_EQ(pointerStyle.id, MOUSE_ICON::CROSS);
    }
}

/**
 * @tc.name: InputManagerPointerTest_SetPointerStyle_002
 * @tc.desc: Sets the pointer style of the window
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetPointerStyle_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t windowId = INVAID_VALUE;
    PointerStyle pointerStyle;
    pointerStyle.id = MOUSE_ICON::CROSS;
    if (InputManager::GetInstance()->SetPointerStyle(windowId, pointerStyle) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle) == RET_OK);
        ASSERT_EQ(pointerStyle.id, MOUSE_ICON::CROSS);
    }
}

/**
 * @tc.name: InputManagerPointerTest_SetTouchpadScrollSwitch_001
 * @tc.desc: Set touchpad scroll switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetTouchpadScrollSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = false;
    ASSERT_TRUE(InputManager::GetInstance()->SetTouchpadScrollSwitch(flag) == RET_OK);
}

/**
 * @tc.name: InputManagerPointerTest_GetTouchpadScrollSwitch_001
 * @tc.desc: Get touchpad scroll switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_GetTouchpadScrollSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = true;
    InputManager::GetInstance()->SetTouchpadScrollSwitch(flag);
    bool newFlag = true;
    ASSERT_TRUE(InputManager::GetInstance()->GetTouchpadScrollSwitch(newFlag) == RET_OK);
    ASSERT_TRUE(flag == newFlag);
}

/**
 * @tc.name: InputManagerPointerTest_SetTouchpadScrollDirection_001
 * @tc.desc: Set touchpad scroll direction switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetTouchpadScrollDirection_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool state = false;
    ASSERT_TRUE(InputManager::GetInstance()->SetTouchpadScrollDirection(state) == RET_OK);
}

/**
 * @tc.name: InputManagerPointerTest_GetTouchpadScrollDirection_001
 * @tc.desc: Get touchpad scroll direction switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_GetTouchpadScrollDirection_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool state = true;
    InputManager::GetInstance()->SetTouchpadScrollDirection(state);
    bool newState = true;
    ASSERT_TRUE(InputManager::GetInstance()->GetTouchpadScrollDirection(newState) == RET_OK);
    ASSERT_TRUE(state == newState);
}

/**
 * @tc.name: InputManagerPointerTest_SetTouchpadTapSwitch_001
 * @tc.desc: Set touchpad tap switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetTouchpadTapSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = false;
    ASSERT_TRUE(InputManager::GetInstance()->SetTouchpadTapSwitch(flag) == RET_OK);
}

/**
 * @tc.name: InputManagerPointerTest_GetTouchpadTapSwitch_001
 * @tc.desc: Get touchpad tap switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_GetTouchpadTapSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = true;
    InputManager::GetInstance()->SetTouchpadTapSwitch(flag);
    bool newFlag = true;
    ASSERT_TRUE(InputManager::GetInstance()->GetTouchpadTapSwitch(newFlag) == RET_OK);
    ASSERT_TRUE(flag == newFlag);
}

/**
 * @tc.name: InputManagerPointerTest_SetTouchpadPointerSpeed_001
 * @tc.desc: Set touchpad pointer speed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetTouchpadPointerSpeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t speed = POINTER_SPEED_ONE;
    ASSERT_TRUE(InputManager::GetInstance()->SetTouchpadPointerSpeed(speed) == RET_OK);
}

/**
 * @tc.name: InputManagerPointerTest_GetTouchpadPointerSpeed_001
 * @tc.desc: Get touchpad pointer speed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_GetTouchpadPointerSpeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t speed = POINTER_SPEED_TWO;
    InputManager::GetInstance()->SetTouchpadPointerSpeed(speed);
    int32_t newSpeed = POINTER_SPEED_THREE;
    ASSERT_TRUE(InputManager::GetInstance()->GetTouchpadPointerSpeed(newSpeed) == RET_OK);
    ASSERT_TRUE(speed == newSpeed);
}

/**
 * @tc.name: InputManagerPointerTest_SetTouchpadPinchSwitch_001
 * @tc.desc: Set touchpad pinch switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetTouchpadPinchSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = false;
    ASSERT_TRUE(InputManager::GetInstance()->SetTouchpadPinchSwitch(flag) == RET_OK);
}

/**
 * @tc.name: InputManagerPointerTest_GetTouchpadPinchSwitch_001
 * @tc.desc: Get touchpad pinch switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_GetTouchpadPinchSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = true;
    InputManager::GetInstance()->SetTouchpadPinchSwitch(flag);
    bool newFlag = true;
    ASSERT_TRUE(InputManager::GetInstance()->GetTouchpadPinchSwitch(newFlag) == RET_OK);
    ASSERT_TRUE(flag == newFlag);
}

/**
 * @tc.name: InputManagerPointerTest_SetTouchpadSwipeSwitch_001
 * @tc.desc: Set touchpad swipe switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetTouchpadSwipeSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = false;
    ASSERT_TRUE(InputManager::GetInstance()->SetTouchpadSwipeSwitch(flag) == RET_OK);
}

/**
 * @tc.name: InputManagerPointerTest_GetTouchpadSwipeSwitch_001
 * @tc.desc: Get touchpad swipe switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_GetTouchpadSwipeSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = true;
    InputManager::GetInstance()->SetTouchpadSwipeSwitch(flag);
    bool newFlag = true;
    ASSERT_TRUE(InputManager::GetInstance()->GetTouchpadSwipeSwitch(newFlag) == RET_OK);
    ASSERT_TRUE(flag == newFlag);
}

/**
 * @tc.name: InputManagerPointerTest_SetTouchpadRightClickType_001
 * @tc.desc: Set touchpad right click type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetTouchpadRightClickType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t type = 1;
    ASSERT_TRUE(InputManager::GetInstance()->SetTouchpadRightClickType(type) == RET_OK);
}

/**
 * @tc.name: InputManagerPointerTest_GetTouchpadRightClickType_001
 * @tc.desc: Get touchpad right click type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_GetTouchpadRightClickType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t type = RIGHT_CLICK_TYPE;
    InputManager::GetInstance()->SetTouchpadRightClickType(type);
    int32_t newType = 1;
    ASSERT_TRUE(InputManager::GetInstance()->GetTouchpadRightClickType(newType) == RET_OK);
    ASSERT_TRUE(type == newType);
}

/**
 * @tc.name: InputManagerPointerTest_SetPointerSize_001
 * @tc.desc: Sets pointer size
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetPointerSize_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t setSize = 3;
    ASSERT_TRUE(InputManager::GetInstance()->SetPointerSize(setSize) == RET_OK);
    setSize = 1;
    InputManager::GetInstance()->SetPointerSize(setSize);
}

/**
 * @tc.name: InputManagerPointerTest_GetPointerSize_001
 * @tc.desc: Gets pointer size
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_GetPointerSize_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t setSize = 1;
    ASSERT_TRUE(InputManager::GetInstance()->SetPointerSize(setSize) == RET_OK);
    int32_t getSize = 3;
    ASSERT_TRUE(InputManager::GetInstance()->GetPointerSize(getSize) == RET_OK);
    ASSERT_TRUE(setSize == getSize);
}

/**
 * @tc.name: InputManagerPointerTest_SetPointerColor_001
 * @tc.desc: Sets pointer color
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetPointerColor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int32_t> deviceIds;
    auto callback = [&deviceIds] (std::vector<int32_t> ids) {
        deviceIds = ids;
    };
    int32_t ret = InputManager::GetInstance()->GetDeviceIds(callback);
    ASSERT_EQ(ret, RET_OK);
    for (const auto& devicedId : deviceIds) {
        std::shared_ptr<InputDevice> device;
        auto tmpcallback = [&device] (std::shared_ptr<InputDevice> inputDevice) {
            device = inputDevice;
        };
        ASSERT_EQ(InputManager::GetInstance()->GetDevice(devicedId, tmpcallback), RET_OK);
        ASSERT_TRUE(device != nullptr);
        if (device->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_POINTER)) {
            int32_t setColor = 0xA946F1;
            ASSERT_TRUE(InputManager::GetInstance()->SetPointerColor(setColor) == RET_OK);
            setColor = 0x000000;
            InputManager::GetInstance()->SetPointerColor(setColor);
            break;
        }
    }
}

/**
 * @tc.name: InputManagerPointerTest_GetPointerColor_001
 * @tc.desc: Gets pointer color
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_GetPointerColor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int32_t> deviceIds;
    auto callback = [&deviceIds] (std::vector<int32_t> ids) {
        deviceIds = ids;
    };
    int32_t ret = InputManager::GetInstance()->GetDeviceIds(callback);
    ASSERT_EQ(ret, RET_OK);
    for (const auto& devicedId : deviceIds) {
        std::shared_ptr<InputDevice> device;
        auto tmpcallback = [&device] (std::shared_ptr<InputDevice> inputDevice) {
            device = inputDevice;
        };
        ASSERT_EQ(InputManager::GetInstance()->GetDevice(devicedId, tmpcallback), RET_OK);
        ASSERT_TRUE(device != nullptr);
        if (device->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_POINTER)) {
            int32_t setColor = 0x000000;
            ASSERT_TRUE(InputManager::GetInstance()->SetPointerColor(setColor) == RET_OK);
            int32_t getColor = 3;
            ASSERT_TRUE(InputManager::GetInstance()->GetPointerColor(getColor) == RET_OK);
            ASSERT_TRUE(setColor == getColor);
            break;
        }
    }
}

/**
 * @tc.name: InputManagerPointerTest_SetCustomCursor_001
 * @tc.desc: Set the mouse custom cursor
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetCustomCursor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto window = WindowUtilsTest::GetInstance()->GetWindow();
    CHKPV(window);
    uint32_t windowId = window->GetWindowId();
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    PointerStyle pointerStyle;
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = InputManagerUtil::SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    pointerStyle.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    if (InputManager::GetInstance()->SetCustomCursor(windowId, (void *)pixelMap.get(), 32, 32) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle) == RET_OK);
        ASSERT_EQ(pointerStyle.id, MOUSE_ICON::DEVELOPER_DEFINED_ICON);
    } else if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        ASSERT_FALSE(false);  // errors occur
    } else {
        ASSERT_TRUE(false);
    }
}

/**
 * @tc.name: InputManagerPointerTest_SetCustomCursor_002
 * @tc.desc: Set the mouse custom cursor
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetCustomCursor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto window = WindowUtilsTest::GetInstance()->GetWindow();
    CHKPV(window);
    uint32_t windowId = window->GetWindowId();
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/Zoom_Out.svg";
    PointerStyle pointerStyle;
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = InputManagerUtil::SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    pointerStyle.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    if (InputManager::GetInstance()->SetCustomCursor(windowId, (void *)pixelMap.get(), 64, 64) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle) == RET_OK);
        ASSERT_EQ(pointerStyle.id, MOUSE_ICON::DEVELOPER_DEFINED_ICON);
    } else if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        ASSERT_FALSE(false);  // errors occur
    } else {
        ASSERT_TRUE(false);
    }
}

/**
 * @tc.name: InputManagerPointerTest_SetCustomCursor_003
 * @tc.desc: Set the mouse custom cursor
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetCustomCursor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto window = WindowUtilsTest::GetInstance()->GetWindow();
    CHKPV(window);
    uint32_t windowId = window->GetWindowId();
    PointerStyle pointerStyle;
    pointerStyle.id = MOUSE_ICON::DEFAULT;
    int32_t ret = InputManager::GetInstance()->SetPointerStyle(windowId, pointerStyle);
    ASSERT_TRUE(ret == RET_OK);
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/Zoom_Out.svg";
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = InputManagerUtil::SetMouseIconTest(iconPath);
    ASSERT_TRUE(pixelMap != nullptr);
    pointerStyle.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    ret = InputManager::GetInstance()->SetCustomCursor(INVAID_VALUE, (void *)pixelMap.get(), 0, 0);
    ASSERT_EQ(ret, RET_ERR);
    ASSERT_TRUE(InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle) == RET_OK);
    ASSERT_EQ(pointerStyle.id, MOUSE_ICON::DEFAULT);
}

/**
 * @tc.name: InputManagerPointerTest_SetCustomCursor_004
 * @tc.desc: Set the mouse custom cursor
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetCustomCursor_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto window = WindowUtilsTest::GetInstance()->GetWindow();
    CHKPV(window);
    uint32_t windowId = window->GetWindowId();
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/Zoom_Out.svg";
    PointerStyle pointerStyle;
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = InputManagerUtil::SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    pointerStyle.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    if (InputManager::GetInstance()->SetCustomCursor(windowId, (void *)pixelMap.get()) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle) == RET_OK);
        ASSERT_EQ(pointerStyle.id, MOUSE_ICON::DEVELOPER_DEFINED_ICON);
    } else if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        ASSERT_FALSE(false);  // errors occur
    } else {
        ASSERT_TRUE(false);
    }
}

/**
 * @tc.name: InputManagerPointerTest_SetCustomCursor_005
 * @tc.desc: Set the mouse custom cursor
 * @tc.type: FUNC
 * @tc.require: I530XS
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetCustomCursor_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto window = WindowUtilsTest::GetInstance()->GetWindow();
    CHKPV(window);
    uint32_t windowId = window->GetWindowId();
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/Zoom_Out.svg";
    PointerStyle pointerStyle;
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = InputManagerUtil::SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    pointerStyle.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    int32_t focusX = 64;
    if (InputManager::GetInstance()->SetCustomCursor(windowId, (void *)pixelMap.get(), focusX) == RET_OK) {
        ASSERT_TRUE(InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle) == RET_OK);
        ASSERT_EQ(pointerStyle.id, MOUSE_ICON::DEVELOPER_DEFINED_ICON);
    } else if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        ASSERT_FALSE(false);  // errors occur
    } else {
        ASSERT_TRUE(false);
    }
}

/**
 * @tc.name: InputManagerPointerTest_SetTouchpadThreeFingersTapSwitch_001
 * @tc.desc: Set touchpad ThreeFingers Tap switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerPointerTest, InputManagerPointerTest_SetTouchpadThreeFingersTapSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = false;
    ASSERT_TRUE(InputManager::GetInstance()->SetTouchpadThreeFingersTapSwitch(flag) == RET_OK);
}
} // namespace MMI
} // namespace OHOS