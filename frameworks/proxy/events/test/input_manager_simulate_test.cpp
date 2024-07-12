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

#include "event_util_test.h"
#include "input_manager_util.h"
#include "multimodal_event_handler.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputManagerSimulateTest"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t TIME_WAIT_FOR_OP = 100;
constexpr int32_t NANOSECOND_TO_MILLISECOND = 1000000;
constexpr int32_t DEFAULT_POINTER_ID = 0;
constexpr int32_t DEFAULT_DEVICE_ID = 0;
constexpr int32_t POINTER_ID = -1;
constexpr int32_t INPUT_INTERCEPTOR_ONE = 2;
constexpr int32_t INPUT_INTERCEPTOR_TWO = 3;
constexpr int32_t INTERCEPTOR_PRIORITY_ONE = 400;
constexpr int32_t INTERCEPTOR_PRIORITY_TWO = 500;
constexpr int32_t INTERCEPTOR_PRIORITY_THREE = 600;
constexpr int32_t POINTER_ITEM_DISPLAY_X_ONE = 90;
constexpr int32_t POINTER_ITEM_DISPLAY_X_THREE = 123;
constexpr int32_t POINTER_ITEM_DISPLAY_X_FIVE = 222;
constexpr int32_t POINTER_ITEM_DISPLAY_X_EIGHT = 505;
constexpr int32_t POINTER_ITEM_DISPLAY_X_NINE = 523;
constexpr int32_t POINTER_ITEM_DISPLAY_X_TEN = 528;
constexpr int32_t POINTER_ITEM_DISPLAY_X_ELEVEN = 543;
constexpr int32_t POINTER_ITEM_DISPLAY_X_THIRTEEN = 640;
constexpr int32_t POINTER_ITEM_DISPLAY_X_FOURTEEN = 660;
constexpr int32_t POINTER_ITEM_DISPLAY_X_SIXTEEN = 710;
constexpr int32_t POINTER_ITEM_DISPLAY_X_SEVENTEEN = 852;
constexpr int32_t POINTER_ITEM_DISPLAY_Y_THREE = 223;
constexpr int32_t POINTER_ITEM_DISPLAY_Y_FOUR = 357;
constexpr int32_t POINTER_ITEM_DISPLAY_Y_FIVE = 367;
constexpr int32_t POINTER_ITEM_DISPLAY_Y_EIGHT = 505;
constexpr int32_t POINTER_ITEM_DISPLAY_Y_TEN = 666;
constexpr int32_t POINTER_ITEM_DISPLAY_Y_ELEVEN = 723;
constexpr int32_t POINTER_ITEM_DISPLAY_Y_TWELVE = 757;
constexpr int32_t POINTER_ITEM_DISPLAY_Y_THIRTEEN = 840;
constexpr int32_t POINTER_ITEM_DISPLAY_Y_FOURTEEN = 860;
constexpr int32_t POINTER_ITEM_DISPLAY_Y_FIFTEEN = 863;
constexpr int32_t POINTER_ITEM_DISPLAY_Y_SIXTEEN = 910;
constexpr int32_t POINTER_ITEM_DOWN_TIME_TWO = 10005;
constexpr int32_t POINTER_ITEM_DOWN_TIME_THREE = 10006;
constexpr int32_t POINTER_ITEM_DOWN_TIME_FOUR = 10007;
constexpr double POINTER_ITEM_PRESSURE_ONE = 5.0;
constexpr double POINTER_ITEM_PRESSURE_TWO = 7.0;
} // namespace

class InputManagerSimulateTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    std::string GetEventDump();
};

void InputManagerSimulateTest::SetUpTestCase()
{
    ASSERT_TRUE(TestUtil->Init());
}

void InputManagerSimulateTest::SetUp()
{
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_FOCUS);
}

void InputManagerSimulateTest::TearDown()
{
    TestUtil->AddEventDump("");
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

std::string InputManagerSimulateTest::GetEventDump()
{
    return TestUtil->GetEventDump();
}

/**
 * @tc.name: MultimodalEventHandler_SimulateKeyEvent_004
 * @tc.desc: Verify simulate key exception event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerSimulateTest, InputManagerSimulateTest_SimulateKeyEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_TRUE(injectDownEvent != nullptr);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    TestSimulateInputEvent(injectDownEvent, TestScene::EXCEPTION_TEST);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

/**
 * @tc.name: MultimodalEventHandler_SimulatePointerEvent_004
 * @tc.desc: Verify simulate screen exception event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerSimulateTest, MultimodalEventHandler_SimulatePointerEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(POINTER_ID);
#ifdef OHOS_BUILD_ENABLE_TOUCH
    TestSimulateInputEvent(pointerEvent, TestScene::EXCEPTION_TEST);
#endif // OHOS_BUILD_ENABLE_TOUCH
}

/**
 * @tc.name: MultimodalEventHandler_SimulatePointerEvent_008
 * @tc.desc: Verify simulate mouse exception event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerSimulateTest, MultimodalEventHandler_SimulatePointerEvent_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(POINTER_ID);
#ifdef OHOS_BUILD_ENABLE_POINTER
    TestSimulateInputEvent(pointerEvent, TestScene::EXCEPTION_TEST);
#endif // OHOS_BUILD_ENABLE_POINTER
}

/**
 * @tc.name: InputManager_Pencil2InputEvent_004
 * @tc.desc: Verify simulate exception event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerSimulateTest, InputManager_Pencil2InputEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(POINTER_ID);
#ifdef OHOS_BUILD_ENABLE_TOUCH
    TestSimulateInputEvent(pointerEvent, TestScene::EXCEPTION_TEST);
#endif // OHOS_BUILD_ENABLE_TOUCH
}

/**
 * @tc.name: TestInputEventInterceptor_006
 * @tc.desc: Verify touchscreen interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerSimulateTest, TestInputEventInterceptor_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->AddFlag(PointerEvent::EVENT_FLAG_NO_INTERCEPT);
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_FIVE);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_FOUR);
    item.SetPressure(POINTER_ITEM_PRESSURE_ONE);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    item.SetPointerId(1);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_SIXTEEN);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_SIXTEEN);
    item.SetPressure(POINTER_ITEM_PRESSURE_TWO);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId{InputManager::GetInstance()->AddInterceptor(interceptor)};
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
#else
    EXPECT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: TestInputEventInterceptor_008
 * @tc.desc: Verify touchscreen interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerSimulateTest, TestInputEventInterceptor_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetDownTime(POINTER_ITEM_DOWN_TIME_FOUR);
    item.SetPointerId(0);
    item.SetDeviceId(1);
    item.SetPressed(true);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_TEN);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_TWELVE);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->AddPointerItem(item);

    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId = InputManager::GetInstance()->AddInterceptor(interceptor);
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
#else
    EXPECT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::string sPointerEs = GetEventDump();
    MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
    ASSERT_TRUE(!sPointerEs.empty());
#else
    ASSERT_TRUE(sPointerEs.empty());
#endif // OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_INTERCEPTOR
    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: TestInputEventInterceptor_009
 * @tc.desc: Verify mouse interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerSimulateTest, TestInputEventInterceptor_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(POINTER_ITEM_DOWN_TIME_THREE);
    item.SetPressed(true);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_ELEVEN);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_FIFTEEN);
    item.SetDeviceId(1);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetPointerId(0);

    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId = InputManager::GetInstance()->AddInterceptor(interceptor);
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
#else
    EXPECT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::string sPointerEs = GetEventDump();
    MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
    ASSERT_TRUE(!sPointerEs.empty());
#else
    ASSERT_TRUE(sPointerEs.empty());
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_INTERCEPTOR
    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: TestInputEventInterceptor_010
 * @tc.desc: Verify volume key interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerSimulateTest, TestInputEventInterceptor_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_NE(injectDownEvent, nullptr);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetDownTime(downTime);
    kitDown.SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    kitDown.SetPressed(true);
    kitDown.SetDeviceId(1);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    auto interceptor = GetPtr<InputEventCallback>();
    int32_t interceptorId{InputManager::GetInstance()->AddInterceptor(interceptor)};
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
#else
    EXPECT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);

    std::string sPointerEs = GetEventDump();
    MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: TestInputEventInterceptor_012
 * @tc.desc: Verify mouse interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerSimulateTest, TestInputEventInterceptor_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(POINTER_ITEM_DOWN_TIME_TWO);
    item.SetPressed(true);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_SEVENTEEN);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_FIVE);
    item.SetDeviceId(1);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->AddPointerItem(item);

    auto interceptor = GetPtr<InputEventCallback>();
    uint32_t touchTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX);
    int32_t interceptorId =
        InputManager::GetInstance()->AddInterceptor(interceptor, INTERCEPTOR_PRIORITY_ONE, touchTags);
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
#else
    EXPECT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);

    std::string sPointerEs = GetEventDump();
    MMI_HILOGD("sPointerEs:%{public}s", sPointerEs.c_str());
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
    ASSERT_TRUE(!sPointerEs.empty());
#else
    ASSERT_TRUE(sPointerEs.empty());
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_INTERCEPTOR
    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: TestInputEventInterceptor_014
 * @tc.desc: Verify space key interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerSimulateTest, TestInputEventInterceptor_014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_NE(injectDownEvent, nullptr);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetDeviceId(1);
    kitDown.SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    auto interceptor2 = GetPtr<PriorityMiddleCallback>();
    auto interceptor1 = GetPtr<PriorityHighCallback>();
    uint32_t touchTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX);
    int32_t interceptorId2{
        InputManager::GetInstance()->AddInterceptor(interceptor2, INTERCEPTOR_PRIORITY_TWO, touchTags)};
    int32_t interceptorId1{
        InputManager::GetInstance()->AddInterceptor(interceptor1, INTERCEPTOR_PRIORITY_ONE, touchTags)};
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId1));
    EXPECT_TRUE(IsValidHandlerId(interceptorId2));
#else
    EXPECT_EQ(interceptorId1, ERROR_UNSUPPORT);
    EXPECT_EQ(interceptorId2, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);
    for (size_t i = 0; i < INPUT_INTERCEPTOR_ONE; ++i) {
        std::string sPointerEs = GetEventDump();
        MMI_HILOGD("PriorityLevel Test:sPointerEs:%{public}s", sPointerEs.c_str());
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
        if (i == 0) {
            EXPECT_NE(sPointerEs, "Call high interceptors");
        } else {
            ASSERT_TRUE(sPointerEs.empty());
        }
#else
        ASSERT_TRUE(sPointerEs.empty());
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_INTERCEPTOR
    }

    InputManagerUtil::TestInterceptorId(interceptorId1, interceptorId2);
}

/**
 * @tc.name: TestInputEventInterceptor_015
 * @tc.desc: Verify space key interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerSimulateTest, TestInputEventInterceptor_015, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_INTERCEPT);
    std::shared_ptr<KeyEvent> injectDownEvent = KeyEvent::Create();
    ASSERT_NE(injectDownEvent, nullptr);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetPressed(true);
    kitDown.SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    kitDown.SetDeviceId(1);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
    injectDownEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    uint32_t touchTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX);
    int32_t interceptorId1{InputManager::GetInstance()->AddInterceptor(
        GetPtr<PriorityHighCallback>(), INTERCEPTOR_PRIORITY_TWO, touchTags)};
    int32_t interceptorId2{InputManager::GetInstance()->AddInterceptor(
        GetPtr<PriorityMiddleCallback>(), INTERCEPTOR_PRIORITY_THREE, touchTags)};
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    EXPECT_TRUE(IsValidHandlerId(interceptorId1));
    EXPECT_TRUE(IsValidHandlerId(interceptorId2));
#else
    EXPECT_EQ(interceptorId1, ERROR_UNSUPPORT);
    EXPECT_EQ(interceptorId2, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    if (IsValidHandlerId(interceptorId1)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId1);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    InputManager::GetInstance()->SimulateInputEvent(injectDownEvent);
    for (size_t i = 0; i < INPUT_INTERCEPTOR_TWO; ++i) {
        std::string sPointerEs = GetEventDump();
        MMI_HILOGD("PriorityLevel Test:sPointerEs:%{public}s", sPointerEs.c_str());
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
        if (i == 0) {
            EXPECT_NE(sPointerEs, "Call middle interceptors");
        } else {
            ASSERT_TRUE(sPointerEs.empty());
        }
#else
        ASSERT_TRUE(sPointerEs.empty());
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_INTERCEPTOR
    }

    if (IsValidHandlerId(interceptorId2)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId2);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }
}

/**
 * @tc.name: TestInputEventInterceptor_016
 * @tc.desc: Verify keyevent interceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerSimulateTest, TestInputEventInterceptor_016, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto fun = [](std::shared_ptr<KeyEvent> keyEvent) { MMI_HILOGD("Add interceptor success"); };
    int32_t interceptorId = InputManager::GetInstance()->AddInterceptor(fun);
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
    ASSERT_NE(interceptorId, INVALID_HANDLER_ID);
#else
    ASSERT_EQ(interceptorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_INTERCEPTOR
    if (IsValidHandlerId(interceptorId)) {
        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
    }
}

/**
 * @tc.name: InputManager_TouchPadSimulateInputEvent_001
 * @tc.desc: Verify touchpad simulate and monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerSimulateTest, InputManager_TouchPadSimulateInputEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_NE(callbackPtr, nullptr);
    int32_t monitorId{InputManagerUtil::TestAddMonitor(callbackPtr)};
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int64_t stepTime = GetSysClockTime();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item{};
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(stepTime);
    item.SetPressed(true);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_NINE);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_ELEVEN);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetActionTime(stepTime);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    InputManagerUtil::TestMonitor(monitorId, pointerEvent);
}

/**
 * @tc.name: InputManager_TouchPadSimulateInputEvent_002
 * @tc.desc: Verify touchpad simulate and monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerSimulateTest, InputManager_TouchPadSimulateInputEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_NE(callbackPtr, nullptr);
    int32_t monitorId{InputManagerUtil::TestAddMonitor(callbackPtr)};
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int64_t measureTime = GetSysClockTime();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item{};
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(measureTime);
    item.SetPressed(true);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_ONE);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_TEN);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetActionTime(measureTime);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    InputManagerUtil::TestMonitor(monitorId, pointerEvent);
}

/**
 * @tc.name: InputManager_TouchPadSimulateInputEvent_003
 * @tc.desc: Verify touchpad simulate and monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerSimulateTest, InputManager_TouchPadSimulateInputEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_NE(callbackPtr, nullptr);
    int32_t monitorId{InputManagerUtil::TestAddMonitor(callbackPtr)};
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int64_t deedTime = GetSysClockTime();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item{};
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(deedTime);
    item.SetPressed(false);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_EIGHT);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_EIGHT);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetActionTime(deedTime);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    InputManagerUtil::TestMonitor(monitorId, pointerEvent);
}

/**
 * @tc.name: InputManager_TouchPadSimulateInputEvent_004
 * @tc.desc: Verify touchpad simulate and monitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerSimulateTest, InputManager_TouchPadSimulateInputEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callbackPtr = GetPtr<InputEventCallback>();
    ASSERT_NE(callbackPtr, nullptr);
    int32_t monitorId{InputManagerUtil::TestAddMonitor(callbackPtr)};
#ifdef OHOS_BUILD_ENABLE_MONITOR
    EXPECT_TRUE(monitorId >= MIN_HANDLER_ID);
#else
    EXPECT_EQ(monitorId, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_MONITOR
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    int64_t actionTime = GetSysClockTime();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_TRUE(pointerEvent != nullptr);
    PointerEvent::PointerItem item{};
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDownTime(actionTime);
    item.SetPressed(true);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_THREE);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_THREE);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);
    item.SetPointerId(1);
    item.SetDownTime(actionTime);
    item.SetPressed(true);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_THIRTEEN);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_THIRTEEN);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);
    item.SetPointerId(2);
    item.SetDownTime(actionTime);
    item.SetPressed(true);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X_FOURTEEN);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y_FOURTEEN);
    item.SetDeviceId(DEFAULT_DEVICE_ID);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetActionTime(actionTime);
    pointerEvent->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);

    InputManagerUtil::TestMonitor(monitorId, pointerEvent);
}
} // namespace MMI
} // namespace OHOS