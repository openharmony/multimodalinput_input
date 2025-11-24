/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#include "key_event_hook_manager.h"
#include "pointer_event_hook.h"
#include "input_event_hook.h"
#include "event_dispatch_handler.h"
#include "event_loop_closure_checker.h"
#include "event_dispatch_order_checker.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_event_handler.h"
#include "uds_server.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerEventHookTest"

namespace OHOS {
namespace MMI {
namespace {
const std::string PROGRAM_NAME = "uds_server_test";
constexpr int32_t MODULE_TYPE = 1;
constexpr int32_t UDS_FD = -1;
constexpr int32_t UDS_UID = 456;
constexpr int32_t UDS_PID = 123;
constexpr int32_t POINTER_ITEM_DOWN_TIME_THREE = 10006;
constexpr int32_t POINTER_ITEM_DISPLAY_X_ELEVEN = 543;
constexpr int32_t POINTER_ITEM_DISPLAY_Y_FIFTEEN = 863;
using namespace testing::ext;
} // namespace

class PointerEventHookTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: PointerEventHookTest001
 * @tc.desc: Test the function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventHookTest, PointerEventHookTest001, TestSize.Level0)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NextHookGetter nextHookGetter = [this] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> {
        return nullptr;
    };
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
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
    PointerEventHook hook(sess, HOOK_EVENT_TYPE_MOUSE, nextHookGetter);
    bool result = hook.OnPointerEvent(pointerEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: PointerEventHookTest002
 * @tc.desc: Test the function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventHookTest, PointerEventHookTest002, TestSize.Level0)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NextHookGetter nextHookGetter = [this] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> {
        return nullptr;
    };
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    PointerEventHook hook(sess, HOOK_EVENT_TYPE_MOUSE, nextHookGetter);
    bool result = hook.OnPointerEvent(pointerEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: PointerEventHookTest003
 * @tc.desc: Test the function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventHookTest, PointerEventHookTest003, TestSize.Level0)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NextHookGetter nextHookGetter = [this] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> {
        return nullptr;
    };
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    PointerEventHook hook(sess, HOOK_EVENT_TYPE_TOUCH, nextHookGetter);
    bool result = hook.OnPointerEvent(pointerEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: PointerEventHookTest004
 * @tc.desc: Test the function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventHookTest, PointerEventHookTest004, TestSize.Level0)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NextHookGetter nextHookGetter = [this] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> {
        return nullptr;
    };
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    PointerEventHook hook(sess, HOOK_EVENT_TYPE_TOUCH, nextHookGetter);
    int32_t eventId = 1;
    int32_t eventId1 = 0;
    pointerEvent->SetId(eventId);
    hook.orderChecker_.UpdateEvent(eventId1);
    int32_t result = hook.DispatchToNextHandler(pointerEvent);
    EXPECT_EQ(result, ERROR_INVALID_PARAMETER);
}

/**
 * @tc.name: PointerEventHookTest005
 * @tc.desc: Test the function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventHookTest, PointerEventHookTest005, TestSize.Level0)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NextHookGetter nextHookGetter = [this] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> {
        return nullptr;
    };
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    PointerEvent::PointerItem pointerItem1;
    int32_t disPlayX1 = 100;
    int32_t disPlayY1 = 110;
    pointerItem1.SetFixedDisplayXPos(disPlayX1);
    pointerItem1.SetFixedDisplayYPos(disPlayY1);
    pointerItem1.SetPointerId(0);
    pointerItem1.SetDownTime(0);
    pointerItem1.SetPressed(true);
    pointerItem1.SetPressure(30);
    pointerEvent->AddPointerItem(pointerItem1);
    PointerEventHook hook(sess, HOOK_EVENT_TYPE_TOUCH, nextHookGetter);
    int32_t eventId = 1;
    int32_t eventId1 = 0;
    pointerEvent->SetId(eventId);
    hook.orderChecker_.UpdateEvent(eventId1);
    int32_t result = hook.DispatchToNextHandler(pointerEvent);
    EXPECT_EQ(result, ERROR_INVALID_PARAMETER);
}

/**
 * @tc.name: PointerEventHookTest006
 * @tc.desc: Test the function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventHookTest, PointerEventHookTest006, TestSize.Level0)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NextHookGetter nextHookGetter = [this] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> {
        return nullptr;
    };
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    PointerEventHook hook(sess, HOOK_EVENT_TYPE_TOUCH, nextHookGetter);
    int32_t eventId = 1;
    int32_t eventId1 = 0;
    pointerEvent->SetId(eventId);
    hook.orderChecker_.UpdateEvent(eventId1);
    bool result = hook.DispatchDirectly(pointerEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: PointerEventHookTest007
 * @tc.desc: Test the function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventHookTest, PointerEventHookTest007, TestSize.Level0)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NextHookGetter nextHookGetter = [this] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> {
        return nullptr;
    };
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    PointerEventHook hook(sess, HOOK_EVENT_TYPE_TOUCH, nextHookGetter);
    int32_t eventId = 1;
    int32_t eventId1 = 0;
    pointerEvent->SetId(eventId);
    hook.orderChecker_.UpdateEvent(eventId1);
    bool result = hook.DispatchDirectly(pointerEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: PointerEventHookTest008
 * @tc.desc: Test the function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventHookTest, PointerEventHookTest008, TestSize.Level0)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NextHookGetter nextHookGetter = [this] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> {
        return nullptr;
    };
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    PointerEventHook hook(sess, HOOK_EVENT_TYPE_TOUCH, nextHookGetter);
    int32_t eventId = 1;
    int32_t eventId1 = 0;
    pointerEvent->SetId(eventId);
    hook.orderChecker_.UpdateEvent(eventId1);
    bool result = hook.DispatchDirectly(pointerEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: PointerEventHookTest009
 * @tc.desc: Test the function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerEventHookTest, PointerEventHookTest009, TestSize.Level0)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NextHookGetter nextHookGetter = [this] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> {
        return nullptr;
    };
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_UNKNOWN);
    PointerEventHook hook(sess, HOOK_EVENT_TYPE_TOUCH, nextHookGetter);
    int32_t eventId = 1;
    int32_t eventId1 = 0;
    pointerEvent->SetId(eventId);
    hook.orderChecker_.UpdateEvent(eventId1);
    bool result = hook.DispatchDirectly(pointerEvent);
    EXPECT_FALSE(result);
}
} // namespace MMI
} // namespace OHOS