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
#define MMI_LOG_TAG "InputEventHookTest"

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

class InputEventHookTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: InputEventHookTest001
 * @tc.desc: Test the function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookTest, InputEventHookTest001, TestSize.Level0)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NextHookGetter nextHookGetter = [] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> {
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
    InputEventHook hook(sess, HOOK_EVENT_TYPE_MOUSE, nextHookGetter);
    bool result = hook.OnPointerEvent(pointerEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputEventHookTest002
 * @tc.desc: Test the function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookTest, InputEventHookTest002, TestSize.Level0)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NextHookGetter nextHookGetter = [] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> {
        return nullptr;
    };
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    int32_t eventId = 1;
    keyEvent->SetId(eventId);
    InputEventHook hook(sess, HOOK_EVENT_TYPE_MOUSE, nextHookGetter);
    bool result = hook.OnKeyEvent(keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputEventHookTest003
 * @tc.desc: Test the function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookTest, InputEventHookTest003, TestSize.Level0)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NextHookGetter nextHookGetter = [] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> {
        return nullptr;
    };
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    int32_t eventId = 1;
    keyEvent->SetId(eventId);
    InputEventHook hook(sess, HOOK_EVENT_TYPE_MOUSE, nextHookGetter);
    int32_t result = hook.DispatchToNextHandler(keyEvent);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: InputEventHookTest004
 * @tc.desc: Test the function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookTest, InputEventHookTest004, TestSize.Level0)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NextHookGetter nextHookGetter = [] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> {
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
    InputEventHook hook(sess, HOOK_EVENT_TYPE_MOUSE, nextHookGetter);
    int32_t result = hook.DispatchToNextHandler(pointerEvent);
    EXPECT_EQ(result, RET_OK);
}
} // namespace MMI
} // namespace OHOS