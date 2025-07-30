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

#include "server_msg_handler.h"

#include <cinttypes>
#include <cstdio>
#include <gtest/gtest.h>

#include "image_source.h"
#include "pixel_map.h"
#include "sec_comp_enhance_kit.h"
#include "running_process_info.h"

#include "authorize_helper.h"
#include "define_multimodal.h"
#include "display_event_monitor.h"
#include "event_log_helper.h"
#include "inject_notice_manager.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "input_manager_impl.h"
#include "libinput.h"
#include "mmi_log.h"
#include "pointer_event.h"
#include "stream_buffer.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ServerMsgHandlerSupTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class ServerMsgHandlerSupTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: ServerMsgHandlerSupTest_OnDeviceRemoved_001
 * @tc.desc: Test the function OnDeviceRemoved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerSupTest, ServerMsgHandlerSupTest_OnDeviceRemoved_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 600;
    int32_t deviceId2 = 601;

    ServerMsgHandler handler;
    auto keyEvent = handler.CleanUpKeyEvent();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keys_.clear();

    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    item.SetDeviceId(deviceId2);
    keyEvent->AddKeyItem(item);

    KeyEvent::KeyItem item2;
    item2.SetDeviceId(deviceId);
    item2.SetPressed(false);
    item2.SetKeyCode(KeyEvent::KEYCODE_HOME);
    keyEvent->AddKeyItem(item2);

    KeyEvent::KeyItem item3;
    item3.SetDeviceId(deviceId);
    item3.SetPressed(true);
    item3.SetKeyCode(KeyEvent::KEYCODE_CLEAR);
    keyEvent->AddKeyItem(item3);
    EXPECT_EQ(keyEvent->GetKeyItems().size(), 3);

    ASSERT_NO_FATAL_FAILURE(handler.OnDeviceRemoved(deviceId));
    EXPECT_EQ(keyEvent->GetKeyItems().size(), 2);
    EXPECT_EQ(keyEvent->GetDeviceId(), deviceId);
    keyEvent = nullptr;
}

/**
 * @tc.name: ServerMsgHandlerSupTest_CleanUpKeyEvent_001
 * @tc.desc: Test the function CleanUpKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerSupTest, ServerMsgHandlerSupTest_CleanUpKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t deviceId = 600;

    auto keyEvent = handler.CleanUpKeyEvent();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keys_.clear();

    KeyEvent::KeyItem item2;
    item2.SetDeviceId(deviceId);
    item2.SetPressed(false);

    int32_t keyCode = 1;
    item2.SetKeyCode(keyCode);
    keyEvent->AddKeyItem(item2);

    KeyEvent::KeyItem item3;
    item3.SetDeviceId(deviceId);
    item3.SetPressed(true);
    keyCode = 2;
    item3.SetKeyCode(keyCode);
    keyEvent->AddKeyItem(item3);
    EXPECT_EQ(keyEvent->GetKeyItems().size(), 2);

    auto rlt = handler.CleanUpKeyEvent();
    ASSERT_NE(rlt, nullptr);
    EXPECT_EQ(keyEvent->GetKeyItems().size(), 1);
    EXPECT_EQ(rlt->GetKeyItems().size(), 1);
    keyEvent = nullptr;
}

/**
 * @tc.name: ServerMsgHandlerSupTest_NormalizeKeyEvent_001
 * @tc.desc: Test the function NormalizeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerSupTest, ServerMsgHandlerSupTest_NormalizeKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto inputEvent = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_VOLUME_UP);
    int32_t deviceId = 999;
    inputEvent->SetDeviceId(deviceId);
    INPUT_DEV_MGR->virtualInputDevices_.clear();
    auto rlt = handler.NormalizeKeyEvent(inputEvent);
    EXPECT_EQ(rlt, inputEvent);
}

/**
 * @tc.name: ServerMsgHandlerSupTest_NormalizeKeyEvent_002
 * @tc.desc: Test the function NormalizeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerSupTest, ServerMsgHandlerSupTest_NormalizeKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t deviceId = 600;

    auto keyEvent = handler.CleanUpKeyEvent();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keys_.clear();

    auto inputEvent = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_VOLUME_UP);
    inputEvent->SetDeviceId(deviceId);
    int64_t actionTime = 999;
    inputEvent->SetActionTime(actionTime);
    inputEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    auto inputDevice = std::make_shared<InputDevice>();
    inputDevice->SetRemoteDevice(true);
    INPUT_DEV_MGR->virtualInputDevices_.clear();
    INPUT_DEV_MGR->AddVirtualInputDeviceInner(deviceId, inputDevice);

    auto rlt = handler.NormalizeKeyEvent(inputEvent);
    EXPECT_EQ(rlt, keyEvent);
    EXPECT_EQ(keyEvent->GetDeviceId(), inputEvent->GetDeviceId());
    EXPECT_EQ(keyEvent->GetActionStartTime(), actionTime);
    EXPECT_EQ(rlt->GetKeyItems().size(), 1);

    int32_t deviceId1 = 601;
    auto inputEvent2 = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_VOLUME_UP);
    inputEvent2->SetDeviceId(deviceId1);
    inputEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    int32_t keyCode = KeyEvent::KEYCODE_SCROLL_LOCK;
    inputEvent2->SetKeyCode(keyCode);
    KeyEvent::KeyItem item;
    item.SetDeviceId(deviceId1);
    item.SetPressed(true);
    item.SetKeyCode(keyCode);
    inputEvent2->AddKeyItem(item);
    rlt = handler.NormalizeKeyEvent(inputEvent);
    EXPECT_EQ(rlt, keyEvent);
    EXPECT_EQ(rlt->GetKeyItems().size(), 1);
}

/**
 * @tc.name: ServerMsgHandlerSupTest_NormalizeKeyEvent_003
 * @tc.desc: Test the function NormalizeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerSupTest, ServerMsgHandlerSupTest_NormalizeKeyEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t deviceId = 600;

    auto keyEvent = handler.CleanUpKeyEvent();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->keys_.clear();

    auto inputEvent = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_VOLUME_UP);
    inputEvent->SetDeviceId(deviceId);
    inputEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    auto inputDevice = std::make_shared<InputDevice>();
    inputDevice->SetRemoteDevice(true);
    INPUT_DEV_MGR->virtualInputDevices_.clear();
    INPUT_DEV_MGR->AddVirtualInputDeviceInner(deviceId, inputDevice);

    auto rlt = handler.NormalizeKeyEvent(inputEvent);
    EXPECT_EQ(rlt, keyEvent);
    EXPECT_EQ(rlt->GetKeyItems().size(), 1);

    int32_t keyCode = KeyEvent::KEYCODE_SCROLL_LOCK;
    inputEvent->SetKeyCode(keyCode);

    KeyEvent::KeyItem item;
    item.SetDeviceId(deviceId);
    item.SetPressed(true);
    item.SetKeyCode(keyCode);
    inputEvent->AddKeyItem(item);

    rlt = handler.NormalizeKeyEvent(inputEvent);
    EXPECT_EQ(rlt, keyEvent);
    EXPECT_EQ(rlt->GetKeyItems().size(), 1);
}
} // namespace MMI
} // namespace OHOS
