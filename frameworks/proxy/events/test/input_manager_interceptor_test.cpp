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

#include <memory>
#include <thread>
#include <gtest/gtest.h>

#include "define_multimodal.h"
#include "input_manager.h"
#include "key_event.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputManagerInterceptorTest"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t DEFAULT_DEVICE_ID { 0 };
constexpr int32_t TIME_WAIT_FOR_OP { 50 };
}
using namespace testing::ext;

class InputManagerInterceptorTest : public testing::Test {
public:
    void SetUp() {}
    void TearDown() {}
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

protected:
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    std::shared_ptr<KeyEvent> BuildKeyEvent0101();
#endif // OHOS_BUILD_ENABLE_KEYBOARD
};

#ifdef OHOS_BUILD_ENABLE_KEYBOARD

std::shared_ptr<KeyEvent> InputManagerInterceptorTest::BuildKeyEvent0101()
{
    auto keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyEvent->SetDeviceId(DEFAULT_DEVICE_ID);

    KeyEvent::KeyItem key1 {};
    key1.SetPressed(true);
    key1.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    key1.SetDeviceId(DEFAULT_DEVICE_ID);
    keyEvent->AddPressedKeyItems(key1);
    return keyEvent;
}

/**
 * @tc.name: LocalHotKey_001
 * @tc.desc: No interception of local hot kyes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerInterceptorTest, LocalHotKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyCode = KeyEvent::KEYCODE_UNKNOWN;
    auto interceptorId = InputManager::GetInstance()->AddInterceptor(
        [&keyCode](std::shared_ptr<KeyEvent> keyEvent) {
            CHKPV(keyEvent);
            keyCode = keyEvent->GetKeyCode();
        });
    EXPECT_TRUE(IsValidHandlerId(interceptorId));
    if (IsValidHandlerId(interceptorId)) {
        auto keyEvent = BuildKeyEvent0101();
        ASSERT_NE(keyEvent, nullptr);
        InputManager::GetInstance()->SimulateInputEvent(keyEvent);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        EXPECT_EQ(keyCode, KeyEvent::KEYCODE_CTRL_LEFT);

        KeyEvent::KeyItem key1 {};
        key1.SetPressed(true);
        key1.SetKeyCode(KeyEvent::KEYCODE_VOLUME_MUTE);
        key1.SetDeviceId(DEFAULT_DEVICE_ID);
        keyEvent->AddPressedKeyItems(key1);

        InputManager::GetInstance()->SimulateInputEvent(keyEvent);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
        EXPECT_EQ(keyCode, KeyEvent::KEYCODE_CTRL_LEFT);

        InputManager::GetInstance()->RemoveInterceptor(interceptorId);
    }
}

#endif // OHOS_BUILD_ENABLE_KEYBOARD
} // namespace MMI
} // namespace OHOS
