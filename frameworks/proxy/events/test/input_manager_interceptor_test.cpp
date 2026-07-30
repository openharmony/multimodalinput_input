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

#endif // OHOS_BUILD_ENABLE_KEYBOARD
} // namespace MMI
} // namespace OHOS
