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

#include <gtest/gtest.h>
#include <fstream>

#include "key_subscriber_handler.h"
#include "switch_subscriber_handler.h"
#include "mmi_log.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "KeyCommandHandlerTest" };
} // namespace

class KeySubscriberHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: InputWindowsManagerTest_UnsubscribeKeyEvent_001
 * @tc.desc: Test UnsubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, InputWindowsManagerTest_UnsubscribeKeyEvent_001, TestSize.Level1)
{
    KeySubscriberHandler keySubscriberHandler;
    auto keyEvent = KeyEvent::Create();
    keySubscriberHandler.HandleKeyEvent(keyEvent);
    auto pointerEvent = PointerEvent::Create();
    keySubscriberHandler.HandlePointerEvent(pointerEvent);
    keySubscriberHandler.HandleTouchEvent(pointerEvent);
    keySubscriberHandler.RemoveSubscriberKeyUpTimer(1);
    std::vector<std::string> args = {};
    keySubscriberHandler.Dump(1, args);

    UDSServer udsServer;
    SessionPtr sess = udsServer.GetSessionByPid(1);
    std::shared_ptr<KeyOption> keyOption = nullptr;
    ASSERT_EQ(keySubscriberHandler.SubscribeKeyEvent(sess, -1, keyOption), -1);
    SessionPtr sessPtr = nullptr;
    ASSERT_EQ(keySubscriberHandler.UnsubscribeKeyEvent(sessPtr, -1), -1);
    ASSERT_EQ(keySubscriberHandler.UnsubscribeKeyEvent(sess, 1), -1);
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEnableCombineKey_001
 * @tc.desc: Test IsEnableCombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEnableCombineKey_001, TestSize.Level1)
{
    KeySubscriberHandler keySubscriberHandler;
    keySubscriberHandler.EnableCombineKey(false);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPV(keyEvent);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keySubscriberHandler.HandleKeyEvent(keyEvent);
    ASSERT_EQ(keySubscriberHandler.EnableCombineKey(true), RET_OK);
}

/**
 * @tc.name: KeySubscriberHandlerTest_IsEnableCombineKey_002
 * @tc.desc: Test IsEnableCombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_IsEnableCombineKey_002, TestSize.Level1)
{
    KeySubscriberHandler keySubscriberHandler;
    keySubscriberHandler.EnableCombineKey(false);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    CHKPV(keyEvent);
    KeyEvent::KeyItem item1;
    item1.SetKeyCode(KeyEvent::KEYCODE_META_LEFT);
    keyEvent->AddKeyItem(item1);
    KeyEvent::KeyItem item2;
    item2.SetKeyCode(KeyEvent::KEYCODE_L);
    keyEvent->AddKeyItem(item2);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_L);
    ASSERT_EQ(keySubscriberHandler.EnableCombineKey(true), RET_OK);
}

/**
 * @tc.name: KeySubscriberHandlerTest_EnableCombineKey_001
 * @tc.desc: Test enable combineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeySubscriberHandlerTest, KeySubscriberHandlerTest_EnableCombineKey_001, TestSize.Level1)
{
    KeySubscriberHandler keySubscriberHandler;
    ASSERT_EQ(keySubscriberHandler.EnableCombineKey(true), RET_OK);
}
} // namespace MMI
} // namespace OHOS
