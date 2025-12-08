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

#include <fstream>

#include <gtest/gtest.h>

#include "config_policy_utils.h"
#include "event_interceptor_handler.h"
#include "i_input_event_handler.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "input_handler_type.h"
#include "key_shortcut_manager.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
using namespace testing::ext;
using namespace testing;

struct InputEventHandlerMock : public IInputEventHandler {
    InputEventHandlerMock() = default;
    virtual ~InputEventHandlerMock() = default;

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override
    {
        auto event = KeyEvent::Clone(keyEvent);
        if (event != nullptr) {
            keyEvents_.push_back(event);
        }
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent>) override {}
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent>) override {}
#endif // OHOS_BUILD_ENABLE_TOUCH

    std::vector<std::shared_ptr<KeyEvent>> keyEvents_;
};

class EventInterceptorTestWithMock : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp();
    void TearDown();
};

void EventInterceptorTestWithMock::SetUp()
{}

void EventInterceptorTestWithMock::TearDown()
{
    InputDeviceManagerMock::ReleaseInstance();
    InputEventHandlerManager::ReleaseInstance();
}

/**
 * @tc.name: HandleKeyEvent_001
 * @tc.desc: Test HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorTestWithMock, HandleKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto inputDev = std::make_shared<InputDevice>();
    inputDev->AddCapability(INPUT_DEV_CAP_KEYBOARD);
    EXPECT_CALL(*INPUT_DEV_MGR, GetInputDevice(_)).WillRepeatedly(Return(inputDev));

    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        }, LocalHotKeyAction::COPY);
    auto interceptorHandler = std::make_shared<EventInterceptorHandler>();
    auto udsServer = std::make_shared<UDSServer>();
    EXPECT_CALL(*InputHandler, GetInterceptorHandler).WillRepeatedly(Return(interceptorHandler));
    EXPECT_CALL(*InputHandler, GetUDSServer).WillRepeatedly(Return(udsServer.get()));

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(nullptr));

    InputHandlerType handlerType { InputHandlerType::NONE };
    HandleEventType eventType { HANDLE_EVENT_TYPE_KEY };
    int32_t priority { 0 };
    uint32_t deviceTags { CapabilityToTags(INPUT_DEV_CAP_KEYBOARD) };
    auto session = std::make_shared<UDSSession>();
    session->SetTokenType(TokenType::TOKEN_SYSTEM_HAP);
    EventInterceptorHandler::SessionHandler interceptor { handlerType, eventType, priority, deviceTags, session };

    auto ret = interceptorHandler->AddInputHandler(
        InputHandlerType::INTERCEPTOR, HANDLE_EVENT_TYPE_KEY, priority, deviceTags, session);
    EXPECT_EQ(ret, RET_OK);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyEvent::KeyItem key1 {};
    key1.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    key1.SetPressed(true);
    keyEvent->AddKeyItem(key1);

    interceptorHandler->HandleKeyEvent(keyEvent);
    const auto &consumedKeys = interceptorHandler->localHotKeyHandler_.consumedKeys_;
    auto iter = consumedKeys.find(keyEvent->GetKeyCode());
    EXPECT_NE(iter, consumedKeys.cend());
    if (iter != consumedKeys.cend()) {
        EXPECT_EQ(iter->second, LocalHotKeyAction::INTERCEPT);
    }
}

/**
 * @tc.name: InterceptorCollection_HandleEvent_001
 * @tc.desc: Test HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorTestWithMock, InterceptorCollection_HandleEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto inputDev = std::make_shared<InputDevice>();
    EXPECT_CALL(*INPUT_DEV_MGR, GetInputDevice(_)).WillRepeatedly(Return(inputDev));

    InputHandlerType handlerType { InputHandlerType::NONE };
    HandleEventType eventType { HANDLE_EVENT_TYPE_NONE };
    int32_t priority { 0 };
    uint32_t deviceTags { 0 };
    EventInterceptorHandler::SessionHandler interceptor { handlerType, eventType, priority, deviceTags, nullptr };

    EventInterceptorHandler::InterceptorCollection interceptors {};
    interceptors.AddInterceptor(interceptor);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyEvent::KeyItem key1 {};
    key1.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    key1.SetPressed(true);
    keyEvent->AddKeyItem(key1);

    EXPECT_FALSE(interceptors.HandleEvent(keyEvent));
}

/**
 * @tc.name: InterceptorCollection_HandleEvent_002
 * @tc.desc: Test HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorTestWithMock, InterceptorCollection_HandleEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto inputDev = std::make_shared<InputDevice>();
    inputDev->AddCapability(INPUT_DEV_CAP_KEYBOARD);
    EXPECT_CALL(*INPUT_DEV_MGR, GetInputDevice(_)).WillRepeatedly(Return(inputDev));

    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        }, LocalHotKeyAction::COPY);
    auto interceptorHandler = std::make_shared<EventInterceptorHandler>();
    EXPECT_CALL(*InputHandler, GetInterceptorHandler).WillRepeatedly(Return(interceptorHandler));

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillRepeatedly(testing::Return(nullptr));

    InputHandlerType handlerType { InputHandlerType::NONE };
    HandleEventType eventType { HANDLE_EVENT_TYPE_KEY };
    int32_t priority { 0 };
    uint32_t deviceTags { CapabilityToTags(INPUT_DEV_CAP_KEYBOARD) };
    auto session = std::make_shared<UDSSession>();
    session->SetTokenType(TokenType::TOKEN_SYSTEM_HAP);
    EventInterceptorHandler::SessionHandler interceptor { handlerType, eventType, priority, deviceTags, session };

    EventInterceptorHandler::InterceptorCollection interceptors {};
    interceptors.AddInterceptor(interceptor);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyEvent::KeyItem key1 {};
    key1.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    key1.SetPressed(true);
    keyEvent->AddKeyItem(key1);

    KeyEvent::KeyItem key2 {};
    key2.SetKeyCode(KeyEvent::KEYCODE_A);
    key2.SetPressed(true);
    keyEvent->AddKeyItem(key2);

    EXPECT_FALSE(interceptors.HandleEvent(keyEvent));
}

/**
 * @tc.name: InterceptorCollection_HandleEvent_003
 * @tc.desc: Test HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorTestWithMock, InterceptorCollection_HandleEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto inputDev = std::make_shared<InputDevice>();
    inputDev->AddCapability(INPUT_DEV_CAP_KEYBOARD);
    EXPECT_CALL(*INPUT_DEV_MGR, GetInputDevice(_)).WillRepeatedly(Return(inputDev));

    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        }, LocalHotKeyAction::COPY);
    auto interceptorHandler = std::make_shared<EventInterceptorHandler>();
    EXPECT_CALL(*InputHandler, GetInterceptorHandler).WillRepeatedly(Return(interceptorHandler));

    InputHandlerType handlerType { InputHandlerType::NONE };
    HandleEventType eventType { HANDLE_EVENT_TYPE_KEY };
    int32_t priority { 0 };
    uint32_t deviceTags { CapabilityToTags(INPUT_DEV_CAP_KEYBOARD) };
    auto session = std::make_shared<UDSSession>();
    session->SetTokenType(TokenType::TOKEN_SYSTEM_HAP);
    EventInterceptorHandler::SessionHandler interceptor { handlerType, eventType, priority, deviceTags, session };

    EventInterceptorHandler::InterceptorCollection interceptors {};
    interceptors.AddInterceptor(interceptor);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyEvent::KeyItem key1 {};
    key1.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    key1.SetPressed(true);
    keyEvent->AddKeyItem(key1);

    EXPECT_TRUE(interceptors.HandleEvent(keyEvent));
}

/**
 * @tc.name: InterceptorCollection_ShouldHandleLocally_001
 * @tc.desc: Test ShouldHandleLocally
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorTestWithMock, InterceptorCollection_ShouldHandleLocally_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType { InputHandlerType::NONE };
    HandleEventType eventType { HANDLE_EVENT_TYPE_NONE };
    int32_t priority { 0 };
    uint32_t deviceTags { 0 };
    EventInterceptorHandler::SessionHandler interceptor { handlerType, eventType, priority, deviceTags, nullptr };

    EventInterceptorHandler::InterceptorCollection interceptors {};
    EXPECT_FALSE(interceptors.ShouldHandleLocally(interceptor, nullptr));
}

/**
 * @tc.name: InterceptorCollection_ShouldHandleLocally_002
 * @tc.desc: Test ShouldHandleLocally
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorTestWithMock, InterceptorCollection_ShouldHandleLocally_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType { InputHandlerType::NONE };
    HandleEventType eventType { HANDLE_EVENT_TYPE_NONE };
    int32_t priority { 0 };
    uint32_t deviceTags { 0 };
    auto session = std::make_shared<UDSSession>();
    session->SetTokenType(TokenType::TOKEN_NATIVE);
    EventInterceptorHandler::SessionHandler interceptor { handlerType, eventType, priority, deviceTags, session };

    EventInterceptorHandler::InterceptorCollection interceptors {};
    EXPECT_FALSE(interceptors.ShouldHandleLocally(interceptor, nullptr));
}

/**
 * @tc.name: InterceptorCollection_ShouldHandleLocally_003
 * @tc.desc: Test ShouldHandleLocally
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorTestWithMock, InterceptorCollection_ShouldHandleLocally_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*InputHandler, GetInterceptorHandler).WillRepeatedly(Return(nullptr));

    InputHandlerType handlerType { InputHandlerType::NONE };
    HandleEventType eventType { HANDLE_EVENT_TYPE_NONE };
    int32_t priority { 0 };
    uint32_t deviceTags { 0 };
    auto session = std::make_shared<UDSSession>();
    session->SetTokenType(TokenType::TOKEN_SYSTEM_HAP);
    EventInterceptorHandler::SessionHandler interceptor { handlerType, eventType, priority, deviceTags, session };

    EventInterceptorHandler::InterceptorCollection interceptors {};
    EXPECT_FALSE(interceptors.ShouldHandleLocally(interceptor, nullptr));
}

/**
 * @tc.name: InterceptorCollection_ShouldHandleLocally_004
 * @tc.desc: Test ShouldHandleLocally
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorTestWithMock, InterceptorCollection_ShouldHandleLocally_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        }, LocalHotKeyAction::COPY);
    auto interceptorHandler = std::make_shared<EventInterceptorHandler>();
    EXPECT_CALL(*InputHandler, GetInterceptorHandler).WillRepeatedly(Return(interceptorHandler));

    InputHandlerType handlerType { InputHandlerType::NONE };
    HandleEventType eventType { HANDLE_EVENT_TYPE_NONE };
    int32_t priority { 0 };
    uint32_t deviceTags { 0 };
    auto session = std::make_shared<UDSSession>();
    session->SetTokenType(TokenType::TOKEN_SYSTEM_HAP);
    EventInterceptorHandler::SessionHandler interceptor { handlerType, eventType, priority, deviceTags, session };

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyEvent::KeyItem key1 {};
    key1.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    key1.SetPressed(true);
    keyEvent->AddKeyItem(key1);

    EventInterceptorHandler::InterceptorCollection interceptors {};
    EXPECT_FALSE(interceptors.ShouldHandleLocally(interceptor, keyEvent));
}

/**
 * @tc.name: InterceptorCollection_ShouldHandleLocally_005
 * @tc.desc: Test ShouldHandleLocally
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorTestWithMock, InterceptorCollection_ShouldHandleLocally_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        }, LocalHotKeyAction::COPY);
    auto interceptorHandler = std::make_shared<EventInterceptorHandler>();
    EXPECT_CALL(*InputHandler, GetInterceptorHandler).WillRepeatedly(Return(interceptorHandler));

    InputHandlerType handlerType { InputHandlerType::NONE };
    HandleEventType eventType { HANDLE_EVENT_TYPE_NONE };
    int32_t priority { 0 };
    uint32_t deviceTags { 0 };
    auto session = std::make_shared<UDSSession>();
    session->SetTokenType(TokenType::TOKEN_SYSTEM_HAP);
    EventInterceptorHandler::SessionHandler interceptor { handlerType, eventType, priority, deviceTags, session };

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyEvent::KeyItem key1 {};
    key1.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    key1.SetPressed(true);
    keyEvent->AddKeyItem(key1);

    KeyEvent::KeyItem key2 {};
    key2.SetKeyCode(KeyEvent::KEYCODE_A);
    key2.SetPressed(true);
    keyEvent->AddKeyItem(key2);

    EventInterceptorHandler::InterceptorCollection interceptors {};
    EXPECT_TRUE(interceptors.ShouldHandleLocally(interceptor, keyEvent));
}
} // namespace MMI
} // namespace OH
