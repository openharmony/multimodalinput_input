/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "event_interceptor_handler.h"
#include "key_shortcut_manager.h"
#include "mmi_log.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t UID_ROOT { 0 };
constexpr size_t TWO_ITEMS { 2 };
const std::string PROGRAM_NAME = "uds_sesion_test";
int32_t g_moduleType = 3;
int32_t g_pid = 0;
int32_t g_writeFd = -1;
} // namespace

struct InputEventHandlerMock : public IInputEventHandler {
    InputEventHandlerMock() = default;
    virtual ~InputEventHandlerMock() = default;

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override
    {
        auto event = KeyEvent::Clone(keyEvent);
        if (event != nullptr) {
            events_.push_back(event);
        }
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent>) override {}
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent>) override {}
#endif // OHOS_BUILD_ENABLE_TOUCH

    std::vector<std::shared_ptr<KeyEvent>> events_;
};

class EventInterceptorHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: HandleKeyEvent_001
 * @tc.desc: Test EventInterceptorHandler::HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, HandleKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_A,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL,
        }, LocalHotKeyAction::COPY);

    auto event = KeyEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetKeyCode(KeyEvent::KEYCODE_A);
    event->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyEvent::KeyItem key1 {};
    key1.SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    key1.SetPressed(true);
    event->AddPressedKeyItems(key1);

    KeyEvent::KeyItem key2 {};
    key2.SetKeyCode(KeyEvent::KEYCODE_A);
    key2.SetPressed(true);
    event->AddPressedKeyItems(key2);

    auto eventHandler = std::make_shared<InputEventHandlerMock>();
    EventInterceptorHandler handler;
    handler.SetNext(eventHandler);
    handler.HandleKeyEvent(event);

    EXPECT_EQ(eventHandler->events_.size(), TWO_ITEMS);
    if (!eventHandler->events_.empty()) {
        auto event = eventHandler->events_.front();
        ASSERT_NE(event, nullptr);
        EXPECT_EQ(event->GetKeyCode(), KeyEvent::KEYCODE_CTRL_LEFT);
        EXPECT_EQ(event->GetKeyAction(), KeyEvent::KEY_ACTION_DOWN);
    }
    auto iter = handler.localHotKeyHandler_.consumedKeys_.find(KeyEvent::KEYCODE_CTRL_LEFT);
    EXPECT_NE(iter, handler.localHotKeyHandler_.consumedKeys_.end());
    if (iter != handler.localHotKeyHandler_.consumedKeys_.end()) {
        EXPECT_EQ(iter->second, LocalHotKeyAction::OVER);
    }
}

/**
 * @tc.name: HandleKeyEvent_002
 * @tc.desc: Test LocalHotKeyHandler::IsFirstPressed with various scenarios
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, HandleKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LocalHotKeyHandler handler;

    EXPECT_FALSE(handler.IsFirstPressed(nullptr));

    auto event = KeyEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetKeyCode(KeyEvent::KEYCODE_F);
    event->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    EXPECT_TRUE(handler.IsFirstPressed(event));

    handler.consumedKeys_.insert_or_assign(KeyEvent::KEYCODE_F, LocalHotKeyAction::INTERCEPT);
    EXPECT_FALSE(handler.IsFirstPressed(event));

    event->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    EXPECT_FALSE(handler.IsFirstPressed(event));
}

/**
 * @tc.name: HandleKeyEvent_003
 * @tc.desc: Test LocalHotKeyHandler::RectifyProcessed with various scenarios
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, HandleKeyEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LocalHotKeyHandler handler;

    handler.RectifyProcessed(nullptr, LocalHotKeyAction::INTERCEPT);

    auto event = KeyEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetKeyCode(KeyEvent::KEYCODE_F);

    event->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    handler.RectifyProcessed(event, LocalHotKeyAction::INTERCEPT);
    auto iter = handler.consumedKeys_.find(KeyEvent::KEYCODE_F);
    EXPECT_EQ(iter, handler.consumedKeys_.end());

    event->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    handler.RectifyProcessed(event, LocalHotKeyAction::COPY);
    iter = handler.consumedKeys_.find(KeyEvent::KEYCODE_F);
    EXPECT_NE(iter, handler.consumedKeys_.end());
    EXPECT_EQ(iter->second, LocalHotKeyAction::COPY);

    handler.RectifyProcessed(event, LocalHotKeyAction::OVER);
    iter = handler.consumedKeys_.find(KeyEvent::KEYCODE_F);
    EXPECT_NE(iter, handler.consumedKeys_.end());
    EXPECT_EQ(iter->second, LocalHotKeyAction::OVER);
}

/**
 * @tc.name: HandleKeyEvent_004
 * @tc.desc: Test EventInterceptorHandler::HandleKeyEvent when key is first pressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, HandleKeyEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler eventHandler;
    auto mockHandler = std::make_shared<InputEventHandlerMock>();
    eventHandler.SetNext(mockHandler);

    auto event = KeyEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetKeyCode(KeyEvent::KEYCODE_G);
    event->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    KeyEvent::KeyItem keyItem;
    keyItem.SetKeyCode(KeyEvent::KEYCODE_G);
    keyItem.SetPressed(true);
    event->AddPressedKeyItems(keyItem);

    EXPECT_TRUE(eventHandler.localHotKeyHandler_.IsFirstPressed(event));

    LocalHotKeyHandler::steward_.localHotKeys_.clear();

    eventHandler.HandleKeyEvent(event);

    auto iter = eventHandler.localHotKeyHandler_.consumedKeys_.find(KeyEvent::KEYCODE_G);
    EXPECT_NE(iter, eventHandler.localHotKeyHandler_.consumedKeys_.end());
    EXPECT_EQ(iter->second, LocalHotKeyAction::OVER);
}

/**
 * @tc.name: HandleKeyEvent_005
 * @tc.desc: Test EventInterceptorHandler::HandleKeyEvent when key is not first pressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, HandleKeyEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler eventHandler;
    auto mockHandler = std::make_shared<InputEventHandlerMock>();
    eventHandler.SetNext(mockHandler);

    auto event = KeyEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetKeyCode(KeyEvent::KEYCODE_H);
    event->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    KeyEvent::KeyItem keyItem;
    keyItem.SetKeyCode(KeyEvent::KEYCODE_H);
    keyItem.SetPressed(true);
    event->AddPressedKeyItems(keyItem);

    eventHandler.localHotKeyHandler_.consumedKeys_.insert_or_assign(KeyEvent::KEYCODE_H, LocalHotKeyAction::INTERCEPT);
    EXPECT_FALSE(eventHandler.localHotKeyHandler_.IsFirstPressed(event));

    LocalHotKeyHandler::steward_.localHotKeys_.clear();

    eventHandler.HandleKeyEvent(event);

    auto iter = eventHandler.localHotKeyHandler_.consumedKeys_.find(KeyEvent::KEYCODE_H);
    EXPECT_NE(iter, eventHandler.localHotKeyHandler_.consumedKeys_.end());
    EXPECT_NE(iter->second, LocalHotKeyAction::OVER);
}

/**
 * @tc.name: HandleKeyEvent_006
 * @tc.desc: Test HandleKeyEvent_003::RectifyProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, HandleKeyEvent_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LocalHotKeyHandler handler;

    handler.RectifyProcessed(nullptr, LocalHotKeyAction::INTERCEPT);

    auto event = KeyEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetKeyCode(KeyEvent::KEYCODE_E);

    event->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    handler.RectifyProcessed(event, LocalHotKeyAction::INTERCEPT);

    auto iter = handler.consumedKeys_.find(KeyEvent::KEYCODE_E);
    EXPECT_EQ(iter, handler.consumedKeys_.end());
}

/**
 * @tc.name: HandleKeyEvent_007
 * @tc.desc: Test EventInterceptorHandler::HandleKeyEvent when local hotkey not matched but isFirstPressed,
 *           verify RectifyProcessed is called with LocalHotKeyAction::OVER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, HandleKeyEvent_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    LocalHotKeyHandler::steward_.localHotKeys_.clear();
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_TAB,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_ALT,
        }, LocalHotKeyAction::INTERCEPT);
        
    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_DEL,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_ALT,
        }, LocalHotKeyAction::INTERCEPT);

    auto event = KeyEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetKeyCode(KeyEvent::KEYCODE_A);
    event->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyEvent::KeyItem keyItem {};
    keyItem.SetKeyCode(KeyEvent::KEYCODE_A);
    keyItem.SetPressed(true);
    event->AddPressedKeyItems(keyItem);

    auto eventHandler = std::make_shared<InputEventHandlerMock>();
    EventInterceptorHandler handler;
    handler.SetNext(eventHandler);

    handler.HandleKeyEvent(event);

    auto iter = handler.localHotKeyHandler_.consumedKeys_.find(KeyEvent::KEYCODE_A);
    EXPECT_NE(iter, handler.localHotKeyHandler_.consumedKeys_.end());
    if (iter != handler.localHotKeyHandler_.consumedKeys_.end()) {
        EXPECT_EQ(iter->second, LocalHotKeyAction::OVER);
    }

    EXPECT_FALSE(eventHandler->events_.empty());
}

/**
 * @tc.name: HandleKeyEvent_008
 * @tc.desc: Test EventInterceptorHandler::HandleKeyEvent when key event is intercepted,
 *           then re-inject the same key to verify down/up matching in interceptor and local handler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, HandleKeyEvent_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    LocalHotKeyHandler::steward_.localHotKeys_.clear();

    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_TAB,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_ALT,
        }, LocalHotKeyAction::INTERCEPT);

    LocalHotKeyHandler::steward_.localHotKeys_.emplace(
        LocalHotKey {
            .keyCode_ = KeyEvent::KEYCODE_DEL,
            .modifiers_ = KeyShortcutManager::SHORTCUT_MODIFIER_CTRL | KeyShortcutManager::SHORTCUT_MODIFIER_ALT,
        }, LocalHotKeyAction::INTERCEPT);

    auto eventHandler = std::make_shared<InputEventHandlerMock>();
    EventInterceptorHandler handler;
    handler.SetNext(eventHandler);

    auto altTabDownEvent = KeyEvent::Create();
    ASSERT_NE(altTabDownEvent, nullptr);
    altTabDownEvent->SetKeyCode(KeyEvent::KEYCODE_TAB);
    altTabDownEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyEvent::KeyItem altKeyItem {};
    altKeyItem.SetKeyCode(KeyEvent::KEYCODE_ALT_LEFT);
    altKeyItem.SetPressed(true);
    altTabDownEvent->AddPressedKeyItems(altKeyItem);
    
    KeyEvent::KeyItem tabKeyItem {};
    tabKeyItem.SetKeyCode(KeyEvent::KEYCODE_TAB);
    tabKeyItem.SetPressed(true);
    altTabDownEvent->AddPressedKeyItems(tabKeyItem);

    handler.HandleKeyEvent(altTabDownEvent);

    auto iterTab = handler.localHotKeyHandler_.consumedKeys_.find(KeyEvent::KEYCODE_TAB);
    EXPECT_NE(iterTab, handler.localHotKeyHandler_.consumedKeys_.end());
    if (iterTab != handler.localHotKeyHandler_.consumedKeys_.end()) {
        EXPECT_EQ(iterTab->second, LocalHotKeyAction::OVER);
    }

    auto altTabUpEvent = KeyEvent::Create();
    ASSERT_NE(altTabUpEvent, nullptr);
    altTabUpEvent->SetKeyCode(KeyEvent::KEYCODE_TAB);
    altTabUpEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);

    KeyEvent::KeyItem altKeyUpItem {};
    altKeyUpItem.SetKeyCode(KeyEvent::KEYCODE_ALT_LEFT);
    altKeyUpItem.SetPressed(false);
    altTabUpEvent->AddPressedKeyItems(altKeyUpItem);

    KeyEvent::KeyItem tabKeyUpItem {};
    tabKeyUpItem.SetKeyCode(KeyEvent::KEYCODE_TAB);
    tabKeyUpItem.SetPressed(false);
    altTabUpEvent->AddPressedKeyItems(tabKeyUpItem);

    handler.HandleKeyEvent(altTabUpEvent);

    iterTab = handler.localHotKeyHandler_.consumedKeys_.find(KeyEvent::KEYCODE_TAB);
    EXPECT_EQ(iterTab, handler.localHotKeyHandler_.consumedKeys_.end());
}

/**
 * @tc.name: EventInterceptorHandler_Test_001
 * @tc.desc: Test the function HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_Test_002
 * @tc.desc: Test the function HandlePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerEvent(pointerEvent));
}

/**
 * @tc.name: EventInterceptorHandler_Test_003
 * @tc.desc: Test the function HandleTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NO_FATAL_FAILURE(handler.HandleTouchEvent(pointerEvent));
}

/**
 * @tc.name: EventInterceptorHandler_Test_004
 * @tc.desc: Test the function OnHandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    EXPECT_FALSE(handler.OnHandleEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_Test_005
 * @tc.desc: Test the function OnHandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    EXPECT_FALSE(handler.OnHandleEvent(pointerEvent));
}

/**
 * @tc.name: EventInterceptorHandler_Test_007
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    std::shared_ptr<KeyEvent> KeyEvent = KeyEvent::Create();
    bool ret = interceptorHandler.HandleEvent(KeyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: EventInterceptorHandler_Test_008
 * @tc.desc: Test the function CheckInputDeviceSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    uint32_t deviceTags = 4;
    bool ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_TRUE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    deviceTags = 2;
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_TRUE(ret);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: EventInterceptorHandler_Test_009
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    bool ret = interceptorHandler.HandleEvent(pointerEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: EventInterceptorHandler_Test_010
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    bool ret = interceptorHandler.HandleEvent(pointerEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: EventInterceptorHandler_AddInterceptor_01
 * @tc.desc: Test AddInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInterceptor_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    
    handlerType = InputHandlerType::NONE;
    eventType = 0;
    priority = 0;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    for (int32_t i = 0; i < 20; i++) {
        interceptorHandler.interceptors_.push_back(interceptorSecond);
    }
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.AddInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_AddInterceptor_02
 * @tc.desc: Test AddInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInterceptor_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    for (int32_t i = 0; i < 20; i++) {
        interceptorHandler.interceptors_.push_back(interceptorFirst);
    }
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.AddInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_AddInterceptor_03
 * @tc.desc: Test AddInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInterceptor_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 1;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    
    handlerType = InputHandlerType::NONE;
    eventType = 0;
    priority = 2;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    interceptorHandler.interceptors_.push_back(interceptorSecond);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.AddInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_AddInterceptor_04
 * @tc.desc: Test AddInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInterceptor_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 1;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    
    handlerType = InputHandlerType::NONE;
    eventType = 0;
    priority = 0;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    interceptorHandler.interceptors_.push_back(interceptorSecond);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.AddInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInterceptor_01
 * @tc.desc: Test RemoveInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInterceptor_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    
    handlerType = InputHandlerType::NONE;
    eventType = 0;
    priority = 0;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    interceptorHandler.interceptors_.push_back(interceptorSecond);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.RemoveInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInterceptor_02
 * @tc.desc: Test RemoveInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInterceptor_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.RemoveInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInterceptor_03
 * @tc.desc: Test RemoveInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInterceptor_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    
    handlerType = InputHandlerType::NONE;
    eventType = 1;
    priority = 2;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    interceptorHandler.interceptors_.push_back(interceptorSecond);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.RemoveInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInterceptor_04
 * @tc.desc: Test RemoveInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInterceptor_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    
    handlerType = InputHandlerType::NONE;
    eventType = 1;
    priority = 0;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    interceptorHandler.interceptors_.push_back(interceptorSecond);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.RemoveInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_OnSessionLost_01
 * @tc.desc: Test OnSessionLost
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_OnSessionLost_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr session = sessionSecond;
    EventInterceptorHandler::SessionHandler interceptor(handlerType, eventType, priority,
        deviceTags, session);
    interceptorHandler.interceptors_.push_back(interceptor);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.OnSessionLost(sessionFirst));
}

/**
 * @tc.name: EventInterceptorHandler_OnSessionLost_02
 * @tc.desc: Test OnSessionLost
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_OnSessionLost_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr session = sessionFirst;
    EventInterceptorHandler::SessionHandler interceptor(handlerType, eventType, priority,
        deviceTags, session);
    interceptorHandler.interceptors_.push_back(interceptor);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.OnSessionLost(sessionFirst));
}

/**
 * @tc.name: EventInterceptorHandler_AddInputHandler_001
 * @tc.desc: Test the function AddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInputHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    SessionPtr sess = nullptr;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_NONE;
    int32_t priority = 2;
    uint32_t deviceTags = 3;
    int32_t ret = handler.AddInputHandler(handlerType, eventType, priority, deviceTags, sess);
    EXPECT_EQ(ret, RET_ERR);
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    ret = handler.AddInputHandler(handlerType, eventType, priority, deviceTags, sess);
    EXPECT_EQ(ret, RET_ERR);
    eventType = HANDLE_EVENT_TYPE_KEY;
    ret = handler.AddInputHandler(handlerType, eventType, priority, deviceTags, sess);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInputHandler_001
 * @tc.desc: Test the function RemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInputHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 1;
    int32_t priority = 2;
    uint32_t deviceTags = 1;
    SessionPtr session = nullptr;
    ASSERT_NO_FATAL_FAILURE(handler.RemoveInputHandler(handlerType, eventType, priority, deviceTags, session));
    session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    ASSERT_NO_FATAL_FAILURE(handler.RemoveInputHandler(handlerType, eventType, priority, deviceTags, session));
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInputHandler_002
 * @tc.desc: Test the function RemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInputHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 1;
    int32_t priority = 2;
    uint32_t deviceTags = 1;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    ASSERT_NO_FATAL_FAILURE(handler.RemoveInputHandler(handlerType, eventType, priority, deviceTags, session));
    handlerType = InputHandlerType::MONITOR;
    ASSERT_NO_FATAL_FAILURE(handler.RemoveInputHandler(handlerType, eventType, priority, deviceTags, session));
}

/**
 * @tc.name: EventInterceptorHandler_InitSessionLostCallback_001
 * @tc.desc: Test the function InitSessionLostCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_InitSessionLostCallback_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    handler.sessionLostCallbackInitialized_ = true;
    ASSERT_NO_FATAL_FAILURE(handler.InitSessionLostCallback());
    handler.sessionLostCallbackInitialized_ = false;
    ASSERT_NO_FATAL_FAILURE(handler.InitSessionLostCallback());
}

/**
 * @tc.name: EventInterceptorHandler_SendToClient_keyEvent_001
 * @tc.desc: Test the function SendToClient,parameter is keyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_SendToClient_keyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 1;
    uint32_t deviceTags = 0x01;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler sessionHandler { handlerType, eventType, priority, deviceTags, session };
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    ASSERT_NO_FATAL_FAILURE(sessionHandler.SendToClient(keyEvent));
    keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(sessionHandler.SendToClient(keyEvent));
}

/**
 * @tc.name: EventInterceptorHandler_SendToClient_pointerEvent_001
 * @tc.desc: Test the function SendToClient,parameter is pointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_SendToClient_pointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 1;
    uint32_t deviceTags = 0x01;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler sessionHandler { handlerType, eventType, priority, deviceTags, session };
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    ASSERT_NO_FATAL_FAILURE(sessionHandler.SendToClient(pointerEvent));
    pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(sessionHandler.SendToClient(pointerEvent));
}

/**
 * @tc.name: EventInterceptorHandler_Test_011
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    // SessionPtr session = std::make_shared<SessionPtr>();
    EventInterceptorHandler::SessionHandler sessionHandler(handlerType, eventType, priority, deviceTags, nullptr);
    interceptorHandler.interceptors_.push_back(sessionHandler);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    bool ret = interceptorHandler.HandleEvent(pointerEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TouchPadKnuckleDoubleClickHandle_Test_001
 * @tc.desc: Test the function TouchPadKnuckleDoubleClickHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, TouchPadKnuckleDoubleClickHandle_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    event->SetKeyAction(KNUCKLE_1F_DOUBLE_CLICK); // or KNUCKLE_2F_DOUBLE_CLICK
    EventInterceptorHandler handler;
    handler.nextHandler_ = std::make_shared<EventInterceptorHandler>();
    bool result = handler.TouchPadKnuckleDoubleClickHandle(event);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TouchPadKnuckleDoubleClickHandle_Test_002
 * @tc.desc: Test the function TouchPadKnuckleDoubleClickHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, TouchPadKnuckleDoubleClickHandle_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    int32_t keyAction = 123;
    event->SetKeyAction(keyAction); // Not a double click action
    EventInterceptorHandler handler;
    bool result = handler.TouchPadKnuckleDoubleClickHandle(event);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TouchPadKnuckleDoubleClickHandle_Test_003
 * @tc.desc: Test the function TouchPadKnuckleDoubleClickHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, TouchPadKnuckleDoubleClickHandle_Test_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    event->SetKeyAction(KNUCKLE_2F_DOUBLE_CLICK); // or KNUCKLE_2F_DOUBLE_CLICK
    EventInterceptorHandler handler;
    handler.nextHandler_ = std::make_shared<EventInterceptorHandler>();
    bool result = handler.TouchPadKnuckleDoubleClickHandle(event);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: EventInterceptorHandler_Test_0011
 * @tc.desc: Test the function HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    event->SetKeyAction(KNUCKLE_2F_DOUBLE_CLICK);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_Test_0018
 * @tc.desc: Test the function TouchPadKnuckleDoubleClickHandle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0018, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    int32_t keyAction = 123;
    event->SetKeyAction(keyAction); // or KNUCKLE_2F_DOUBLE_CLICK
    EventInterceptorHandler handler;
    handler.nextHandler_ = std::make_shared<EventInterceptorHandler>();
    ASSERT_NO_FATAL_FAILURE(handler.TouchPadKnuckleDoubleClickHandle(event));
}

/**
 * @tc.name: EventInterceptorHandler_Test_0019
 * @tc.desc: Test the function HandlePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0019, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    auto InputEvent = InputEvent::Create();
    ASSERT_NE(InputEvent, nullptr);
    InputEvent->ClearFlag();
    uint32_t flag = 1;
    InputEvent->AddFlag(flag);
    EventInterceptorHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.HandlePointerEvent(pointerEvent));
}

static uint32_t TestCapabilityToTags(InputDeviceCapability capability)
{
    return static_cast<uint32_t>((1 << capability) - (capability / INPUT_DEV_CAP_MAX));
}

/**
 * @tc.name: EventInterceptorHandler_Test_0020
 * @tc.desc: Test the function CheckInputDeviceSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0020, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    uint32_t deviceTags = TestCapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_TOUCH);
    bool ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_EQ(ret, true);
    deviceTags = TestCapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_TABLET_TOOL);
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_EQ(ret, true);
    deviceTags = 0;
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_EQ(ret, false);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    deviceTags = TestCapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_POINTER);
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_EQ(ret, true);
    deviceTags = TestCapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_TOUCH);
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_EQ(ret, false);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    deviceTags = TestCapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_POINTER);
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_EQ(ret, true);
    deviceTags = TestCapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_TOUCH);
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_EQ(ret, false);

    pointerEvent->SetSourceType(0);
    deviceTags = TestCapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_POINTER);
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_EQ(ret, false);
    deviceTags = TestCapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_TOUCH);
    ret = EventInterceptorHandler::CheckInputDeviceSource(pointerEvent, deviceTags);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: EventInterceptorHandler_Test_0021
 * @tc.desc: Test the function HandleEvent when ENABLE_KEYBOARD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0021, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_NONE;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptor(handlerType, eventType, priority,
        deviceTags, session);
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    interceptorHandler.interceptors_.push_back(interceptor);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    bool ret = interceptorHandler.HandleEvent(keyEvent);
    EXPECT_EQ(ret, false);

    KeyEvent::KeyItem item;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    item.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    item.SetDownTime(200);
    keyEvent->AddKeyItem(item);
    ret = interceptorHandler.HandleEvent(keyEvent);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: EventInterceptorHandler_Test_0022
 * @tc.desc: Test the function HandleEvent when ENABLE_KEYBOARD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0022, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    int32_t priority = 0;
    uint32_t deviceTags = INPUT_DEV_CAP_KEYBOARD;
    EventInterceptorHandler::SessionHandler interceptor(handlerType, eventType, priority,
        deviceTags, nullptr);
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    interceptorHandler.interceptors_.push_back(interceptor);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyEvent::KeyItem item;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    item.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    item.SetDownTime(200);
    keyEvent->AddKeyItem(item);

    bool ret = interceptorHandler.HandleEvent(keyEvent);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: EventInterceptorHandler_Test_0023
 * @tc.desc: Test the function HandleEvent when ENABLE_KEYBOARD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0023, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    int32_t priority = 0;
    uint32_t deviceTags = INPUT_DEV_CAP_TOUCH;
    EventInterceptorHandler::SessionHandler interceptor(handlerType, eventType, priority,
        deviceTags, nullptr);
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    interceptorHandler.interceptors_.push_back(interceptor);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyEvent::KeyItem item;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    item.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    item.SetDownTime(200);
    keyEvent->AddKeyItem(item);

    bool ret = interceptorHandler.HandleEvent(keyEvent);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: EventInterceptorHandler_Test_0024
 * @tc.desc: Test the function HandleEvent when ENABLE_KEYBOARD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0024, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    int32_t priority = 0;
    uint32_t deviceTags = INPUT_DEV_CAP_KEYBOARD;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptor(handlerType, eventType, priority,
        deviceTags, session);
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    interceptorHandler.interceptors_.push_back(interceptor);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyEvent::KeyItem item;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    item.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    item.SetDownTime(200);
    keyEvent->AddKeyItem(item);

    ASSERT_NO_FATAL_FAILURE(interceptorHandler.HandleEvent(keyEvent));
}

/**
 * @tc.name: EventInterceptorHandler_Test_0025
 * @tc.desc: Test the function HandleEvent when ENABLE_KEYBOARD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0025, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_NONE;
    int32_t priority = 0;
    uint32_t deviceTags = INPUT_DEV_CAP_KEYBOARD;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptor(handlerType, eventType, priority,
        deviceTags, session);
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    interceptorHandler.interceptors_.push_back(interceptor);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    KeyEvent::KeyItem item;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    item.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    item.SetDownTime(200);
    keyEvent->AddKeyItem(item);

    bool ret = interceptorHandler.HandleEvent(keyEvent);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: EventInterceptorHandler_Test_0026
 * @tc.desc: Test the function HandleEvent when ENABLE_KEYBOARD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0026, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_NONE;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    bool ret = interceptorHandler.HandleEvent(pointerEvent);
    EXPECT_EQ(ret, false);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    ret = interceptorHandler.HandleEvent(pointerEvent);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: EventInterceptorHandler_Test_0027
 * @tc.desc: Test the function HandleEvent when ENABLE_KEYBOARD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0027, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_NONE;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, nullptr);
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    bool ret = interceptorHandler.HandleEvent(pointerEvent);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: EventInterceptorHandler_Test_0028
 * @tc.desc: Test the function HandleEvent when ENABLE_KEYBOARD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_Test_0028, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_POINTER;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    bool ret = interceptorHandler.HandleEvent(pointerEvent);
    EXPECT_EQ(ret, false);
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
/**
 * @tc.name: EventInterceptorHandler_HandleKeyEvent_002
 * @tc.desc: Test the function HandleKeyEvent WhenDoubleClickDetected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_HandleKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    handler.nextHandler_ = std::make_shared<EventInterceptorHandler>();
    event->SetKeyAction(KNUCKLE_2F_DOUBLE_CLICK);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_HandleKeyEvent_003
 * @tc.desc: Test the function HandleKeyEvent WhenDoubleClickDetected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_HandleKeyEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    handler.nextHandler_ = std::make_shared<EventInterceptorHandler>();
    event->SetKeyAction(KNUCKLE_1F_DOUBLE_CLICK);
    ASSERT_NO_FATAL_FAILURE(handler.HandleKeyEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_OnHandleEvent_001
 * @tc.desc: Test the function OnHandleEvent_001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_OnHandleEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    event->bitwise_ = 0x00000001;
    EXPECT_FALSE(handler.OnHandleEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_OnHandleEvent_002
 * @tc.desc: Test the function OnHandleEvent_002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_OnHandleEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    event->bitwise_ = 0x00000000;
    EXPECT_FALSE(handler.OnHandleEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_OnHandleEvent_003
 * @tc.desc: Test the function OnHandleEvent_003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_OnHandleEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    event->bitwise_ = 0x00000001;
    EXPECT_FALSE(handler.OnHandleEvent(event));
}

/**
 * @tc.name: EventInterceptorHandler_OnHandleEvent_004
 * @tc.desc: Test the function OnHandleEvent_004
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_OnHandleEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    event->bitwise_ = 0x0000000;
    EXPECT_FALSE(handler.OnHandleEvent(event));
}

#endif // OHOS_BUILD_ENABLE_KEYBOARD

/**
 * @tc.name: EventInterceptorHandler_InitSessionLostCallback_002
 * @tc.desc: Test the function InitSessionLostCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_InitSessionLostCallback_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.InitSessionLostCallback());
}

/**
 * @tc.name: EventInterceptorHandler_InitSessionLostCallback_003
 * @tc.desc: Test the function InitSessionLostCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_InitSessionLostCallback_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler handler;
    handler.sessionLostCallbackInitialized_ = false;
    EXPECT_FALSE(handler.sessionLostCallbackInitialized_);
    ASSERT_NO_FATAL_FAILURE(handler.InitSessionLostCallback());
}

/**
 * @tc.name: EventInterceptorHandler_AddInterceptor_05
 * @tc.desc: Test AddInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInterceptor_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 0;
    int32_t priority = 1;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    handlerType = InputHandlerType::INTERCEPTOR;
    eventType = 0;
    priority = 2;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    for (int32_t i = 0; i < MAX_N_INPUT_INTERCEPTORS; i++) {
        interceptorHandler.interceptors_.push_back(interceptorSecond);
    }
    int32_t result = interceptorHandler.AddInterceptor(interceptorFirst);
    EXPECT_EQ(result, RET_ERR);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.AddInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_AddInterceptor_06
 * @tc.desc: Test AddInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInterceptor_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 0;
    int32_t priority = 1;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    handlerType = InputHandlerType::MONITOR;
    eventType = 0;
    priority = 2;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    for (int32_t i = 0; i < MAX_N_INPUT_INTERCEPTORS; i++) {
        interceptorHandler.interceptors_.push_back(interceptorSecond);
    }
    int32_t result = interceptorHandler.AddInterceptor(interceptorFirst);
    EXPECT_EQ(result, RET_ERR);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.AddInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_AddInterceptor_07
 * @tc.desc: Test AddInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInterceptor_07, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 0;
    int32_t priority = 1;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    handlerType = InputHandlerType::MONITOR;
    eventType = 0;
    priority = 2;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    for (int32_t i = 0; i < MAX_N_INPUT_INTERCEPTORS - 1; i++) {
        interceptorHandler.interceptors_.push_back(interceptorSecond);
    }
    EXPECT_EQ(interceptorHandler.AddInterceptor(interceptorFirst), RET_OK);
    int32_t result = interceptorHandler.AddInterceptor(interceptorFirst);
    EXPECT_EQ(result, RET_OK);
    uint32_t num = interceptorHandler.interceptors_.size();
    EXPECT_EQ(num, 16);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.AddInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_AddInterceptor_08
 * @tc.desc: Test AddInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInterceptor_08, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 0;
    int32_t priority = 1;
    uint32_t deviceTags = 11;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    handlerType = InputHandlerType::INTERCEPTOR;
    eventType = 5;
    priority = 2;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
        interceptorHandler.interceptors_.push_back(interceptorSecond);
    int32_t result = interceptorHandler.AddInterceptor(interceptorSecond);
    EXPECT_EQ(result, RET_OK);
    uint32_t num = interceptorHandler.interceptors_.size();
    EXPECT_EQ(num, 2);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.AddInterceptor(interceptorSecond));
}

/**
 * @tc.name: EventInterceptorHandler_AddInterceptor_09
 * @tc.desc: Test AddInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInterceptor_09, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 5;
    int32_t priority = 1;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    handlerType = InputHandlerType::NONE;
    eventType = 5;
    priority = 2;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    int32_t result = interceptorHandler.AddInterceptor(interceptorSecond);
    EXPECT_EQ(result, RET_OK);
    uint32_t num = interceptorHandler.interceptors_.size();
    EXPECT_EQ(num, 2);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.AddInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_AddInterceptor_10
 * @tc.desc: Test AddInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInterceptor_10, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 5;
    int32_t priority = 1;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    int32_t result = interceptorHandler.AddInterceptor(interceptorFirst);
    EXPECT_EQ(result, RET_OK);
    uint32_t num = interceptorHandler.interceptors_.size();
    EXPECT_EQ(num, 1);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.AddInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_AddInterceptor_11
 * @tc.desc: Test AddInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInterceptor_11, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 5;
    int32_t priority = 1;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    for (int32_t i = 0; i < MAX_N_INPUT_INTERCEPTORS; i++) {
        interceptorHandler.interceptors_.push_back(interceptorFirst);
    }
    int32_t result = interceptorHandler.AddInterceptor(interceptorFirst);
    EXPECT_EQ(result, RET_OK);
    uint32_t num = interceptorHandler.interceptors_.size();
    EXPECT_EQ(num, MAX_N_INPUT_INTERCEPTORS);
}

/**
 * @tc.name: EventInterceptorHandler_AddInterceptor_12
 * @tc.desc: Test AddInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInterceptor_12, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 5;
    int32_t priority = 20;
    uint32_t deviceTags = 0;
    const std::string programName = "uds_session_test";
    const int32_t moduleType = 1;
    const int32_t writeFd = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(programName, moduleType,
        writeFd, uid, pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    EXPECT_EQ(interceptorHandler.interceptors_.front().priority_, 20);
    int32_t result = interceptorHandler.AddInterceptor(interceptorFirst);
    EXPECT_EQ(result, RET_OK);
    uint32_t num = interceptorHandler.interceptors_.size();
    EXPECT_EQ(num, 1);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.AddInterceptor(interceptorFirst));
}

/**
 * @tc.name: EventInterceptorHandler_AddInterceptor_13
 * @tc.desc: Test AddInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInterceptor_13, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 5;
    int32_t priority = 20;
    uint32_t deviceTags = 0;
    const std::string programName = "uds_session_test";
    const int32_t moduleType = 1;
    const int32_t writeFd = 1;
    const int32_t uid = 2;
    const int32_t pid = 10;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(programName, moduleType,
        writeFd, uid, pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    priority = 30;
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    interceptorHandler.interceptors_.push_back(interceptorSecond);
    priority = 40;
    EventInterceptorHandler::SessionHandler interceptorThird(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    interceptorHandler.interceptors_.push_back(interceptorThird);
    EXPECT_EQ(interceptorHandler.interceptors_.back().priority_, 40);
    int32_t result = interceptorHandler.AddInterceptor(interceptorThird);
    EXPECT_EQ(result, RET_OK);
    uint32_t num = interceptorHandler.interceptors_.size();
    EXPECT_EQ(num, 3);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.AddInterceptor(interceptorThird));
}

/**
 * @tc.name: EventInterceptorHandler_AddInterceptor_14
 * @tc.desc: Test AddInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_AddInterceptor_14, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 5;
    int32_t priority = 20;
    uint32_t deviceTags = 0;
    const std::string programName = "uds_session_test";
    const int32_t moduleType = 1;
    const int32_t writeFd = 1;
    const int32_t uid = 2;
    int32_t pid = 10;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(programName, moduleType,
        writeFd, uid, pid);
    pid = 20;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(programName, moduleType,
        writeFd, uid, pid);
    pid = 30;
    SessionPtr sessionThird = std::make_shared<UDSSession>(programName, moduleType,
        writeFd, uid, pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    priority = 30;
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    interceptorHandler.interceptors_.push_back(interceptorSecond);
    priority = 40;
    EventInterceptorHandler::SessionHandler interceptorThird(handlerType, eventType, priority,
        deviceTags, sessionThird);
    interceptorHandler.interceptors_.push_back(interceptorThird);
    EXPECT_EQ(interceptorHandler.interceptors_.back().priority_, 40);
    int32_t result = interceptorHandler.AddInterceptor(interceptorThird);
    EXPECT_EQ(result, RET_OK);
    uint32_t num = interceptorHandler.interceptors_.size();
    EXPECT_EQ(num, 3);
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInterceptor_05
 * @tc.desc: Test RemoveInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInterceptor_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    handlerType = InputHandlerType::INTERCEPTOR;
    eventType = 0;
    priority = 0;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    interceptorHandler.interceptors_.push_back(interceptorSecond);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.RemoveInterceptor(interceptorFirst));
    EXPECT_FALSE(interceptorHandler.interceptors_.empty());
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.RemoveInterceptor(interceptorSecond));
    EXPECT_TRUE(interceptorHandler.interceptors_.empty());
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInterceptor_06
 * @tc.desc: Test RemoveInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInterceptor_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    interceptorHandler.RemoveInterceptor(interceptorFirst);
    EXPECT_TRUE(interceptorHandler.interceptors_.empty());
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInterceptor_07
 * @tc.desc: Test RemoveInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInterceptor_07, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    handlerType = InputHandlerType::INTERCEPTOR;
    eventType = 1;
    priority = 2;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    interceptorHandler.interceptors_.push_back(interceptorSecond);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.RemoveInterceptor(interceptorFirst));
    interceptorHandler.RemoveInterceptor(interceptorSecond);
    EXPECT_FALSE(interceptorHandler.interceptors_.empty());
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInterceptor_08
 * @tc.desc: Test RemoveInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInterceptor_08, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    handlerType = InputHandlerType::INTERCEPTOR;
    eventType = 1;
    priority = 0;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    interceptorHandler.interceptors_.push_back(interceptorSecond);
    interceptorHandler.RemoveInterceptor(interceptorFirst);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.RemoveInterceptor(interceptorFirst));
    EXPECT_FALSE(interceptorHandler.interceptors_.empty());
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.RemoveInterceptor(interceptorSecond));
    interceptorHandler.RemoveInterceptor(interceptorSecond);
    EXPECT_FALSE(interceptorHandler.interceptors_.empty());
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInterceptor_09
 * @tc.desc: Test RemoveInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInterceptor_09, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    handlerType = InputHandlerType::MONITOR;
    eventType = 0;
    priority = 0;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    interceptorHandler.interceptors_.push_back(interceptorSecond);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.RemoveInterceptor(interceptorSecond));
    EXPECT_TRUE(interceptorHandler.interceptors_.empty());
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInterceptor_10
 * @tc.desc: Test RemoveInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInterceptor_10, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.RemoveInterceptor(interceptorFirst));
    interceptorHandler.RemoveInterceptor(interceptorFirst);
    EXPECT_TRUE(interceptorHandler.interceptors_.empty());
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInterceptor_11
 * @tc.desc: Test RemoveInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInterceptor_11, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    interceptorHandler.interceptors_.push_back(interceptorFirst);
    handlerType = InputHandlerType::MONITOR;
    eventType = 1;
    priority = 20;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    interceptorHandler.interceptors_.push_back(interceptorSecond);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.RemoveInterceptor(interceptorFirst));
    interceptorHandler.RemoveInterceptor(interceptorSecond);
    EXPECT_FALSE(interceptorHandler.interceptors_.empty());
}

/**
 * @tc.name: EventInterceptorHandler_RemoveInterceptor_12
 * @tc.desc: Test RemoveInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerTest, EventInterceptorHandler_RemoveInterceptor_12, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventInterceptorHandler::InterceptorCollection interceptorHandler;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 5;
    int32_t priority = 1;
    uint32_t deviceTags = 0;
    SessionPtr sessionFirst = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorFirst(handlerType, eventType, priority,
        deviceTags, sessionFirst);
    handlerType = InputHandlerType::MONITOR;
    eventType = 5;
    priority = 10;
    deviceTags = 0;
    SessionPtr sessionSecond = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType,
        g_writeFd, UID_ROOT, g_pid);
    EventInterceptorHandler::SessionHandler interceptorSecond(handlerType, eventType, priority,
        deviceTags, sessionSecond);
    interceptorHandler.interceptors_.push_back(interceptorSecond);
    ASSERT_NO_FATAL_FAILURE(interceptorHandler.RemoveInterceptor(interceptorFirst));
    interceptorHandler.RemoveInterceptor(interceptorSecond);
    EXPECT_FALSE(interceptorHandler.interceptors_.empty());
}
} // namespace MMI
} // namespace OH