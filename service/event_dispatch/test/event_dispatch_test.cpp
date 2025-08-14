/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#define private public
#define protected public

#include <gtest/gtest.h>

#include "anr_manager.h"
#include "define_multimodal.h"
#include "event_dispatch_handler.h"
#include "i_input_windows_manager.h"
#include "input_event_handler.h"

#undef protected
#undef private
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t UID_ROOT { 0 };
static constexpr char PROGRAM_NAME[] { "uds_sesion_test" };
int32_t g_moduleType { 3 };
int32_t g_pid { 0 };
int32_t g_writeFd { -1 };
} // namespace

class EventDispatchTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: EventDispatchTest_SearchWindow_001
 * @tc.desc: Test the function SearchWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_SearchWindow_001, TestSize.Level1)
{
    EventDispatchHandler edh;
    WindowInfo info;
    auto windowInfo1 = std::make_shared<WindowInfo>(info);
    windowInfo1->id = 1;
    auto windowInfo2 = std::make_shared<WindowInfo>(info);
    windowInfo2->id = 2;
    auto windowInfo3 = std::make_shared<WindowInfo>(info);
    windowInfo3->id = 3;
    auto windowInfo4 = std::make_shared<WindowInfo>(info);
    windowInfo4->id = 4;
    std::vector<std::shared_ptr<WindowInfo>> windowList;
    windowList.push_back(windowInfo1);
    windowList.push_back(windowInfo2);
    windowList.push_back(windowInfo3);
    EXPECT_TRUE(edh.SearchWindow(windowList, windowInfo2));
    EXPECT_TRUE(edh.SearchWindow(windowList, windowInfo3));
    EXPECT_FALSE(edh.SearchWindow(windowList, windowInfo4));
}

/**
 * @tc.name: EventDispatchTest_DispatchKeyEvent_01
 * @tc.desc: Test DispatchKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchKeyEvent_01, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    UDSServer udsServer;
    int32_t fd;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    int32_t currentTime = dispatch.currentTime_;
    int32_t eventTime = dispatch.eventTime_;
    int32_t INTERVAL_TIME = 3000;
    currentTime = 6000;
    eventTime = 1000;
    EXPECT_TRUE(currentTime - eventTime > INTERVAL_TIME);
    fd = -1;
    int32_t ret = dispatch.DispatchKeyEvent(fd, udsServer, keyEvent);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: EventDispatchTest_DispatchKeyEvent_02
 * @tc.desc: Test DispatchKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchKeyEvent_02, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    UDSServer udsServer;
    int32_t fd;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    int32_t currentTime = dispatch.currentTime_;
    int32_t eventTime = dispatch.eventTime_;
    int32_t INTERVAL_TIME = 3000;
    currentTime = 2000;
    eventTime = 1000;
    EXPECT_FALSE(currentTime - eventTime > INTERVAL_TIME);
    fd = 1;
    int32_t ret = dispatch.DispatchKeyEvent(fd, udsServer, keyEvent);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: EventDispatchTest_DispatchKeyEvent_03
 * @tc.desc: Test DispatchKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchKeyEvent_03, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    UDSServer udsServer;
    int32_t fd = 2;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto currentTime = GetSysClockTime();
    auto session = udsServer.GetSession(fd);

    bool ret1 = ANRMgr->TriggerANR(ANR_DISPATCH, currentTime, session);
    EXPECT_FALSE(ret1);
    int32_t ret2 = dispatch.DispatchKeyEvent(fd, udsServer, keyEvent);
    EXPECT_EQ(ret2, RET_ERR);
}

/**
 * @tc.name: EventDispatchTest_DispatchKeyEvent_04
 * @tc.desc: Test DispatchKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchKeyEvent_04, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    UDSServer udsServer;
    int32_t fd = -1;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    int32_t currentTime = dispatch.currentTime_;
    int32_t eventTime = dispatch.eventTime_;
    int32_t INTERVAL_TIME = 3000;
    currentTime = 2000;
    eventTime = 1000;
    EXPECT_FALSE(currentTime - eventTime > INTERVAL_TIME);

    auto currentTime1 = GetSysClockTime();
    auto session = udsServer.GetSession(fd);
    bool ret1 = ANRMgr->TriggerANR(ANR_DISPATCH, currentTime1, session);
    EXPECT_FALSE(ret1);
    int32_t ret2 = dispatch.DispatchKeyEvent(fd, udsServer, keyEvent);
    EXPECT_EQ(ret2, RET_ERR);
}

/**
 * @tc.name: EventDispatchTest_DispatchKeyEvent_05
 * @tc.desc: Test DispatchKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchKeyEvent_05, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    UDSServer udsServer;
    int32_t fd = 2;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto currentTime = GetSysClockTime();
    auto session = udsServer.GetSession(fd);
    bool ret1 = ANRMgr->TriggerANR(ANR_DISPATCH, currentTime, session);
    EXPECT_FALSE(ret1);
    NetPacket pkt(MmiMessageId::INVALID);
    EXPECT_FALSE(pkt.ChkRWError());
    EXPECT_FALSE(udsServer.SendMsg(fd, pkt));
    int32_t ret2 = dispatch.DispatchKeyEvent(fd, udsServer, keyEvent);
    EXPECT_EQ(ret2, RET_ERR);
}

/**
 * @tc.name: FilterInvalidPointerItem_01
 * @tc.desc: Test the function FilterInvalidPointerItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, FilterInvalidPointerItem_01, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t fd = 1;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    std::vector<int32_t> pointerIdList;
    pointerEvent->pointerId_ = 3;
    pointerIdList.push_back(pointerEvent->pointerId_);
    pointerEvent->pointerId_ = 5;
    pointerIdList.push_back(pointerEvent->pointerId_);
    EXPECT_TRUE(pointerIdList.size() > 1);

    PointerEvent::PointerItem pointeritem;
    pointeritem.SetWindowX(10);
    pointeritem.SetWindowY(20);
    pointeritem.SetTargetWindowId(2);
    int32_t id = 1;
    EXPECT_FALSE(pointerEvent->GetPointerItem(id, pointeritem));

    pointeritem.targetWindowId_ = 3;
    auto itemPid = WIN_MGR->GetWindowPid(pointeritem.targetWindowId_);
    EXPECT_FALSE(itemPid >= 0);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.FilterInvalidPointerItem(pointerEvent, fd));
}

/**
 * @tc.name: EventDispatchTest_AddFlagToEsc001
 * @tc.desc: Test AddFlagToEsc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_AddFlagToEsc001, TestSize.Level0)
{
    EventDispatchHandler dispatch;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_ESCAPE);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    KeyEvent::KeyItem item;
    keyEvent->AddPressedKeyItems(item);
    EXPECT_EQ(keyEvent->GetKeyItems().size(), 1);

    EXPECT_EQ(dispatch.escToBackFlag_, false);
    dispatch.AddFlagToEsc(keyEvent);
    EXPECT_EQ(dispatch.escToBackFlag_, true);
    int32_t ret1 = keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    EXPECT_EQ(ret1, false);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    dispatch.AddFlagToEsc(keyEvent);
    EXPECT_EQ(dispatch.escToBackFlag_, false);
    int32_t ret2 = keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    EXPECT_EQ(ret2, true);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    dispatch.AddFlagToEsc(keyEvent);
    EXPECT_EQ(dispatch.escToBackFlag_, true);
    int32_t ret3 = keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    EXPECT_EQ(ret3, false);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    dispatch.AddFlagToEsc(keyEvent);
    EXPECT_EQ(dispatch.escToBackFlag_, false);
    int32_t ret4 = keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    EXPECT_EQ(ret4, true);
}

/**
 * @tc.name: EventDispatchTest_AddFlagToEsc002
 * @tc.desc: Test AddFlagToEsc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_AddFlagToEsc002, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    dispatch.AddFlagToEsc(keyEvent);
    EXPECT_EQ(keyEvent, nullptr);

    keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    dispatch.AddFlagToEsc(keyEvent);
    int32_t ret = keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(dispatch.escToBackFlag_, false);

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_ESCAPE);
    dispatch.AddFlagToEsc(keyEvent);
    int32_t ret1 = keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    EXPECT_EQ(ret1, false);
    EXPECT_EQ(dispatch.escToBackFlag_, false);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    EXPECT_TRUE(keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE));
    dispatch.AddFlagToEsc(keyEvent);
    EXPECT_EQ(dispatch.escToBackFlag_, true);
    int32_t ret2 = keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    EXPECT_EQ(ret2, false);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    EXPECT_TRUE(keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE));
    EXPECT_EQ(dispatch.escToBackFlag_, true);
    dispatch.AddFlagToEsc(keyEvent);
    EXPECT_EQ(dispatch.escToBackFlag_, true);
    int32_t ret3 = keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    EXPECT_EQ(ret3, true);
}

/**
 * @tc.name: EventDispatchTest_AddFlagToEsc003
 * @tc.desc: Test AddFlagToEsc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_AddFlagToEsc003, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_ESCAPE);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    KeyEvent::KeyItem item1;
    KeyEvent::KeyItem item2;
    keyEvent->AddPressedKeyItems(item1);
    keyEvent->AddPressedKeyItems(item2);
    EXPECT_EQ(keyEvent->GetKeyItems().size(), 2);
    EXPECT_FALSE(keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE));

    dispatch.escToBackFlag_ = true;
    dispatch.AddFlagToEsc(keyEvent);
    int32_t ret1 = keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    EXPECT_EQ(ret1, false);
    EXPECT_EQ(dispatch.escToBackFlag_, true);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    EXPECT_EQ(keyEvent->GetKeyItems().size(), 2);
    EXPECT_FALSE(keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE));

    dispatch.escToBackFlag_ = true;
    dispatch.AddFlagToEsc(keyEvent);
    int32_t ret2 = keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    EXPECT_EQ(ret2, false);
    EXPECT_EQ(dispatch.escToBackFlag_, true);
}

/**
 * @tc.name: EventDispatchTest_AddFlagToEsc004
 * @tc.desc: Test AddFlagToEsc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_AddFlagToEsc004, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_ESCAPE);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    KeyEvent::KeyItem item;
    keyEvent->AddPressedKeyItems(item);
    EXPECT_EQ(keyEvent->GetKeyItems().size(), 1);
    EXPECT_FALSE(keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE));

    dispatch.escToBackFlag_ = false;
    dispatch.AddFlagToEsc(keyEvent);
    int32_t ret1 = keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    EXPECT_EQ(ret1, false);
    EXPECT_EQ(dispatch.escToBackFlag_, false);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    EXPECT_FALSE(keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE));

    dispatch.escToBackFlag_ = false;
    dispatch.AddFlagToEsc(keyEvent);
    int32_t ret2 = keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    EXPECT_EQ(ret2, false);
    EXPECT_EQ(dispatch.escToBackFlag_, false);
}

/**
 * @tc.name: EventDispatchTest_DispatchKeyEventPid_01
 * @tc.desc: Test DispatchKeyEventPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchKeyEventPid_01, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    UDSServer udsServer;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    std::vector<std::pair<int32_t, TargetInfo>> vecTarget;

    TargetInfo target1;
    target1.privacyMode = SecureFlag::PRIVACY_MODE;
    target1.id = 1;
    target1.agentWindowId = 3;
    vecTarget.push_back(std::make_pair(1, target1));

    TargetInfo target2;
    target2.privacyMode = SecureFlag::PRIVACY_MODE;
    target2.id = 2;
    target2.agentWindowId = 5;
    vecTarget.push_back(std::make_pair(2, target2));

    int32_t ret = dispatch.DispatchKeyEventPid(udsServer, keyEvent);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventDispatchTest_DispatchKeyEventPid_02
 * @tc.desc: Test DispatchKeyEventPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchKeyEventPid_02, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    UDSServer udsServer;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    std::vector<std::pair<int32_t, TargetInfo>> vecTarget;

    TargetInfo target1;
    target1.privacyMode = SecureFlag::DEFAULT_MODE;
    target1.id = 2;
    target1.agentWindowId = 5;
    vecTarget.push_back(std::make_pair(1, target1));

    TargetInfo target2;
    target2.privacyMode = SecureFlag::DEFAULT_MODE;
    target2.id = 3;
    target2.agentWindowId = 6;
    vecTarget.push_back(std::make_pair(2, target2));

    int32_t ret = dispatch.DispatchKeyEventPid(udsServer, keyEvent);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DispatchPointerEventInner_01
 * @tc.desc: Test DispatchKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, DispatchPointerEventInner_01, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    UDSServer udsServer;
    int32_t fd = 2;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    auto currentTime = GetSysClockTime();
    auto session = udsServer.GetSession(fd);
    bool ret = ANRMgr->TriggerANR(ANR_DISPATCH, currentTime, session);
    EXPECT_FALSE(ret);
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_DOWN;
    ASSERT_NO_FATAL_FAILURE(dispatch.DispatchPointerEventInner(pointerEvent, fd));
}

/**
 * @tc.name: DispatchPointerEventInner_02
 * @tc.desc: Test DispatchKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, DispatchPointerEventInner_02, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    UDSServer udsServer;
    int32_t fd = 3;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    auto currentTime = GetSysClockTime();
    auto session = udsServer.GetSession(fd);
    bool ret = ANRMgr->TriggerANR(ANR_DISPATCH, currentTime, session);
    EXPECT_FALSE(ret);
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_UP;
    ASSERT_NO_FATAL_FAILURE(dispatch.DispatchPointerEventInner(pointerEvent, fd));
}

/**
 * @tc.name: DispatchPointerEventInner_03
 * @tc.desc: Test DispatchKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, DispatchPointerEventInner_03, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    UDSServer udsServer;
    int32_t fd = 3;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    auto currentTime = GetSysClockTime();
    auto session = udsServer.GetSession(fd);
    bool ret = ANRMgr->TriggerANR(ANR_DISPATCH, currentTime, session);
    EXPECT_FALSE(ret);
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_DOWN;
    ASSERT_NO_FATAL_FAILURE(dispatch.DispatchPointerEventInner(pointerEvent, fd));
}

/**
 * @tc.name: DispatchPointerEventInner_04
 * @tc.desc: Test DispatchKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, DispatchPointerEventInner_04, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    UDSServer udsServer;
    int32_t fd = 3;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    auto currentTime = GetSysClockTime();
    auto session = udsServer.GetSession(fd);
    bool ret = ANRMgr->TriggerANR(ANR_DISPATCH, currentTime, session);
    EXPECT_FALSE(ret);
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_UP;
    ASSERT_NO_FATAL_FAILURE(dispatch.DispatchPointerEventInner(pointerEvent, fd));
}

/**
 * @tc.name: DispatchPointerEventInner_05
 * @tc.desc: Test DispatchKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, DispatchPointerEventInner_05, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    UDSServer udsServer;
    int32_t fd = 3;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    auto currentTime = GetSysClockTime();
    auto session = udsServer.GetSession(fd);
    bool ret = ANRMgr->TriggerANR(ANR_DISPATCH, currentTime, session);
    EXPECT_FALSE(ret);
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_MOVE;

    NetPacket pkt(MmiMessageId::INVALID);
    EXPECT_FALSE(udsServer.SendMsg(fd, pkt));
    ASSERT_NO_FATAL_FAILURE(dispatch.DispatchPointerEventInner(pointerEvent, fd));
}

/**
 * @tc.name: EventDispatchTest_HandleTouchEvent_001
 * @tc.desc: Test the function HandleTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_HandleTouchEvent_001, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t eventType = 3;
    std::shared_ptr<PointerEvent> sharedPointerEvent = std::make_shared<PointerEvent>(eventType);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandleTouchEvent(sharedPointerEvent));
}

/**
 * @tc.name: EventDispatchTest_FilterInvalidPointerItem_001
 * @tc.desc: Test the function FilterInvalidPointerItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_FilterInvalidPointerItem_001, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t fd = 1;
    int32_t eventType = 3;
    std::shared_ptr<PointerEvent> sharedPointerEvent = std::make_shared<PointerEvent>(eventType);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.FilterInvalidPointerItem(sharedPointerEvent, fd));
}

/**
 * @tc.name: EventDispatchTest_FilterInvalidPointerItem_002
 * @tc.desc: Test the function FilterInvalidPointerItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_FilterInvalidPointerItem_002, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t fd = 1;
    int32_t eventType = 3;
    std::shared_ptr<PointerEvent> sharedPointerEvent = std::make_shared<PointerEvent>(eventType);
    EXPECT_NE(sharedPointerEvent, nullptr);

    std::vector<int32_t> pointerIdList;
    pointerIdList.push_back(1);
    pointerIdList.push_back(2);
    EXPECT_TRUE(pointerIdList.size() > 1);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.FilterInvalidPointerItem(sharedPointerEvent, fd));
}

/**
 * @tc.name: EventDispatchTest_FilterInvalidPointerItem_003
 * @tc.desc: Test the function FilterInvalidPointerItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_FilterInvalidPointerItem_003, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t fd = 1;
    int32_t eventType = 3;
    std::shared_ptr<PointerEvent> sharedPointerEvent = std::make_shared<PointerEvent>(eventType);
    EXPECT_NE(sharedPointerEvent, nullptr);

    std::vector<int32_t> pointerIdList;
    pointerIdList.push_back(1);
    pointerIdList.push_back(2);
    pointerIdList.push_back(3);
    EXPECT_TRUE(pointerIdList.size() > 1);

    int32_t itemPid = 5;
    EXPECT_TRUE(itemPid >= 0);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.FilterInvalidPointerItem(sharedPointerEvent, fd));
}

/**
 * @tc.name: EventDispatchTest_HandleMultiWindowPointerEvent_001
 * @tc.desc: Test HandleMultiWindowPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_HandleMultiWindowPointerEvent_001, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t eventType = 3;
    std::shared_ptr<PointerEvent> point = std::make_shared<PointerEvent>(eventType);
    EXPECT_NE(point, nullptr);

    std::vector<int32_t> windowIds;
    windowIds.push_back(1);
    windowIds.push_back(2);
    windowIds.push_back(3);

    PointerEvent::PointerItem pointerItem;
    pointerItem.SetWindowX(10);
    pointerItem.SetWindowY(20);
    pointerItem.SetTargetWindowId(2);

    std::optional<WindowInfo> windowInfo;
    windowInfo = std::nullopt;
    EXPECT_TRUE(windowInfo == std::nullopt);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandleMultiWindowPointerEvent(point, pointerItem));
}

/**
 * @tc.name: EventDispatchTest_HandleMultiWindowPointerEvent_002
 * @tc.desc: Test HandleMultiWindowPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_HandleMultiWindowPointerEvent_002, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t eventType = 2;
    std::shared_ptr<PointerEvent> point = std::make_shared<PointerEvent>(eventType);
    EXPECT_NE(point, nullptr);

    std::vector<int32_t> windowIds;
    windowIds.push_back(1);
    windowIds.push_back(2);
    windowIds.push_back(3);

    PointerEvent::PointerItem pointerItem;
    pointerItem.SetWindowX(20);
    pointerItem.SetWindowY(30);
    pointerItem.SetTargetWindowId(3);

    std::optional<WindowInfo> windowInfo;
    EXPECT_TRUE(windowInfo->transform.empty());
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandleMultiWindowPointerEvent(point, pointerItem));
}

/**
 * @tc.name: EventDispatchTest_HandleMultiWindowPointerEvent_003
 * @tc.desc: Test HandleMultiWindowPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_HandleMultiWindowPointerEvent_003, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t eventType = 5;
    std::shared_ptr<PointerEvent> point = std::make_shared<PointerEvent>(eventType);
    EXPECT_NE(point, nullptr);
    point->pointerAction_ = PointerEvent::POINTER_ACTION_UP;

    std::vector<int32_t> windowIds;
    windowIds.push_back(1);
    windowIds.push_back(2);
    windowIds.push_back(3);

    PointerEvent::PointerItem pointerItem;
    pointerItem.SetWindowX(30);
    pointerItem.SetWindowY(40);
    pointerItem.SetTargetWindowId(5);

    std::optional<WindowInfo> windowInfo;
    windowInfo = std::nullopt;
    int32_t windowId = 2;
    bool ret = eventdispatchhandler.ReissueEvent(point, windowId, windowInfo);
    EXPECT_FALSE(ret);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandleMultiWindowPointerEvent(point, pointerItem));
}

/**
 * @tc.name: EventDispatchTest_HandleMultiWindowPointerEvent_004
 * @tc.desc: Test HandleMultiWindowPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_HandleMultiWindowPointerEvent_004, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t eventType = 6;
    std::shared_ptr<PointerEvent> point = std::make_shared<PointerEvent>(eventType);
    EXPECT_NE(point, nullptr);
    point->pointerAction_ = PointerEvent::POINTER_ACTION_DOWN;
    point->pointerId_ = 2;

    std::vector<int32_t> windowIds;
    windowIds.push_back(1);
    windowIds.push_back(2);
    windowIds.push_back(3);

    PointerEvent::PointerItem pointerItem;
    pointerItem.SetWindowX(40);
    pointerItem.SetWindowY(50);
    pointerItem.SetTargetWindowId(5);

    std::optional<WindowInfo> windowInfo;
    windowInfo = std::nullopt;
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandleMultiWindowPointerEvent(point, pointerItem));
}

/**
 * @tc.name: EventDispatchTest_HandleMultiWindowPointerEvent_005
 * @tc.desc: Test HandleMultiWindowPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_HandleMultiWindowPointerEvent_005, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t eventType = 6;
    std::shared_ptr<PointerEvent> point = std::make_shared<PointerEvent>(eventType);
    EXPECT_NE(point, nullptr);
    point->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_UP;

    std::vector<int32_t> windowIds;
    windowIds.push_back(1);
    windowIds.push_back(2);
    windowIds.push_back(3);

    PointerEvent::PointerItem pointerItem;
    pointerItem.SetWindowX(45);
    pointerItem.SetWindowY(55);
    pointerItem.SetTargetWindowId(3);

    std::optional<WindowInfo> windowInfo;
    windowInfo = std::nullopt;
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandleMultiWindowPointerEvent(point, pointerItem));
}

/**
 * @tc.name: EventDispatchTest_HandleMultiWindowPointerEvent_006
 * @tc.desc: Test HandleMultiWindowPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_HandleMultiWindowPointerEvent_006, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t eventType = 6;
    std::shared_ptr<PointerEvent> point = std::make_shared<PointerEvent>(eventType);
    EXPECT_NE(point, nullptr);
    point->pointerAction_ = PointerEvent::POINTER_ACTION_CANCEL;

    std::vector<int32_t> windowIds;
    windowIds.push_back(1);
    windowIds.push_back(2);
    windowIds.push_back(3);

    PointerEvent::PointerItem pointerItem;
    pointerItem.SetWindowX(35);
    pointerItem.SetWindowY(50);
    pointerItem.SetTargetWindowId(2);

    std::optional<WindowInfo> windowInfo;
    windowInfo = std::nullopt;
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandleMultiWindowPointerEvent(point, pointerItem));
}

/**
 * @tc.name: EventDispatchTest_NotifyPointerEventToRS_001
 * @tc.desc: Test the function NotifyPointerEventToRS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_NotifyPointerEventToRS_001, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t action = 1;
    std::string name = "ExampleProgram";
    uint32_t processId = 12345;
    int32_t touchCnt = 0;
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.NotifyPointerEventToRS(action, name, processId, touchCnt));
}

/**
 * @tc.name: EventDispatchTest_HandlePointerEventInner_001
 * @tc.desc: Test the function HandlePointerEventInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_HandlePointerEventInner_001, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t eventType = 3;
    PointerEvent* pointerEvent = new PointerEvent(eventType);
    std::shared_ptr<PointerEvent> sharedPointerEvent(pointerEvent);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandlePointerEventInner(sharedPointerEvent));
}

/**
 * @tc.name: EventDispatchTest_HandlePointerEventInner_002
 * @tc.desc: Test the function HandlePointerEventInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_HandlePointerEventInner_002, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t eventType = 3;
    std::shared_ptr<PointerEvent> point = std::make_shared<PointerEvent>(eventType);
    EXPECT_NE(point, nullptr);
    std::vector<int32_t> windowIds;
    windowIds.push_back(1);
    windowIds.push_back(2);
    EXPECT_FALSE(windowIds.empty());
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandlePointerEventInner(point));
}

/**
 * @tc.name: EventDispatchTest_HandlePointerEventInner_003
 * @tc.desc: Test the function HandlePointerEventInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_HandlePointerEventInner_003, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t eventType = 3;
    std::shared_ptr<PointerEvent> pointerEvent = std::make_shared<PointerEvent>(eventType);
    EXPECT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerId(100);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(100);
    pointerEvent->AddPointerItem(pointerItem);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandlePointerEventInner(pointerEvent));
}
 
#ifdef OHOS_BUILD_ENABLE_ONE_HAND_MODE
/**
 * @tc.name: EventDispatchTest_ResetDisplayXY_001
 * @tc.desc: Test the function ResetDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_ResetDisplayXY_001, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t eventType = 3;
    std::shared_ptr<PointerEvent> pointerEvent = std::make_shared<PointerEvent>(eventType);
    EXPECT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerId(100);
    pointerEvent->SetFixedMode(PointerEvent::FixedMode::AUTO);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(100);
    pointerEvent->AddPointerItem(pointerItem);
    eventdispatchhandler.currentXY_.fixed = true;;
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.ResetDisplayXY(pointerEvent));
}
 
/**
 * @tc.name: EventDispatchTest_ResetDisplayXY_002
 * @tc.desc: Test the function ResetDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_ResetDisplayXY_002, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t eventType = 3;
    std::shared_ptr<PointerEvent> pointerEvent = std::make_shared<PointerEvent>(eventType);
    EXPECT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerId(100);
    pointerEvent->SetFixedMode(PointerEvent::FixedMode::AUTO);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(100);
    pointerEvent->AddPointerItem(pointerItem);
    eventdispatchhandler.currentXY_.fixed = false;;
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.ResetDisplayXY(pointerEvent));
}
 
/**
 * @tc.name: EventDispatchTest_ResetDisplayXY_003
 * @tc.desc: Test the function ResetDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_ResetDisplayXY_003, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t eventType = 3;
    std::shared_ptr<PointerEvent> pointerEvent = std::make_shared<PointerEvent>(eventType);
    EXPECT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerId(100);
    pointerEvent->SetFixedMode(PointerEvent::FixedMode::NORMAL);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(100);
    pointerEvent->AddPointerItem(pointerItem);
    eventdispatchhandler.currentXY_.fixed = false;;
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.ResetDisplayXY(pointerEvent));
}
 
/**
 * @tc.name: EventDispatchTest_ResetDisplayXY_004
 * @tc.desc: Test the function ResetDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_ResetDisplayXY_004, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t eventType = 3;
    std::shared_ptr<PointerEvent> pointerEvent = std::make_shared<PointerEvent>(eventType);
    EXPECT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerId(100);
    pointerEvent->SetFixedMode(PointerEvent::FixedMode::NORMAL);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(100);
    pointerEvent->AddPointerItem(pointerItem);
    eventdispatchhandler.currentXY_.fixed = true;;
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.ResetDisplayXY(pointerEvent));
}
 
/**
 * @tc.name: EventDispatchTest_ResetDisplayXY_005
 * @tc.desc: Test the function ResetDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_ResetDisplayXY_005, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t eventType = 3;
    std::shared_ptr<PointerEvent> pointerEvent = std::make_shared<PointerEvent>(eventType);
    EXPECT_NE(pointerEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.ResetDisplayXY(pointerEvent));
}
#endif // OHOS_BUILD_ENABLE_ONE_HAND_MODE

/**
 * @tc.name: EventDispatchTest_DispatchKeyEventPid_001
 * @tc.desc: Test the function DispatchKeyEventPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchKeyEventPid_001, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    UDSServer udsServer;
    int32_t keyevent = 3;
    KeyEvent* keyEvent = new KeyEvent(keyevent);
    std::shared_ptr<KeyEvent> sharedKeyEvent(keyEvent);
    int32_t ret = eventdispatchhandler.DispatchKeyEventPid(udsServer, sharedKeyEvent);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventDispatchTest_AcquireEnableMark
 * @tc.desc: Test Acquire Enable Mark
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_AcquireEnableMark, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    ASSERT_FALSE(dispatch.AcquireEnableMark(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_TRUE(dispatch.AcquireEnableMark(event));
}

/**
 * @tc.name: EventDispatchTest_DispatchPointerEventInner_001
 * @tc.desc: Test Dispatch Pointer Event Inner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchPointerEventInner_001, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    int32_t fd = -1;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    dispatch.eventTime_ = 1000;
    pointerEvent->SetActionTime(5000);
    ASSERT_NO_FATAL_FAILURE(dispatch.DispatchPointerEventInner(pointerEvent, fd));
}

/**
 * @tc.name: EventDispatchTest_DispatchPointerEventInner_002
 * @tc.desc: Test Dispatch Pointer Event Inner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchPointerEventInner_002, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    int32_t fd = -1;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t currentTime = dispatch.currentTime_;
    int32_t eventTime = dispatch.eventTime_;
    int32_t INTERVAL_TIME = 3000;
    currentTime = 6000;
    eventTime = 1000;
    EXPECT_TRUE(currentTime - eventTime > INTERVAL_TIME);
    ASSERT_NO_FATAL_FAILURE(dispatch.DispatchPointerEventInner(pointerEvent, fd));
}

/**
 * @tc.name: EventDispatchTest_DispatchPointerEventInner_003
 * @tc.desc: Test Dispatch Pointer Event Inner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchPointerEventInner_003, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    int32_t fd = 1;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    ASSERT_NE(point, nullptr);
    int32_t pointerAction;
    pointerAction = PointerEvent::POINTER_ACTION_DOWN;
    ASSERT_NO_FATAL_FAILURE(dispatch.DispatchPointerEventInner(point, fd));
}

/**
 * @tc.name: EventDispatchTest_DispatchPointerEventInner_004
 * @tc.desc: Test Dispatch Pointer Event Inner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchPointerEventInner_004, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    SessionPtr sess = nullptr;
    int32_t fd = 1;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    int32_t type = 0;
    int64_t time = 3000;
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    bool ret = ANRMgr->TriggerANR(type, time, sess);
    EXPECT_FALSE(ret);
    ASSERT_NO_FATAL_FAILURE(dispatch.DispatchPointerEventInner(pointerEvent, fd));
}

/**
 * @tc.name: EventDispatchTest_DispatchPointerEventInner_005
 * @tc.desc: Test Dispatch Pointer Event Inner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchPointerEventInner_005, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    SessionPtr sess = nullptr;
    int32_t fd = 1;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    int32_t type = 0;
    int64_t time = 3000;
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    bool ret = ANRMgr->TriggerANR(type, time, sess);
    EXPECT_FALSE(ret);

    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_DOWN;
    ASSERT_NO_FATAL_FAILURE(dispatch.DispatchPointerEventInner(pointerEvent, fd));
}

/**
 * @tc.name: EventDispatchTest_DispatchPointerEventInner_006
 * @tc.desc: Test Dispatch Pointer Event Inner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchPointerEventInner_006, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    SessionPtr sess = nullptr;
    int32_t fd = 2;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    int32_t type = 0;
    int64_t time = 3000;
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    bool ret = ANRMgr->TriggerANR(type, time, sess);
    EXPECT_FALSE(ret);

    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_UP;
    ASSERT_NO_FATAL_FAILURE(dispatch.DispatchPointerEventInner(pointerEvent, fd));
}

/**
 * @tc.name: EventDispatchTest_DispatchPointerEventInner_007
 * @tc.desc: Test Dispatch Pointer Event Inner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchPointerEventInner_007, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    SessionPtr sess = nullptr;
    int32_t fd = 2;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    int32_t type = 0;
    int64_t time = 3000;
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    bool ret = ANRMgr->TriggerANR(type, time, sess);
    EXPECT_FALSE(ret);

    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_DOWN;
    ASSERT_NO_FATAL_FAILURE(dispatch.DispatchPointerEventInner(pointerEvent, fd));
}

/**
 * @tc.name: EventDispatchTest_DispatchPointerEventInner_008
 * @tc.desc: Test Dispatch Pointer Event Inner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchPointerEventInner_008, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    SessionPtr sess = nullptr;
    int32_t fd = 2;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    int32_t type = 0;
    int64_t time = 3000;
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    bool ret = ANRMgr->TriggerANR(type, time, sess);
    EXPECT_FALSE(ret);

    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_UP;
    ASSERT_NO_FATAL_FAILURE(dispatch.DispatchPointerEventInner(pointerEvent, fd));
}

/**
 * @tc.name: EventDispatchTest_DispatchPointerEventInner_009
 * @tc.desc: Test Dispatch Pointer Event Inner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchPointerEventInner_009, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    SessionPtr sess = nullptr;
    int32_t fd = 2;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    int32_t type = 0;
    int64_t time = 3000;
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    bool ret = ANRMgr->TriggerANR(type, time, sess);
    EXPECT_FALSE(ret);

    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_MOVE;
    ASSERT_NO_FATAL_FAILURE(dispatch.DispatchPointerEventInner(pointerEvent, fd));
}

/**
 * @tc.name: EventDispatchTest_DispatchKeyEventPid_002
 * @tc.desc: Test Dispatch Key Event Pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchKeyEventPid_002, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    UDSServer udsServer;
    std::shared_ptr<KeyEvent> KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    dispatch.eventTime_ = 1000;
    KeyEvent->SetActionTime(5000);
    ASSERT_EQ(dispatch.DispatchKeyEventPid(udsServer, KeyEvent), RET_OK);
}

/**
 * @tc.name: EventDispatchTest_DispatchKeyEventPid_003
 * @tc.desc: Test DispatchKeyEventPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchKeyEventPid_003, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    UDSServer udsServer;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t currentTime = dispatch.currentTime_;
    int32_t eventTime = dispatch.eventTime_;
    int32_t INTERVAL_TIME = 3000;
    currentTime = 6000;
    eventTime = 1000;
    EXPECT_TRUE(currentTime - eventTime > INTERVAL_TIME);
    int32_t ret = dispatch.DispatchKeyEventPid(udsServer, keyEvent);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventDispatchTest_DispatchKeyEventPid_004
 * @tc.desc: Test DispatchKeyEventPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchKeyEventPid_004, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    UDSServer udsServer;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    NetPacket pkt(MmiMessageId::INVALID);
    EXPECT_FALSE(pkt.ChkRWError());
    int32_t ret = dispatch.DispatchKeyEventPid(udsServer, keyEvent);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EventDispatchTest_DispatchKeyEventPid_005
 * @tc.desc: Test DispatchKeyEventPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchKeyEventPid_005, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    UDSServer udsServer;
    SessionPtr sess = nullptr;
    std::shared_ptr<KeyEvent> KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    dispatch.eventTime_ = 1000;
    KeyEvent->SetActionTime(2000);

    int32_t type = 0;
    int64_t time = 2000;
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    bool ret = ANRMgr->TriggerANR(type, time, sess);
    EXPECT_FALSE(ret);

    ASSERT_EQ(dispatch.DispatchKeyEventPid(udsServer, KeyEvent), RET_OK);
}

/**
 * @tc.name: EventDispatchTest_ReissueEvent_001
 * @tc.desc: Test ReissueEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_ReissueEvent_001, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    ASSERT_NE(point, nullptr);
    point->pointerAction_ = PointerEvent::POINTER_ACTION_UP;
    int32_t windowId = 100;
    std::optional<WindowInfo> windowInfo = std::nullopt;
    bool result = dispatch.ReissueEvent(point, windowId, windowInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventDispatchTest_ReissueEvent_002
 * @tc.desc: Test ReissueEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_ReissueEvent_002, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    ASSERT_NE(point, nullptr);
    point->pointerAction_ = PointerEvent::POINTER_ACTION_DOWN;
    int32_t windowId = 100;
    std::optional<WindowInfo> windowInfo = std::nullopt;
    bool result = dispatch.ReissueEvent(point, windowId, windowInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventDispatchTest_ReissueEvent_003
 * @tc.desc: Test ReissueEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_ReissueEvent_003, TestSize.Level1)
{
    EventDispatchHandler handler;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    ASSERT_NE(point, nullptr);
    point->pointerAction_ = PointerEvent::POINTER_ACTION_UP;
    int32_t windowId = 1;
    point->pointerId_ = 1;
    point->SetPointerId(point->pointerId_);
    std::optional<WindowInfo> windowInfo = std::nullopt;
    std::shared_ptr<WindowInfo> windowInfo1 = std::make_shared<WindowInfo>();
    windowInfo1->id = 1;
    handler.cancelEventList_[1].push_back(windowInfo1);
    bool result = handler.ReissueEvent(point, windowId, windowInfo);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: EventDispatchTest_ReissueEvent_004
 * @tc.desc: Test ReissueEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_ReissueEvent_004, TestSize.Level1)
{
    EventDispatchHandler handler;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    ASSERT_NE(point, nullptr);
    point->pointerAction_ = PointerEvent::POINTER_ACTION_DOWN;
    int32_t windowId = 1;
    point->pointerId_ = 1;
    point->SetPointerId(point->pointerId_);
    std::optional<WindowInfo> windowInfo = std::nullopt;
    std::shared_ptr<WindowInfo> windowInfo1 = std::make_shared<WindowInfo>();
    windowInfo1->id = 1;
    handler.cancelEventList_[1].push_back(windowInfo1);
    bool result = handler.ReissueEvent(point, windowId, windowInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventDispatchTest_ReissueEvent_005
 * @tc.desc: Test ReissueEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_ReissueEvent_005, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    ASSERT_NE(point, nullptr);
    point->pointerAction_ = PointerEvent::POINTER_ACTION_DOWN;
    int32_t windowId = 100;
    std::optional<WindowInfo> windowInfo = std::make_optional<WindowInfo>();
    ASSERT_NE(windowInfo, std::nullopt);
    point->pointerId_ = 1;
    point->SetPointerId(point->pointerId_);
    std::shared_ptr<WindowInfo> windowInfo1 = std::make_shared<WindowInfo>();
    windowInfo1->id = 1;
    dispatch.cancelEventList_[1].push_back(windowInfo1);
    bool result = dispatch.ReissueEvent(point, windowId, windowInfo);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: EventDispatchTest_ReissueEvent_006
 * @tc.desc: Test ReissueEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_ReissueEvent_006, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    ASSERT_NE(point, nullptr);
    point->pointerAction_ = PointerEvent::POINTER_ACTION_DOWN;
    int32_t windowId = 100;
    std::optional<WindowInfo> windowInfo = std::make_optional<WindowInfo>();
    ASSERT_NE(windowInfo, std::nullopt);
    point->pointerId_ = 5;
    point->SetPointerId(point->pointerId_);
    std::shared_ptr<WindowInfo> windowInfo1 = std::make_shared<WindowInfo>();
    windowInfo1->id = 1;
    dispatch.cancelEventList_[1].push_back(windowInfo1);
    bool result = dispatch.ReissueEvent(point, windowId, windowInfo);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: EventDispatchTest_ReissueEvent_007
 * @tc.desc: Test ReissueEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_ReissueEvent_007, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    ASSERT_NE(point, nullptr);
    point->pointerAction_ = PointerEvent::POINTER_ACTION_UP;
    int32_t windowId = 100;
    std::optional<WindowInfo> windowInfo = std::make_optional<WindowInfo>();
    ASSERT_NE(windowInfo, std::nullopt);
    point->pointerId_ = 1;
    point->SetPointerId(point->pointerId_);
    std::shared_ptr<WindowInfo> windowInfo1 = std::make_shared<WindowInfo>();
    windowInfo1->id = 1;
    dispatch.cancelEventList_[1].push_back(windowInfo1);
    bool result = dispatch.ReissueEvent(point, windowId, windowInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventDispatchTest_ReissueEvent_008
 * @tc.desc: Test ReissueEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_ReissueEvent_008, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    ASSERT_NE(point, nullptr);
    point->pointerAction_ = PointerEvent::POINTER_ACTION_UP;
    int32_t windowId = 100;
    std::optional<WindowInfo> windowInfo = std::make_optional<WindowInfo>();
    ASSERT_NE(windowInfo, std::nullopt);
    point->pointerId_ = 5;
    point->SetPointerId(point->pointerId_);
    std::shared_ptr<WindowInfo> windowInfo1 = std::make_shared<WindowInfo>();
    windowInfo1->id = 1;
    dispatch.cancelEventList_[1].push_back(windowInfo1);
    bool result = dispatch.ReissueEvent(point, windowId, windowInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventDispatchTest_ReissueEvent_009
 * @tc.desc: Test ReissueEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_ReissueEvent_009, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    ASSERT_NE(point, nullptr);
    point->pointerAction_ = PointerEvent::POINTER_ACTION_CANCEL;
    int32_t windowId = 100;
    std::optional<WindowInfo> windowInfo = std::make_optional<WindowInfo>();
    ASSERT_NE(windowInfo, std::nullopt);
    point->pointerId_ = 5;
    point->SetPointerId(point->pointerId_);
    std::shared_ptr<WindowInfo> windowInfo1 = std::make_shared<WindowInfo>();
    windowInfo1->id = 1;
    dispatch.cancelEventList_[1].push_back(windowInfo1);
    bool result = dispatch.ReissueEvent(point, windowId, windowInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventDispatchTest_ReissueEvent_010
 * @tc.desc: Test ReissueEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_ReissueEvent_010, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    ASSERT_NE(point, nullptr);
    point->pointerAction_ = PointerEvent::POINTER_ACTION_CANCEL;
    int32_t windowId = 100;
    std::optional<WindowInfo> windowInfo = std::make_optional<WindowInfo>();
    ASSERT_NE(windowInfo, std::nullopt);
    point->pointerId_ = 1;
    point->SetPointerId(point->pointerId_);
    std::shared_ptr<WindowInfo> windowInfo1 = std::make_shared<WindowInfo>();
    windowInfo1->id = 1;
    dispatch.cancelEventList_[1].push_back(windowInfo1);
    bool result = dispatch.ReissueEvent(point, windowId, windowInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventDispatchTest_ReissueEvent_011
 * @tc.desc: Test ReissueEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_ReissueEvent_011, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    ASSERT_NE(point, nullptr);
    point->pointerAction_ = PointerEvent::POINTER_ACTION_MOVE;
    int32_t windowId = 100;
    std::optional<WindowInfo> windowInfo = std::make_optional<WindowInfo>();
    ASSERT_NE(windowInfo, std::nullopt);
    point->pointerId_ = 1;
    point->SetPointerId(point->pointerId_);
    std::shared_ptr<WindowInfo> windowInfo1 = std::make_shared<WindowInfo>();
    windowInfo1->id = 1;
    dispatch.cancelEventList_[1].push_back(windowInfo1);
    bool result = dispatch.ReissueEvent(point, windowId, windowInfo);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: EventDispatchTest_SearchCancelList_001
 * @tc.desc: Test SearchCancelList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_SearchCancelList_001, TestSize.Level1)
{
    EventDispatchHandler handler;
    int32_t pointerId = 1;
    int32_t windowId = 2;
    std::shared_ptr<WindowInfo> result = handler.SearchCancelList(pointerId, windowId);
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: EventDispatchTest_SearchCancelList_002
 * @tc.desc: Test SearchCancelList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_SearchCancelList_002, TestSize.Level1)
{
    EventDispatchHandler handler;
    int32_t pointerId = 5;
    int32_t windowId = 2;
    std::shared_ptr<WindowInfo> windowInfo1 = std::make_shared<WindowInfo>();
    windowInfo1->id = 1;
    handler.cancelEventList_[1].push_back(windowInfo1);
    std::shared_ptr<WindowInfo> result = handler.SearchCancelList(pointerId, windowId);
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: EventDispatchTest_SearchCancelList_003
 * @tc.desc: Test SearchCancelList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_SearchCancelList_003, TestSize.Level1)
{
    EventDispatchHandler handler;
    int32_t pointerId = 1;
    int32_t windowId = 1;
    std::shared_ptr<WindowInfo> windowInfo1 = std::make_shared<WindowInfo>();
    windowInfo1->id = 1;
    handler.cancelEventList_[1].push_back(windowInfo1);
    std::shared_ptr<WindowInfo> result = handler.SearchCancelList(pointerId, windowId);
    ASSERT_NE(result, nullptr);
}

/**
 * @tc.name: EventDispatchTest_FilterInvalidPointerItem_004
 * @tc.desc: Test the function FilterInvalidPointerItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_FilterInvalidPointerItem_004, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t fd = 1;
    int32_t eventType = 3;
    EXPECT_EQ(InputHandler->udsServer_, nullptr);
    auto udsServer = std::make_unique<UDSServer>();
    InputHandler->udsServer_ = udsServer.get();
    EXPECT_NE(InputHandler->udsServer_, nullptr);
    std::shared_ptr<PointerEvent> sharedPointerEvent = std::make_shared<PointerEvent>(eventType);
    EXPECT_NE(sharedPointerEvent, nullptr);
    std::vector<int32_t> pointerIdList;
    EXPECT_FALSE(pointerIdList.size() > 1);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.FilterInvalidPointerItem(sharedPointerEvent, fd));
    InputHandler->udsServer_ = nullptr;
}

/**
 * @tc.name: EventDispatchTest_FilterInvalidPointerItem_005
 * @tc.desc: Test the function FilterInvalidPointerItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_FilterInvalidPointerItem_005, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    PointerEvent::PointerItem testPointerItem;
    EXPECT_EQ(InputHandler->udsServer_, nullptr);
    auto udsServer = std::make_unique<UDSServer>();
    InputHandler->udsServer_ = udsServer.get();
    EXPECT_NE(InputHandler->udsServer_, nullptr);
    int32_t fd = 1;
    int32_t eventType = 3;
    std::shared_ptr<PointerEvent> event = std::make_shared<PointerEvent>(eventType);
    event->pointers_.push_back(PointerEvent::PointerItem());
    event->pointers_.push_back(PointerEvent::PointerItem());
    std::vector<int32_t> pointerIds = event->GetPointerIds();
    ASSERT_TRUE(pointerIds.size() > 1);
    event->AddPointerItem(testPointerItem);
    int32_t testPointerId = 1;
    testPointerItem.SetPointerId(testPointerId);
    event->AddPointerItem(testPointerItem);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.FilterInvalidPointerItem(event, fd));
    InputHandler->udsServer_ = nullptr;
}

/**
 * @tc.name: EventDispatchTest_FilterInvalidPointerItem_006
 * @tc.desc: Test the function FilterInvalidPointerItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_FilterInvalidPointerItem_006, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    PointerEvent::PointerItem testPointerItem;
    EXPECT_EQ(InputHandler->udsServer_, nullptr);
    auto udsServer = std::make_unique<UDSServer>();
    InputHandler->udsServer_ = udsServer.get();
    EXPECT_NE(InputHandler->udsServer_, nullptr);
    int32_t fd = 1;
    int32_t eventType = 3;
    std::shared_ptr<PointerEvent> event = std::make_shared<PointerEvent>(eventType);
    event->pointers_.push_back(PointerEvent::PointerItem());
    event->pointers_.push_back(PointerEvent::PointerItem());
    std::vector<int32_t> pointerIds = event->GetPointerIds();
    ASSERT_TRUE(pointerIds.size() > 1);
    event->AddPointerItem(testPointerItem);
    int32_t testPointerId = 1;
    testPointerItem.SetPointerId(testPointerId + 1);
    event->AddPointerItem(testPointerItem);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.FilterInvalidPointerItem(event, fd));
    InputHandler->udsServer_ = nullptr;
}

/**
 * @tc.name: EventDispatchTest_FilterInvalidPointerItem_007
 * @tc.desc: Test the function FilterInvalidPointerItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_FilterInvalidPointerItem_007, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t fd = 1;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    EXPECT_EQ(InputHandler->udsServer_, nullptr);
    auto udsServer = std::make_unique<UDSServer>();
    InputHandler->udsServer_ = udsServer.get();
    EXPECT_NE(InputHandler->udsServer_, nullptr);
    PointerEvent::PointerItem testPointerItem;
    testPointerItem.pointerId_ = -1;
    pointerEvent->pointers_.push_back(testPointerItem);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.FilterInvalidPointerItem(pointerEvent, fd));
    testPointerItem.pressed_ = false;
    testPointerItem.SetDisplayX(50);
    testPointerItem.SetDisplayY(100);
    pointerEvent->pointers_.push_back(testPointerItem);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.FilterInvalidPointerItem(pointerEvent, fd));
    InputHandler->udsServer_ = nullptr;
}

/**
 * @tc.name: EventDispatchTest_HandleMultiWindowPointerEvent_007
 * @tc.desc: Test the function HandleMultiWindowPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_HandleMultiWindowPointerEvent_007, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    ASSERT_NE(point, nullptr);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetWindowX(35);
    pointerItem.SetWindowY(50);
    pointerItem.SetTargetWindowId(2);
    point->pointerAction_ = PointerEvent::POINTER_ACTION_DOWN;
    point->pointerId_ = 1;
    std::shared_ptr<WindowInfo> windowInfo = std::make_shared<WindowInfo>();
    windowInfo->id = 5;
    eventdispatchhandler.cancelEventList_[1].push_back(windowInfo);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandleMultiWindowPointerEvent(point, pointerItem));
    windowInfo->id = 1;
    eventdispatchhandler.cancelEventList_[2].push_back(windowInfo);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandleMultiWindowPointerEvent(point, pointerItem));
    point->pointerAction_ = PointerEvent::POINTER_ACTION_MOVE;
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandleMultiWindowPointerEvent(point, pointerItem));
    point->pointerAction_ = PointerEvent::POINTER_ACTION_UP;
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandleMultiWindowPointerEvent(point, pointerItem));
    point->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_UP;
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandleMultiWindowPointerEvent(point, pointerItem));
    point->pointerAction_ = PointerEvent::POINTER_ACTION_CANCEL;
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandleMultiWindowPointerEvent(point, pointerItem));
}

/**
 * @tc.name: EventDispatchTest_DispatchPointerEventInner_010
 * @tc.desc: Test the function DispatchPointerEventInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchPointerEventInner_010, TestSize.Level1)
{
    EventDispatchHandler eventDispatchHandler;
    int32_t fd = 2;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    UDSServer udsServer;
    InputHandler->udsServer_ = &udsServer;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    udsServer.sessionsMap_.insert(std::make_pair(fd, session));
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_DOWN;
    ASSERT_NO_FATAL_FAILURE(eventDispatchHandler.DispatchPointerEventInner(pointerEvent, fd));
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_UP;
    ASSERT_NO_FATAL_FAILURE(eventDispatchHandler.DispatchPointerEventInner(pointerEvent, fd));
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_DOWN;
    ASSERT_NO_FATAL_FAILURE(eventDispatchHandler.DispatchPointerEventInner(pointerEvent, fd));
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_UP;
    ASSERT_NO_FATAL_FAILURE(eventDispatchHandler.DispatchPointerEventInner(pointerEvent, fd));
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW;
    ASSERT_NO_FATAL_FAILURE(eventDispatchHandler.DispatchPointerEventInner(pointerEvent, fd));
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_MOVE;
    ASSERT_NO_FATAL_FAILURE(eventDispatchHandler.DispatchPointerEventInner(pointerEvent, fd));
    fd = -2;
    ASSERT_NO_FATAL_FAILURE(eventDispatchHandler.DispatchPointerEventInner(pointerEvent, fd));
    fd = 5;
    udsServer.sessionsMap_.insert(std::make_pair(5, session));
    ASSERT_NO_FATAL_FAILURE(eventDispatchHandler.DispatchPointerEventInner(pointerEvent, fd));
}

/**
 * @tc.name: EventDispatchTest_DispatchKeyEventPid_006
 * @tc.desc: Test the function DispatchKeyEventPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchKeyEventPid_006, TestSize.Level1)
{
    EventDispatchHandler eventDispatchHandler;
    UDSServer udsServer;
    std::shared_ptr<KeyEvent> KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    ASSERT_EQ(eventDispatchHandler.DispatchKeyEventPid(udsServer, KeyEvent), RET_OK);
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    udsServer.sessionsMap_.insert(std::make_pair(-1, session));
    StreamBuffer streamBuffer;
    streamBuffer.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_READ;
    eventDispatchHandler.DispatchKeyEventPid(udsServer, KeyEvent);
    streamBuffer.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_READ;
    ASSERT_EQ(eventDispatchHandler.DispatchKeyEventPid(udsServer, KeyEvent), RET_OK);
}

/**
 * @tc.name: DispatchPointerEventInner_06
 * @tc.desc: Test the funcation DispatchKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, DispatchPointerEventInner_06, TestSize.Level1)
{
    EventDispatchHandler handler;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    ASSERT_NE(point, nullptr);
    int32_t fd = -5;
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    inputEvent->actionTime_ = 3100;
    handler.eventTime_ = 10;
    ASSERT_NO_FATAL_FAILURE(handler.DispatchPointerEventInner(point, fd));
    inputEvent->actionTime_ = 200;
    ASSERT_NO_FATAL_FAILURE(handler.DispatchPointerEventInner(point, fd));
    fd = 5;
    bool status = true;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, 1, 1, 100, 100);
    session->SetTokenType(TokenType::TOKEN_HAP);
    session->SetAnrStatus(0, status);
    ASSERT_NO_FATAL_FAILURE(handler.DispatchPointerEventInner(point, fd));
    status = false;
    point->pointerAction_ = PointerEvent::POINTER_ACTION_DOWN;
    ASSERT_NO_FATAL_FAILURE(handler.DispatchPointerEventInner(point, fd));
    point->pointerAction_ = PointerEvent::POINTER_ACTION_UP;
    ASSERT_NO_FATAL_FAILURE(handler.DispatchPointerEventInner(point, fd));
    point->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_DOWN;
    ASSERT_NO_FATAL_FAILURE(handler.DispatchPointerEventInner(point, fd));
    point->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_UP;
    ASSERT_NO_FATAL_FAILURE(handler.DispatchPointerEventInner(point, fd));
    point->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_MOVE;
    ASSERT_NO_FATAL_FAILURE(handler.DispatchPointerEventInner(point, fd));
    point->pointerAction_ = PointerEvent::POINTER_ACTION_MOVE;
    ASSERT_NO_FATAL_FAILURE(handler.DispatchPointerEventInner(point, fd));
    point->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW;
    ASSERT_NO_FATAL_FAILURE(handler.DispatchPointerEventInner(point, fd));
    point->pointerAction_ = PointerEvent::POINTER_ACTION_AXIS_END;
    ASSERT_NO_FATAL_FAILURE(handler.DispatchPointerEventInner(point, fd));
}

/**
 * @tc.name: EventDispatchTest_DispatchKeyEvent_001
 * @tc.desc: Test the funcation DispatchKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchKeyEvent_001, TestSize.Level1)
{
    EventDispatchHandler handler;
    int32_t fd = -2;
    UDSServer udsServer;
    std::shared_ptr<KeyEvent> key = KeyEvent::Create();
    ASSERT_NE(key, nullptr);
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    inputEvent->actionTime_ = 4000;
    handler.eventTime_ = 200;
    int32_t ret = handler.DispatchKeyEvent(fd, udsServer, key);
    EXPECT_EQ(ret, RET_ERR);
    inputEvent->actionTime_ = 2000;
    ret = handler.DispatchKeyEvent(fd, udsServer, key);
    EXPECT_EQ(ret, RET_ERR);
    fd = 9;
    bool status = true;
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, 1, 1, 100, 100);
    session->SetTokenType(TokenType::TOKEN_HAP);
    session->SetAnrStatus(0, status);
    ret = handler.DispatchKeyEvent(fd, udsServer, key);
    EXPECT_EQ(ret, RET_ERR);
    status = false;
    StreamBuffer streamBuffer;
    streamBuffer.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_READ;
    ret = handler.DispatchKeyEvent(fd, udsServer, key);
    EXPECT_EQ(ret, RET_ERR);
    streamBuffer.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_OK;
    udsServer.pid_ = 1;
    ret = handler.DispatchKeyEvent(fd, udsServer, key);
    EXPECT_EQ(ret, RET_ERR);
    udsServer.pid_ = -1;
    ret = handler.DispatchKeyEvent(fd, udsServer, key);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: EventDispatchTest_FilterInvalidPointerItem_008
 * @tc.desc: Test the function FilterInvalidPointerItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_FilterInvalidPointerItem_008, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t fd = 10;
    PointerEvent::PointerItem item1;
    item1.pointerId_ = 1;
    item1.pressed_ = true;
    item1.SetDisplayX(10);
    item1.SetDisplayY(20);
    pointerEvent->pointers_.push_back(item1);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.FilterInvalidPointerItem(pointerEvent, fd));
    PointerEvent::PointerItem item2;
    item2.pointerId_ = 2;
    item2.pressed_ = false;
    item2.SetDisplayX(20);
    item2.SetDisplayY(30);
    item2.targetWindowId_ = 1;
    pointerEvent->pointers_.push_back(item2);
    UDSServer udsServer;
    udsServer.pid_ = 1;
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.FilterInvalidPointerItem(pointerEvent, fd));
    udsServer.pid_ = -1;
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.FilterInvalidPointerItem(pointerEvent, fd));
}

/**
 * @tc.name: EventDispatchTest_HandleMultiWindowPointerEvent_008
 * @tc.desc: Test the function HandleMultiWindowPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_HandleMultiWindowPointerEvent_008, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    ASSERT_NE(point, nullptr);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetWindowX(1);
    pointerItem.SetWindowY(2);
    pointerItem.SetTargetWindowId(3);
    point->pointerAction_ = PointerEvent::POINTER_ACTION_UP;
    point->pointerId_ = 3;
    std::shared_ptr<WindowInfo> windowInfo = std::make_shared<WindowInfo>();
    windowInfo->id = 3;
    eventdispatchhandler.cancelEventList_[1].push_back(windowInfo);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandleMultiWindowPointerEvent(point, pointerItem));
    windowInfo->id = 1;
    eventdispatchhandler.cancelEventList_[2].push_back(windowInfo);
    point->pointerAction_ = PointerEvent::POINTER_ACTION_MOVE;
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandleMultiWindowPointerEvent(point, pointerItem));
    point->pointerAction_ = PointerEvent::POINTER_ACTION_CANCEL;
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandleMultiWindowPointerEvent(point, pointerItem));
}

/**
 * @tc.name: EventDispatchTest_DispatchKeyEvent_002
 * @tc.desc: Test the funcation DispatchKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_DispatchKeyEvent_002, TestSize.Level1)
{
    EventDispatchHandler handler;
    int32_t fd = 1;
    UDSServer udsServer;
    std::shared_ptr<KeyEvent> key = KeyEvent::Create();
    ASSERT_NE(key, nullptr);
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, 1, 1, 100, 100);
    session->tokenType_ = 0;
    session->isAnrProcess_.insert(std::make_pair(1, true));
    int32_t ret = handler.DispatchKeyEvent(fd, udsServer, key);
    EXPECT_EQ(ret, RET_ERR);
    fd = 2;
    session->isAnrProcess_.insert(std::make_pair(2, false));
    ret = handler.DispatchKeyEvent(fd, udsServer, key);
    EXPECT_EQ(ret, RET_ERR);
}

#ifdef OHOS_BUILD_ENABLE_ONE_HAND_MODE
/**
 * @tc.name: EventDispatchTest_UpdateDisplayXY_001
 * @tc.desc: Test the function UpdateDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_UpdateDisplayXY_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventDispatchHandler handler;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent = nullptr;
    ASSERT_NO_FATAL_FAILURE(handler.UpdateDisplayXY(pointerEvent));
}

/**
 * @tc.name: EventDispatchTest_UpdateDisplayXY_002
 * @tc.desc: Test the function UpdateDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_UpdateDisplayXY_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventDispatchHandler handler;
    auto pointerEvent = PointerEvent::Create();
    int32_t pointerId = 3;
    pointerEvent->SetPointerId(pointerId);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(2);
    pointerEvent->AddPointerItem(pointerItem);
    ASSERT_NO_FATAL_FAILURE(handler.UpdateDisplayXY(pointerEvent));
}

/**
 * @tc.name: EventDispatchTest_UpdateDisplayXY_003
 * @tc.desc: Test the function UpdateDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_UpdateDisplayXY_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventDispatchHandler handler;
    auto pointerEvent = PointerEvent::Create();
    int32_t pointerId = 3;
    int32_t displayId = 1;
    int32_t windowId = 2;
    pointerEvent->SetPointerId(pointerId);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(pointerItem);
    pointerEvent->SetTargetDisplayId(displayId);
    pointerItem.SetTargetWindowId(windowId);
    ASSERT_NO_FATAL_FAILURE(handler.UpdateDisplayXY(pointerEvent));
}

/**
 * @tc.name: EventDispatchTest_UpdateDisplayXY_004
 * @tc.desc: Test the function UpdateDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_UpdateDisplayXY_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventDispatchHandler handler;
    auto pointerEvent = PointerEvent::Create();
    int32_t pointerId = 3;
    int32_t displayId = 1;
    int32_t windowId = 2;
    pointerEvent->SetPointerId(pointerId);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(pointerItem);
    pointerEvent->SetTargetDisplayId(displayId);
    pointerItem.SetTargetWindowId(windowId);
    pointerEvent->SetFixedMode(PointerEvent::FixedMode::AUTO);
    ASSERT_NO_FATAL_FAILURE(handler.UpdateDisplayXY(pointerEvent));
}

/**
 * @tc.name: EventDispatchTest_UpdateDisplayXY_005
 * @tc.desc: Test the function UpdateDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_UpdateDisplayXY_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventDispatchHandler handler;
    auto pointerEvent = PointerEvent::Create();
    int32_t pointerId = 3;
    int32_t displayId = 1;
    int32_t windowId = 2;
    pointerEvent->SetPointerId(pointerId);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(pointerItem);
    pointerEvent->SetTargetDisplayId(displayId);
    pointerItem.SetTargetWindowId(windowId);
    pointerEvent->SetFixedMode(PointerEvent::FixedMode::NORMAL);
    ASSERT_NO_FATAL_FAILURE(handler.UpdateDisplayXY(pointerEvent));
}
#endif // OHOS_BUILD_ENABLE_ONE_HAND_MODE
/**
 * @tc.name: EventDispatchTest_SendWindowStateError_001
 * @tc.desc: Test the funcation SendWindowStateError
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_SendWindowStateError_001, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t fd = 1;
    int32_t windowId = 3;
    auto udsServer = std::make_unique<UDSServer>();
    InputHandler->udsServer_ = udsServer.get();
    EXPECT_NE(InputHandler->udsServer_, nullptr);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.SendWindowStateError(fd, windowId));
    InputHandler->udsServer_ = nullptr;
}

/**
 * @tc.name: EventDispatchTest_GetClientFd_001
 * @tc.desc: Test the funcation GetClientFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_GetClientFd_001, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t pid = 1;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    point->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    point->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    EXPECT_EQ(eventdispatchhandler.GetClientFd(pid, point), INVALID_FD);
}
/**
 * @tc.name: EventDispatchTest_GetClientFd_002
 * @tc.desc: Test the funcation GetClientFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_GetClientFd_002, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t pid = 1;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    point->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    point->SetSourceType(PointerEvent::SOURCE_TYPE_CROWN);
    EXPECT_EQ(eventdispatchhandler.GetClientFd(pid, point), INVALID_FD);
}
/**
 * @tc.name: EventDispatchTest_GetClientFd_003
 * @tc.desc: Test the funcation GetClientFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_GetClientFd_003, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t pid = 1;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    point->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    EXPECT_EQ(eventdispatchhandler.GetClientFd(pid, point), INVALID_FD);
}

/**
 * @tc.name: EventDispatchTest_GetClientFd_004
 * @tc.desc: Test the funcation GetClientFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_GetClientFd_004, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t pid = 0;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    point->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    point->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    EXPECT_EQ(eventdispatchhandler.GetClientFd(pid, point), INVALID_FD);
}
/**
 * @tc.name: EventDispatchTest_GetClientFd_005
 * @tc.desc: Test the funcation GetClientFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_GetClientFd_005, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t pid = 0;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    point->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    point->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    EXPECT_EQ(eventdispatchhandler.GetClientFd(pid, point), INVALID_FD);
}

/**
 * @tc.name: EventDispatchTest_GetClientFd_006
 * @tc.desc: Test the funcation GetClientFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_GetClientFd_006, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t pid = 1;
    std::shared_ptr<PointerEvent> point = PointerEvent::Create();
    point->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    point->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    EXPECT_EQ(eventdispatchhandler.GetClientFd(pid, point), INVALID_FD);
}

/**
 * @tc.name: EventDispatchTest_HandleKeyEvent_001
 * @tc.desc: Test the function HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_HandleKeyEvent_001, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandleKeyEvent(keyEvent));
}

/**
 * @tc.name: EventDispatchTest_HandleKeyEvent_002
 * @tc.desc: Test the function HandleKeyEvent with AddFlagToEsc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_HandleKeyEvent_002, TestSize.Level1)
{
    EventDispatchHandler dispatch;
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    dispatch.HandleKeyEvent(keyEvent);
    EXPECT_EQ(keyEvent, nullptr);
    keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    
    KeyEvent::KeyItem item;
    keyEvent->AddPressedKeyItems(item);
    EXPECT_EQ(keyEvent->GetKeyItems().size(), 1);

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_ESCAPE);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    EXPECT_EQ(dispatch.escToBackFlag_, false);
    dispatch.HandleKeyEvent(keyEvent);
    EXPECT_EQ(dispatch.escToBackFlag_, false);
    int32_t ret1 = keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    EXPECT_EQ(ret1, false);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    dispatch.HandleKeyEvent(keyEvent);
    EXPECT_EQ(dispatch.escToBackFlag_, false);
    int32_t ret2 = keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    EXPECT_EQ(ret2, false);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    dispatch.HandleKeyEvent(keyEvent);
    EXPECT_EQ(dispatch.escToBackFlag_, false);
    int32_t ret3 = keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    EXPECT_EQ(ret3, false);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    dispatch.HandleKeyEvent(keyEvent);
    EXPECT_EQ(dispatch.escToBackFlag_, false);
    int32_t ret4 = keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    EXPECT_EQ(ret4, false);
}

/**
 * @tc.name: EventDispatchTest_HandlePointerEvent_001
 * @tc.desc: Test the function HandlePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_HandlePointerEvent_001, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandlePointerEvent(pointerEvent));
}

/**
 * @tc.name: EventDispatchTest_FilterInvalidPointerItem_010
 * @tc.desc: Test the function FilterInvalidPointerItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_FilterInvalidPointerItem_010, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t fd = 1;
    int32_t eventType = 3;
    std::shared_ptr<PointerEvent> pointerEvent = std::make_shared<PointerEvent>(eventType);

    std::vector<int32_t> pointerIdList;
    pointerEvent->pointerId_ = 3;
    pointerIdList.push_back(pointerEvent->pointerId_);
    pointerEvent->pointerId_ = 5;
    pointerIdList.push_back(pointerEvent->pointerId_);
    EXPECT_TRUE(pointerIdList.size() > 1);

    PointerEvent::PointerItem pointeritem;
    pointeritem.SetWindowX(10);
    pointeritem.SetWindowY(20);
    pointeritem.SetTargetWindowId(2);
    int32_t id = 1;
    EXPECT_FALSE(pointerEvent->GetPointerItem(id, pointeritem));

    pointeritem.targetWindowId_ = 3;
    auto itemPid = WIN_MGR->GetWindowPid(pointeritem.targetWindowId_);
    EXPECT_FALSE(itemPid >= 0);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.FilterInvalidPointerItem(pointerEvent, fd));
}

/**
 * @tc.name: EventDispatchTest_SearchCancelList_004
 * @tc.desc: Test SearchCancelList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_SearchCancelList_004, TestSize.Level1)
{
    EventDispatchHandler handler;
    int32_t pointerId = 1;
    int32_t windowId = 1;
    std::shared_ptr<WindowInfo> result = handler.SearchCancelList(pointerId, windowId);
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: EventDispatchTest_HandleMultiWindowPointerEvent_009
 * @tc.desc: Test HandleMultiWindowPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchTest, EventDispatchTest_HandleMultiWindowPointerEvent_009, TestSize.Level1)
{
    EventDispatchHandler eventdispatchhandler;
    int32_t eventType = 3;
    std::shared_ptr<PointerEvent> point = std::make_shared<PointerEvent>(eventType);
    EXPECT_NE(point, nullptr);

    std::vector<int32_t> windowIds;
    windowIds.push_back(1);
    windowIds.push_back(2);
    windowIds.push_back(3);

    PointerEvent::PointerItem pointerItem;
    pointerItem.SetWindowX(10);
    pointerItem.SetWindowY(20);
    pointerItem.SetTargetWindowId(2);

    int32_t pointerId = 1;
    int32_t windowId = 1;
    std::shared_ptr<WindowInfo> windowInfo1 = std::make_shared<WindowInfo>();
    windowInfo1->id = 1;
    eventdispatchhandler.cancelEventList_[1].push_back(windowInfo1);
    auto windowInfo = eventdispatchhandler.SearchCancelList(pointerId, windowId);
    ASSERT_NO_FATAL_FAILURE(eventdispatchhandler.HandleMultiWindowPointerEvent(point, pointerItem));
}
} // namespace MMI
} // namespace OHOS
