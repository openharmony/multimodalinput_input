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

#include "key_event_input_subscribe_manager.h"
#include <cinttypes>
#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "multimodal_event_handler.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventInputSubscribeManagerTest"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t INVALID_SUBSCRIBE_ID { -1 };
using namespace testing::ext;
} // namespace

class KeyEventInputSubscribeManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};
/**
 * @tc.name: KeyEventInputSubscribeManagerTest_SubscribeKeyEvent001
 * @tc.desc: Verify SubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventInputSubscribeManagerTest, KeyEventInputSubscribeManagerTest_SubscribeKeyEvent001,
    TestSize.Level1)
{
    KeyEventInputSubscribeManager manager;
    std::set<int32_t> preKeys;
    preKeys.insert(1);
    preKeys.insert(2);
    preKeys.insert(3);
    preKeys.insert(4);
    preKeys.insert(5);

    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    ASSERT_NE(keyOption, nullptr);
    keyOption->SetPreKeys(preKeys);

    auto myCallback = [](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGD("Add monitor success");
    };
    auto ret = manager.SubscribeKeyEvent(keyOption, myCallback);
    EXPECT_EQ(ret, INVALID_SUBSCRIBE_ID);
}

/**
 * @tc.name: KeyEventInputSubscribeManagerTest_UnsubscribeKeyEvent001
 * @tc.desc: Verify UnsubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventInputSubscribeManagerTest, KeyEventInputSubscribeManagerTest_UnsubscribeKeyEvent001,
    TestSize.Level1)
{
    KeyEventInputSubscribeManager manager;
    int32_t subscribeId = -1;
    auto ret = manager.UnsubscribeKeyEvent(subscribeId);
    EXPECT_EQ(ret, RET_ERR);

    subscribeId = 1;
    ret = manager.UnsubscribeKeyEvent(subscribeId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: KeyEventInputSubscribeManagerTest_SubscribeHotkey002
 * @tc.desc: Verify SubscribeHotkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventInputSubscribeManagerTest, KeyEventInputSubscribeManagerTest_SubscribeHotkey002,
    TestSize.Level1)
{
    std::set<int32_t> preKeys;
    preKeys.insert(1);
    preKeys.insert(2);
    preKeys.insert(3);
    preKeys.insert(4);
    preKeys.insert(5);

    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    ASSERT_NE(keyOption, nullptr);
    keyOption->SetPreKeys(preKeys);

    auto myCallback = [](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGD("Add monitor success");
    };
    KeyEventInputSubscribeManager manager;
    auto ret = manager.SubscribeHotkey(keyOption, myCallback);
    EXPECT_EQ(ret, INVALID_SUBSCRIBE_ID);
}

/**
 * @tc.name: KeyEventInputSubscribeManagerTest_UnsubscribeHotkey001
 * @tc.desc: Verify UnsubscribeHotkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventInputSubscribeManagerTest, KeyEventInputSubscribeManagerTest_UnsubscribeHotkey001,
    TestSize.Level1)
{
    KeyEventInputSubscribeManager manager;
    int32_t subscribeId = -1;
    auto ret = manager.UnsubscribeHotkey(subscribeId);
    EXPECT_EQ(ret, RET_ERR);

    subscribeId = 1;
    ret = manager.UnsubscribeHotkey(subscribeId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: KeyEventInputSubscribeManagerTest_OnSubscribeKeyEventCallback001
 * @tc.desc: Verify OnSubscribeKeyEventCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventInputSubscribeManagerTest, KeyEventInputSubscribeManagerTest_OnSubscribeKeyEventCallback001,
    TestSize.Level1)
{
    KeyEventInputSubscribeManager manager;
    std::shared_ptr<KeyEvent> event = KeyEvent::Create();
    EXPECT_NE(event, nullptr);
    int32_t subscribeId = -1;
    EXPECT_EQ(manager.OnSubscribeKeyEventCallback(event, subscribeId), RET_ERR);
}

/**
 * @tc.name: KeyEventInputSubscribeManagerTest_GetSubscribeKeyEvent001
 * @tc.desc: Verify GetSubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventInputSubscribeManagerTest, KeyEventInputSubscribeManagerTest_GetSubscribeKeyEvent001,
    TestSize.Level1)
{
    KeyEventInputSubscribeManager manager;
    int32_t subscribeId = -1;
    EXPECT_EQ(manager.GetSubscribeKeyEvent(subscribeId), nullptr);
}

/**
 * @tc.name: KeyEventInputSubscribeManagerTest_SubscribeKeyEventInfo001
 * @tc.desc: Verify SubscribeKeyEventInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventInputSubscribeManagerTest, KeyEventInputSubscribeManagerTest_SubscribeKeyEventInfo001,
    TestSize.Level1)
{
    KeyEventInputSubscribeManager manager;
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    EXPECT_NE(keyOption, nullptr);

    auto myCallback = [](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGD("Add monitor success");
    };

    manager.subscribeIdManager_ = std::numeric_limits<int32_t>::max();
    KeyEventInputSubscribeManager::SubscribeKeyEventInfo info1(keyOption, myCallback);
    EXPECT_EQ(info1.GetSubscribeId(), -1);

    KeyEventInputSubscribeManager::SubscribeKeyEventInfo info2(info1);
    EXPECT_EQ(info2.GetSubscribeId(), -1);

    std::shared_ptr<KeyOption> keyOptionNull;
    std::function<void(std::shared_ptr<KeyEvent>)> myCallbackNull;
    KeyEventInputSubscribeManager::SubscribeKeyEventInfo info3(keyOptionNull, myCallbackNull);
    EXPECT_TRUE(info3 < info1);
    EXPECT_FALSE(info1 < info3);
    EXPECT_FALSE(info1 < info2);

    KeyEventInputSubscribeManager::SubscribeKeyEventInfo info4 = info1;
    EXPECT_EQ(info4.GetSubscribeId(), -1);
    manager.subscribeIdManager_ = 0;
}

#ifdef OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER
/**
 * @tc.name: KeyEventInputSubscribeManagerTest_SubscribeKeyMonitor001
 * @tc.desc: Verify SubscribeKeyMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventInputSubscribeManagerTest, KeyEventInputSubscribeManagerTest_SubscribeKeyMonitor001,
    TestSize.Level1)
{
    KeyEventInputSubscribeManager manager;
    KeyMonitorOption keyOption;
    keyOption.SetKey(KeyEvent::KEYCODE_VOLUME_UP);
    keyOption.SetAction(KeyEvent::KEY_ACTION_UP);
    keyOption.SetRepeat(false);

    auto myCallback = [](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGD("Add monitor success");
    };
    auto rlt1 = manager.SubscribeKeyMonitor(keyOption, myCallback);
    EXPECT_NE(rlt1, 0);
}

/**
 * @tc.name: KeyEventInputSubscribeManagerTest_SubscribeKeyMonitor002
 * @tc.desc: Verify SubscribeKeyMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventInputSubscribeManagerTest, KeyEventInputSubscribeManagerTest_SubscribeKeyMonitor002,
    TestSize.Level1)
{
    KeyEventInputSubscribeManager::MonitorIdentity monitorId;
    monitorId.key_ = KeyEvent::KEYCODE_VOLUME_UP;
    monitorId.action_ = KeyEvent::KEY_ACTION_UP;
    monitorId.isRepeat_ = false;

    auto myCallback = [](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGD("Add monitor success");
    };

    std::map<int32_t, KeyEventInputSubscribeManager::Monitor> monitors;
    KeyEventInputSubscribeManager::Monitor monitor;
    monitor.callback_ = myCallback;

    int32_t id = 1;
    monitors.emplace(id, monitor);

    KeyEventInputSubscribeManager manager;
    manager.monitors_.emplace(monitorId, monitors);
    manager.subscribeIdManager_ = 0;

    KeyMonitorOption keyOption;
    keyOption.SetKey(KeyEvent::KEYCODE_VOLUME_UP);
    keyOption.SetAction(KeyEvent::KEY_ACTION_UP);
    keyOption.SetRepeat(false);

    auto rlt = manager.SubscribeKeyMonitor(keyOption, myCallback);
    EXPECT_EQ(rlt, 0);
}

/**
 * @tc.name: KeyEventInputSubscribeManagerTest_UnsubscribeKeyMonitor001
 * @tc.desc: Verify UnsubscribeKeyMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventInputSubscribeManagerTest, KeyEventInputSubscribeManagerTest_UnsubscribeKeyMonitor001,
    TestSize.Level1)
{
    KeyEventInputSubscribeManager::MonitorIdentity monitorId;
    monitorId.key_ = KeyEvent::KEYCODE_VOLUME_UP;
    monitorId.action_ = KeyEvent::KEY_ACTION_UP;
    monitorId.isRepeat_ = false;

    auto myCallback = [](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGD("Add monitor success");
    };

    std::map<int32_t, KeyEventInputSubscribeManager::Monitor> monitors;
    KeyEventInputSubscribeManager::Monitor monitor;
    monitor.callback_ = myCallback;

    int32_t id1 = 1;
    int32_t id2 = 2;
    monitors.emplace(id1, monitor);
    monitors.emplace(id2, monitor);

    KeyEventInputSubscribeManager manager;
    manager.monitors_.emplace(monitorId, monitors);
    int32_t subscriberId = -1;

    auto rlt = manager.UnsubscribeKeyMonitor(subscriberId);
    EXPECT_EQ(rlt, -PARAM_INPUT_INVALID);

    subscriberId = id1;
    rlt = manager.UnsubscribeKeyMonitor(subscriberId);
    EXPECT_EQ(rlt, RET_OK);

    subscriberId = id2;
    rlt = manager.UnsubscribeKeyMonitor(subscriberId);
    MMI_HILOGI("UnsubscribeKeyMonitor ret:%{public}d", rlt);
}

/**
 * @tc.name: KeyEventInputSubscribeManagerTest_CheckKeyMonitors001
 * @tc.desc: Verify CheckKeyMonitors
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventInputSubscribeManagerTest, KeyEventInputSubscribeManagerTest_CheckKeyMonitors001,
    TestSize.Level1)
{
    KeyEventInputSubscribeManager::MonitorIdentity monitorId;
    monitorId.key_ = KeyEvent::KEYCODE_VOLUME_UP;
    monitorId.action_ = KeyEvent::KEY_ACTION_UP;
    monitorId.isRepeat_ = false;

    auto myCallback = [](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGD("Add monitor success");
    };

    std::map<int32_t, KeyEventInputSubscribeManager::Monitor> monitors;
    KeyEventInputSubscribeManager::Monitor monitor;
    monitor.callback_ = myCallback;

    int32_t id = 1;
    monitors.emplace(id, monitor);

    KeyEventInputSubscribeManager manager;
    manager.monitors_.emplace(monitorId, monitors);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetRepeatKey(true);

    auto keyMonitors = manager.CheckKeyMonitors(keyEvent);
    EXPECT_EQ(keyMonitors.size(), 0);

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyMonitors = manager.CheckKeyMonitors(keyEvent);
    EXPECT_EQ(keyMonitors.size(), 0);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyMonitors = manager.CheckKeyMonitors(keyEvent);
    EXPECT_EQ(keyMonitors.size(), 1);
}

/**
 * @tc.name: KeyEventInputSubscribeManagerTest_CheckKeyMonitors002
 * @tc.desc: Verify CheckKeyMonitors
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventInputSubscribeManagerTest, KeyEventInputSubscribeManagerTest_CheckKeyMonitors002,
    TestSize.Level1)
{
    KeyEventInputSubscribeManager::MonitorIdentity monitorId;
    monitorId.key_ = KeyEvent::KEYCODE_VOLUME_DOWN;
    monitorId.action_ = KeyEvent::KEY_ACTION_DOWN;
    monitorId.isRepeat_ = false;

    auto myCallback = [](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGD("Add monitor success");
    };

    std::map<int32_t, KeyEventInputSubscribeManager::Monitor> monitors;
    KeyEventInputSubscribeManager::Monitor monitor;
    monitor.callback_ = myCallback;

    int32_t id = 1;
    monitors.emplace(id, monitor);

    KeyEventInputSubscribeManager manager;
    manager.monitors_.emplace(monitorId, monitors);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetRepeatKey(true);

    auto keyMonitors = manager.CheckKeyMonitors(keyEvent);
    EXPECT_EQ(keyMonitors.size(), 0);

    keyEvent->SetRepeatKey(false);
    keyMonitors = manager.CheckKeyMonitors(keyEvent);
    EXPECT_EQ(keyMonitors.size(), 1);
}

/**
 * @tc.name: KeyEventInputSubscribeManagerTest_CheckKeyMonitors003
 * @tc.desc: Verify CheckKeyMonitors
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventInputSubscribeManagerTest, KeyEventInputSubscribeManagerTest_CheckKeyMonitors003,
    TestSize.Level1)
{
    KeyEventInputSubscribeManager::MonitorIdentity monitorId;
    monitorId.key_ = KeyEvent::KEYCODE_VOLUME_UP;
    monitorId.action_ = KeyEvent::KEY_ACTION_UP;
    monitorId.isRepeat_ = true;

    auto myCallback = [](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGD("Add monitor success");
    };

    std::map<int32_t, KeyEventInputSubscribeManager::Monitor> monitors;
    KeyEventInputSubscribeManager::Monitor monitor;
    monitor.callback_ = myCallback;

    int32_t id = 1;
    monitors.emplace(id, monitor);

    KeyEventInputSubscribeManager manager;
    manager.monitors_.emplace(monitorId, monitors);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetRepeatKey(true);

    auto keyMonitors = manager.CheckKeyMonitors(keyEvent);
    EXPECT_EQ(keyMonitors.size(), 1);
}

/**
 * @tc.name: KeyEventInputSubscribeManagerTest_OnSubscribeKeyMonitor001
 * @tc.desc: Verify OnSubscribeKeyMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventInputSubscribeManagerTest, KeyEventInputSubscribeManagerTest_OnSubscribeKeyMonitor001,
    TestSize.Level1)
{
    KeyEventInputSubscribeManager::MonitorIdentity monitorId;
    monitorId.key_ = KeyEvent::KEYCODE_VOLUME_UP;
    monitorId.action_ = KeyEvent::KEY_ACTION_UP;
    monitorId.isRepeat_ = true;

    auto myCallback = [](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGD("Add monitor success");
    };

    std::map<int32_t, KeyEventInputSubscribeManager::Monitor> monitors;
    KeyEventInputSubscribeManager::Monitor monitor;
    monitor.callback_ = myCallback;

    int32_t id = 1;
    monitors.emplace(id, monitor);

    KeyEventInputSubscribeManager manager;
    manager.monitors_.emplace(monitorId, monitors);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetRepeatKey(true);
    auto ret = manager.OnSubscribeKeyMonitor(keyEvent, false);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: KeyEventInputSubscribeManagerTest_OnSubscribeKeyMonitor002
 * @tc.desc: Verify OnSubscribeKeyMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventInputSubscribeManagerTest, KeyEventInputSubscribeManagerTest_OnSubscribeKeyMonitor002,
    TestSize.Level1)
{
    KeyEventInputSubscribeManager::MonitorIdentity monitorId;
    monitorId.key_ = KeyEvent::KEYCODE_VOLUME_UP;
    monitorId.action_ = KeyEvent::KEY_ACTION_UP;
    monitorId.isRepeat_ = true;

    KeyEventInputSubscribeManager::Monitor monitor;

    int32_t id = 1;
    std::map<int32_t, KeyEventInputSubscribeManager::Monitor> monitors;
    monitors.emplace(id, monitor);

    KeyEventInputSubscribeManager manager;
    manager.monitors_.emplace(monitorId, monitors);

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetRepeatKey(true);
    auto ret = manager.OnSubscribeKeyMonitor(keyEvent, false);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: KeyEventInputSubscribeManagerTest_MonitorIdentity001
 * @tc.desc: Verify MonitorIdentity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventInputSubscribeManagerTest, KeyEventInputSubscribeManagerTest_MonitorIdentity001,
    TestSize.Level1)
{
    KeyEventInputSubscribeManager::MonitorIdentity monitorId;
    monitorId.key_ = KeyEvent::KEYCODE_VOLUME_UP;
    monitorId.action_ = KeyEvent::KEY_ACTION_UP;
    monitorId.isRepeat_ = true;

    KeyEventInputSubscribeManager::MonitorIdentity monitorId2;
    monitorId2.key_ = KeyEvent::KEYCODE_VOLUME_UP;
    monitorId2.action_ = KeyEvent::KEY_ACTION_UP;
    monitorId2.isRepeat_ = true;

    EXPECT_FALSE(monitorId < monitorId2);

    monitorId.isRepeat_ = false;
    EXPECT_TRUE(monitorId < monitorId2);

    monitorId.isRepeat_ = true;
    monitorId.action_ = KeyEvent::KEY_ACTION_DOWN;
    EXPECT_TRUE(monitorId < monitorId2);

    monitorId.action_ = KeyEvent::KEY_ACTION_UP;
    monitorId.key_ = KeyEvent::KEYCODE_VOLUME_DOWN;
    EXPECT_FALSE(monitorId < monitorId2);
}
#endif
} // namespace MMI
} // namespace OHOS