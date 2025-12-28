/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "common_event_data.h"
#include "common_event_manager.h"
#include "device_event_monitor.h"
#include "display_event_monitor.h"
#include "input_windows_manager.h"
#include "mmi_log.h"
#include "repeat_key_handler.h"
#include "test_key_command_service.h"
#include "want.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "RepeatKeyHandlerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t MODULE_TYPE { 1 };
constexpr int32_t UDS_FD { -1 };
constexpr int32_t UDS_UID { 100 };
constexpr int32_t UDS_PID { 100 };
const std::string SOS_BUNDLE_NAME { "com.huawei.hmos.emergencycommunication" };
} // namespace
class RepeatKeyHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    void SetUp() override
    {
        shortcutKeys_ = std::make_unique<std::map<std::string, ShortcutKey>>();
        sequences_ = std::make_unique<std::vector<Sequence>>();
        repeatKeys_ = std::make_unique<std::vector<RepeatKey>>();
        excludeKeys_ = std::make_unique<std::vector<ExcludeKey>>();

        context_.shortcutKeys_ = shortcutKeys_.get();
        context_.sequences_ = sequences_.get();
        context_.repeatKeys_ = repeatKeys_.get();
        context_.excludeKeys_ = excludeKeys_.get();

        service_ = std::make_unique<TestKeyCommandService>();  
        handler_ = std::make_unique<RepeatKeyHandler>(context_, *service_);
    }

private:
    KeyCommandContext context_;
    std::unique_ptr<std::map<std::string, ShortcutKey>> shortcutKeys_;
    std::unique_ptr<std::vector<Sequence>> sequences_;
    std::unique_ptr<std::vector<RepeatKey>> repeatKeys_;
    std::unique_ptr<std::vector<ExcludeKey>> excludeKeys_;
    std::unique_ptr<TestKeyCommandService> service_;
    std::unique_ptr<RepeatKeyHandler> handler_;
};

/**
 * @tc.name: RepeatKeyHandlerTest_HandleRepeatKey_001
 * @tc.desc: Test the funcation HandleRepeatKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_HandleRepeatKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey item;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_UP);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.times = 5;
    context_.count_ = 5;
    ASSERT_FALSE(handler_->HandleRepeatKey(item, keyEvent));
    context_.count_ = 10;
    ASSERT_FALSE(handler_->HandleRepeatKey(item, keyEvent));
}

/**
 * @tc.name: RepeatKeyHandlerTest_HandleRepeatKey_002
 * @tc.desc: Test the funcation HandleRepeatKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_HandleRepeatKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey item;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    item.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    item.times = 6;
    context_.count_ = 5;
    ASSERT_FALSE(handler_->HandleRepeatKey(item, keyEvent));
}

/**
 * @tc.name: RepeatKeyHandlerTest_HandleRepeatKey_003
 * @tc.desc: HandleRepeatKey_003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_HandleRepeatKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    repeatKey.times = 2;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.ability.bundleName = "bundleName";
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    context_.repeatKeyMaxTimes_.emplace(KeyEvent::KEYCODE_POWER, 2);
    ASSERT_FALSE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: RepeatKeyHandlerTest_HandleRepeatKey_004
 * @tc.desc: HandleRepeatKey_004
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_HandleRepeatKey_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    context_.count_ = 3;
    repeatKey.times = 2;
    repeatKey.statusConfig = "statusConfig";
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    repeatKey.ability.bundleName = "bundleName";
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    context_.repeatKeyCountMap_.emplace(repeatKey.ability.bundleName, 2);
    context_.repeatKeyMaxTimes_.emplace(KeyEvent::KEYCODE_POWER, 5);
    ASSERT_FALSE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: RepeatKeyHandlerTest_HandleRepeatKey_005
 * @tc.desc: HandleRepeatKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_HandleRepeatKey_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    repeatKey.times = 2;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    ASSERT_FALSE(handler_->HandleRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: RepeatKeyHandlerTest_HandleRepeatKeyCount_001
 * @tc.desc: Test if (walletLaunchDelayTimes_ != 0)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_HandleRepeatKeyCount_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_POWER;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    context_.walletLaunchDelayTimes_ = 0;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKeyCount(repeatKey, keyEvent));
 
    context_.walletLaunchDelayTimes_ = 1;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKeyCount(repeatKey, keyEvent));
}

/**
 * @tc.name: RepeatKeyHandlerTest_HandleRepeatKeyCount_002
 * @tc.desc: HandleRepeatKeyCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_HandleRepeatKeyCount_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    repeatKey.keyCode = 2017;
    keyEvent->SetKeyCode(2017);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetActionTime(20);
    context_.repeatKey_.keyCode = 2018;
    ASSERT_TRUE(handler_->HandleRepeatKeyCount(repeatKey, keyEvent));

    context_.repeatKey_.keyCode = 2017;
    ASSERT_TRUE(handler_->HandleRepeatKeyCount(repeatKey, keyEvent));

    context_.intervalTime_ = 100;
    keyEvent->SetActionTime(50);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    ASSERT_TRUE(handler_->HandleRepeatKeyCount(repeatKey, keyEvent));

    keyEvent->SetKeyCode(2018);
    ASSERT_FALSE(handler_->HandleRepeatKeyCount(repeatKey, keyEvent));
}

/**
 * @tc.name: RepeatKeyHandlerTest_HandleRepeatKeyAbility_001
 * @tc.desc: HandleRepeatKeyAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_HandleRepeatKeyAbility_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    context_.count_ = 2;
    repeatKey.ability.bundleName = "bundleName";
    ASSERT_TRUE(handler_->HandleRepeatKeyAbility(repeatKey, keyEvent, false));
}

/**
 * @tc.name: RepeatKeyHandlerTest_HandleRepeatKeyAbility_002
 * @tc.desc: HandleRepeatKeyAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_HandleRepeatKeyAbility_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    context_.count_ = 2;
    repeatKey.ability.bundleName = "bundleName";
    handler_->repeatKeyTimerIds_.emplace(repeatKey.ability.bundleName, 1);
    ASSERT_TRUE(handler_->HandleRepeatKeyAbility(repeatKey, keyEvent, false));
}

/**
 * @tc.name: RepeatKeyHandlerTest_HandleRepeatKeyOwnCount_001
 * @tc.desc: Test if (item.ability.bundleName == SOS_BUNDLE_NAME)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_HandleRepeatKeyOwnCount_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKeyOwnCount(repeatKey));
 
    repeatKey.ability.bundleName = "test";
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKeyOwnCount(repeatKey));
}
 
/**
 * @tc.name: RepeatKeyHandlerTest_HandleRepeatKeyOwnCount_002
 * @tc.desc: Test if (item.ability.bundleName == SOS_BUNDLE_NAME)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_HandleRepeatKeyOwnCount_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.ability.bundleName = SOS_BUNDLE_NAME;
    repeatKey.delay = 10;
    handler_->downActionTime_ = 10;
    handler_->lastDownActionTime_ = 10;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKeyOwnCount(repeatKey));
 
    handler_->downActionTime_ = 100;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKeyOwnCount(repeatKey));
}
 
/**
 * @tc.name: RepeatKeyHandlerTest_HandleRepeatKeyOwnCount_003
 * @tc.desc: Test if (item.ability.bundleName == SOS_BUNDLE_NAME)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_HandleRepeatKeyOwnCount_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    repeatKey.ability.bundleName = "test";
    repeatKey.delay = 10;
    handler_->upActionTime_ = 10;
    handler_->lastDownActionTime_ = 10;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKeyOwnCount(repeatKey));
 
    handler_->downActionTime_ = 100;
    ASSERT_NO_FATAL_FAILURE(handler_->HandleRepeatKeyOwnCount(repeatKey));
}

/**
 * @tc.name: RepeatKeyHandlerTest_HandleKeyUpCancel
 * @tc.desc: HandleKeyUpCancel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_HandleKeyUpCancel, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RepeatKey repeatKey;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    repeatKey.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    ASSERT_TRUE(handler_->HandleKeyUpCancel(repeatKey, keyEvent));
}

/**
 * @tc.name: RepeatKeyHandlerTest_CheckSpecialRepeatKey_001
 * @tc.desc: Test if (bundleName.find(matchName) == std::string::npos)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_CheckSpecialRepeatKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    repeatKey.ability.bundleName = ".camera";

    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    WindowInfo windowInfo;
    windowInfo.id = 0;
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
        it->second.focusWindowId = 0;   
    }
    UDSServer udsServer;
    udsServer.idxPidMap_.insert(std::make_pair(0, 1));
    SessionPtr sessionPtr = std::make_shared<UDSSession>(repeatKey.ability.bundleName,
        MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_[1] = sessionPtr;
    inputWindowsManager->udsServer_ = &udsServer;
    EXPECT_NE(inputWindowsManager->udsServer_, nullptr);
    IInputWindowsManager::instance_ = inputWindowsManager;

    DISPLAY_MONITOR->SetScreenStatus("test");
    DISPLAY_MONITOR->SetScreenLocked(true);
    ASSERT_NO_FATAL_FAILURE(handler_->CheckSpecialRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: RepeatKeyHandlerTest_CheckSpecialRepeatKey_002
 * @tc.desc: Test if (WIN_MGR->JudgeCameraInFore() &&
 * (screenStatus != EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF && isScreenLocked))
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_CheckSpecialRepeatKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    repeatKey.ability.bundleName = ".camera";

    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    WindowInfo windowInfo;
    windowInfo.id = 0;
    OLD::DisplayGroupInfo displayGroupInfoRef;
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        displayGroupInfoRef = it->second;
    }
    displayGroupInfoRef.windowsInfo.push_back(windowInfo);
    displayGroupInfoRef.focusWindowId = 0;    
    UDSServer udsServer;
    udsServer.idxPidMap_.insert(std::make_pair(0, 1));
    SessionPtr sessionPtr = std::make_shared<UDSSession>(repeatKey.ability.bundleName,
        MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_[1] = sessionPtr;
    inputWindowsManager->udsServer_ = &udsServer;
    EXPECT_NE(inputWindowsManager->udsServer_, nullptr);
    IInputWindowsManager::instance_ = inputWindowsManager;

    DISPLAY_MONITOR->SetScreenStatus(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    DISPLAY_MONITOR->SetScreenLocked(true);
    ASSERT_NO_FATAL_FAILURE(handler_->CheckSpecialRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: RepeatKeyHandlerTest_CheckSpecialRepeatKey_003
 * @tc.desc: Test if (WIN_MGR->JudgeCameraInFore() &&
 * (screenStatus != EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF && isScreenLocked))
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_CheckSpecialRepeatKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);

    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    repeatKey.ability.bundleName = ".camera";

    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    WindowInfo windowInfo;
    windowInfo.id = 0;
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
        it->second.focusWindowId = 0;
    }
    UDSServer udsServer;
    udsServer.idxPidMap_.insert(std::make_pair(0, 1));
    SessionPtr sessionPtr = std::make_shared<UDSSession>(repeatKey.ability.bundleName,
        MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_[1] = sessionPtr;
    inputWindowsManager->udsServer_ = &udsServer;
    EXPECT_NE(inputWindowsManager->udsServer_, nullptr);
    IInputWindowsManager::instance_ = inputWindowsManager;

    DISPLAY_MONITOR->SetScreenStatus("test");
    DISPLAY_MONITOR->SetScreenLocked(false);
    ASSERT_NO_FATAL_FAILURE(handler_->CheckSpecialRepeatKey(repeatKey, keyEvent));
}

/**
 * @tc.name: CheckSpecialRepeatKey_Normal_Branch_004
 * @tc.desc: Test KEY_ACTION_UP and keyCode equl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, CheckSpecialRepeatKey_Normal_Branch_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    RepeatKey repeatKey;
    repeatKey.keyCode = KeyEvent::KEYCODE_VOLUME_DOWN;
    repeatKey.ability.bundleName = ".camera";

    auto inputWindowsManager = std::make_shared<InputWindowsManager>();
    WindowInfo windowInfo;
    windowInfo.id = 0;
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end())
    {
        it->second.windowsInfo.push_back(windowInfo);
        it->second.focusWindowId = 0;
    }
    UDSServer udsServer;
    udsServer.idxPidMap_.insert(std::make_pair(0, 1));
    SessionPtr sessionPtr =
        std::make_shared<UDSSession>(repeatKey.ability.bundleName, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    udsServer.sessionsMap_[1] = sessionPtr;
    inputWindowsManager->udsServer_ = &udsServer;
    EXPECT_NE(inputWindowsManager->udsServer_, nullptr);
    IInputWindowsManager::instance_ = inputWindowsManager;

    DISPLAY_MONITOR->SetScreenStatus("test");
    DISPLAY_MONITOR->SetScreenLocked(false);
    ASSERT_NO_FATAL_FAILURE(handler_->CheckSpecialRepeatKey(repeatKey, keyEvent));
    int32_t ret = keyEvent->GetKeyAction();
    EXPECT_EQ(context_.repeatKey_.keyAction, ret);
}

/**
 * @tc.name: RepeatKeyHandlerTest_SendKeyEvent_001
 * @tc.desc: Test the funcation SendKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_SendKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.isHandleSequence_ = true;
    context_.launchAbilityCount_ = 1;
    context_.count_ = 5;
    ASSERT_NO_FATAL_FAILURE(handler_->SendKeyEvent());
}

/**
 * @tc.name: RepeatKeyHandlerTest_SendKeyEvent_002
 * @tc.desc: Test the funcation SendKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_SendKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.isHandleSequence_ = false;
    context_.launchAbilityCount_ = 1;
    context_.repeatKey_.keyCode = 3;
    ASSERT_NO_FATAL_FAILURE(handler_->SendKeyEvent());
}

/**
 * @tc.name: RepeatKeyHandlerTest_SendKeyEvent_003
 * @tc.desc: Test the funcation SendKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_SendKeyEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    context_.isHandleSequence_ = false;
    context_.launchAbilityCount_ = 0;
    context_.repeatKey_.keyCode = 2;
    ASSERT_NO_FATAL_FAILURE(handler_->SendKeyEvent());
}

/**
 * @tc.name: RepeatKeyHandlerTest_CreateKeyEvent
 * @tc.desc: CreateKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, RepeatKeyHandlerTest_CreateKeyEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 2017;
    int32_t keyAction = KeyEvent::KEY_ACTION_DOWN;
    bool isPressed = true;
    ASSERT_NE(handler_->CreateKeyEvent(keyCode, keyAction, isPressed), nullptr);
}

/**
 * @tc.name: IsCallScene_Normal_Branch_001
 * @tc.desc: Test callState Normal Branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, IsCallScene_Normal_Branch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::Want want;
    want.SetParam("state", 0);
    EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 0;
    DEVICE_MONITOR->SetCallState(data, callState);
    EXPECT_FALSE(handler_->IsCallScene());

    want.SetParam("state", 1);
    data.SetWant(want);
    callState = 1;
    DEVICE_MONITOR->SetCallState(data, callState);
    EXPECT_FALSE(handler_->IsCallScene());

    want.SetParam("state", 4);
    data.SetWant(want);
    callState = 4;
    DEVICE_MONITOR->SetCallState(data, callState);
    EXPECT_FALSE(handler_->IsCallScene());

    want.SetParam("state", 9);
    data.SetWant(want);
    callState = 9;
    DEVICE_MONITOR->SetCallState(data, callState);
    EXPECT_FALSE(handler_->IsCallScene());

    want.SetParam("state", 3);
    data.SetWant(want);
    callState = 3;
    DEVICE_MONITOR->SetCallState(data, callState);
    EXPECT_FALSE(handler_->IsCallScene());
}

/**
 * @tc.name: IsCallScene_Normal_Branch_002
 * @tc.desc: Test voipCallState Normal Branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, IsCallScene_Normal_Branch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::Want want;
    want.SetParam("state", 0);
    EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 0;
    DEVICE_MONITOR->SetVoipCallState(data, callState);
    EXPECT_FALSE(handler_->IsCallScene());

    want.SetParam("state", 1);
    data.SetWant(want);
    callState = 1;
    DEVICE_MONITOR->SetVoipCallState(data, callState);
    EXPECT_FALSE(handler_->IsCallScene());

    want.SetParam("state", 4);
    data.SetWant(want);
    callState = 4;
    DEVICE_MONITOR->SetVoipCallState(data, callState);
    EXPECT_FALSE(handler_->IsCallScene());

    want.SetParam("state", 9);
    data.SetWant(want);
    callState = 9;
    DEVICE_MONITOR->SetVoipCallState(data, callState);
    EXPECT_FALSE(handler_->IsCallScene());

    want.SetParam("state", 3);
    data.SetWant(want);
    callState = 3;
    DEVICE_MONITOR->SetVoipCallState(data, callState);
    EXPECT_FALSE(handler_->IsCallScene());
}

/**
 * @tc.name: IsCallScene_Abnormal_Branch_003
 * @tc.desc: Test IsCallScene Abnormal Branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RepeatKeyHandlerTest, IsCallScene_Abnormal_Branch_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::Want want;
    want.SetParam("state", 8);
    EventFwk::CommonEventData data;
    data.SetWant(want);
    int callState = 8;
    DEVICE_MONITOR->SetVoipCallState(data, callState);
    EXPECT_FALSE(handler_->IsCallScene());
}
} // namespace MMI
} // namespace OHOS

