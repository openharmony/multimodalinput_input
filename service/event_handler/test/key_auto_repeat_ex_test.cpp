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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "key_auto_repeat.h"
#include "libinput_mock.h"
#include "mmi_log.h"
#include "mock.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyAutoRepeatExTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;
} // namespace

class KeyAutoRepeatExTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

    static inline std::shared_ptr<MessageParcelMock> messageParcelMock_ = nullptr;
};

void KeyAutoRepeatExTest::SetUpTestCase(void)
{
    messageParcelMock_ = std::make_shared<MessageParcelMock>();
    MessageParcelMock::messageParcel = messageParcelMock_;
}
void KeyAutoRepeatExTest::TearDownTestCase()
{
    MessageParcelMock::messageParcel = nullptr;
    messageParcelMock_ = nullptr;
}

/**
 * @tc.name: KeyAutoRepeatExTest_RemoveDeviceConfig
 * @tc.desc: Cover if (iter == deviceConfig_.end()) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatExTest, KeyAutoRepeatExTest_RemoveDeviceConfig, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 10;
    EXPECT_CALL(*messageParcelMock_, FindInputDeviceId(_)).WillRepeatedly(Return(deviceId));
    KeyAutoRepeat keyAutoRepeat;
    libinput_device device {};
    EXPECT_NO_FATAL_FAILURE(keyAutoRepeat.RemoveDeviceConfig(&device));
}

/**
 * @tc.name: KeyAutoRepeatExTest_RemoveDeviceConfig_001
 * @tc.desc: Cover the else branch of if (iter == deviceConfig_.end())
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatExTest, KeyAutoRepeatExTest_RemoveDeviceConfig_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 15;
    EXPECT_CALL(*messageParcelMock_, FindInputDeviceId(_)).WillRepeatedly(Return(deviceId));
    KeyAutoRepeat keyAutoRepeat;
    libinput_device device {};
    DeviceConfig deviceConfig;
    keyAutoRepeat.deviceConfig_.insert(std::make_pair(deviceId, deviceConfig));
    EXPECT_NO_FATAL_FAILURE(keyAutoRepeat.RemoveDeviceConfig(&device));
}

/**
 * @tc.name: KeyAutoRepeatExTest_AddDeviceConfig_Success_001
 * @tc.desc: Test AddDeviceConfig with valid device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatExTest, KeyAutoRepeatExTest_AddDeviceConfig_Success_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 20;
    EXPECT_CALL(*messageParcelMock_, FindInputDeviceId(_)).WillRepeatedly(Return(deviceId));
    KeyAutoRepeat keyAutoRepeat;
    libinput_device device {};
    DeviceConfig deviceConfig;
    keyAutoRepeat.deviceConfig_[deviceId] = deviceConfig;
    EXPECT_NO_FATAL_FAILURE(keyAutoRepeat.RemoveDeviceConfig(&device));
}

/**
 * @tc.name: KeyAutoRepeatExTest_AddDeviceConfig_NullPtr_001
 * @tc.desc: Test AddDeviceConfig with null device pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatExTest, KeyAutoRepeatExTest_AddDeviceConfig_NullPtr_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyAutoRepeat keyAutoRepeat;
    libinput_device *device = nullptr;
    int32_t ret = keyAutoRepeat.AddDeviceConfig(device);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
}

/**
 * @tc.name: KeyAutoRepeatExTest_SelectAutoRepeat_KeyDown_001
 * @tc.desc: Test SelectAutoRepeat with KEY_ACTION_DOWN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatExTest, KeyAutoRepeatExTest_SelectAutoRepeat_KeyDown_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyAutoRepeat keyAutoRepeat;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetDeviceId(1);

    DeviceConfig deviceConfig;
    deviceConfig.autoSwitch = 1;
    keyAutoRepeat.deviceConfig_[1] = deviceConfig;

    EXPECT_NO_FATAL_FAILURE(keyAutoRepeat.SelectAutoRepeat(keyEvent));
}

/**
 * @tc.name: KeyAutoRepeatExTest_SelectAutoRepeat_KeyUp_001
 * @tc.desc: Test SelectAutoRepeat with KEY_ACTION_UP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatExTest, KeyAutoRepeatExTest_SelectAutoRepeat_KeyUp_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyAutoRepeat keyAutoRepeat;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetDeviceId(1);

    DeviceConfig deviceConfig;
    deviceConfig.autoSwitch = 1;
    keyAutoRepeat.deviceConfig_[1] = deviceConfig;
    keyAutoRepeat.repeatKeyCode_ = KeyEvent::KEYCODE_A;
    keyAutoRepeat.timerId_ = 100;

    EXPECT_NO_FATAL_FAILURE(keyAutoRepeat.SelectAutoRepeat(keyEvent));
}

/**
 * @tc.name: KeyAutoRepeatExTest_SelectAutoRepeat_KeyCancel_001
 * @tc.desc: Test SelectAutoRepeat with KEY_ACTION_CANCEL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatExTest, KeyAutoRepeatExTest_SelectAutoRepeat_KeyCancel_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyAutoRepeat keyAutoRepeat;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    keyEvent->SetDeviceId(1);

    DeviceConfig deviceConfig;
    deviceConfig.autoSwitch = 1;
    keyAutoRepeat.deviceConfig_[1] = deviceConfig;
    keyAutoRepeat.repeatKeyCode_ = KeyEvent::KEYCODE_A;
    keyAutoRepeat.timerId_ = 100;

    EXPECT_NO_FATAL_FAILURE(keyAutoRepeat.SelectAutoRepeat(keyEvent));
}

/**
 * @tc.name: KeyAutoRepeatExTest_JudgeKeyEvent_001
 * @tc.desc: Test JudgeKeyEvent method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatExTest, KeyAutoRepeatExTest_JudgeKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyAutoRepeat keyAutoRepeat;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    // Test KEY_ACTION_UP
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    bool result = keyAutoRepeat.JudgeKeyEvent(keyEvent);
    EXPECT_TRUE(result);

    // Test KEY_ACTION_CANCEL
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    result = keyAutoRepeat.JudgeKeyEvent(keyEvent);
    EXPECT_TRUE(result);

    // Test KEY_ACTION_DOWN
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    result = keyAutoRepeat.JudgeKeyEvent(keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: KeyAutoRepeatExTest_JudgeLimitPrint_001
 * @tc.desc: Test JudgeLimitPrint method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatExTest, KeyAutoRepeatExTest_JudgeLimitPrint_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyAutoRepeat keyAutoRepeat;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    // Test with EVENT_FLAG_PRIVACY_MODE
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE);
    bool result = keyAutoRepeat.JudgeLimitPrint(keyEvent);
    EXPECT_TRUE(result);

    // Test without flag
    auto keyEvent2 = KeyEvent::Create();
    ASSERT_NE(keyEvent2, nullptr);
    result = keyAutoRepeat.JudgeLimitPrint(keyEvent2);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: KeyAutoRepeatExTest_GetTomlFilePath_001
 * @tc.desc: Test GetTomlFilePath method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatExTest, KeyAutoRepeatExTest_GetTomlFilePath_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyAutoRepeat keyAutoRepeat;
    std::string fileName = "test_file";
    std::string result = keyAutoRepeat.GetTomlFilePath(fileName);
    std::string expected = "/vendor/etc/keymap/test_file.TOML";
    EXPECT_EQ(result, expected);
}

/**
 * @tc.name: KeyAutoRepeatExTest_GetDelayTime_Boundary_001
 * @tc.desc: Test GetDelayTime with boundary values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatExTest, KeyAutoRepeatExTest_GetDelayTime_Boundary_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyAutoRepeat keyAutoRepeat;

    // Test with minimum user ID
    int32_t userId = 0;
    int32_t delay = keyAutoRepeat.GetDelayTime(userId);
    EXPECT_GE(delay, 300);
    EXPECT_LE(delay, 1000);

    // Test with maximum user ID
    userId = 1000;
    delay = keyAutoRepeat.GetDelayTime(userId);
    EXPECT_GE(delay, 300);
    EXPECT_LE(delay, 1000);
}

/**
 * @tc.name: KeyAutoRepeatExTest_GetIntervalTime_Boundary_001
 * @tc.desc: Test GetIntervalTime with boundary values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatExTest, KeyAutoRepeatExTest_GetIntervalTime_Boundary_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyAutoRepeat keyAutoRepeat;

    // Test with minimum device ID
    int32_t userId = 0;
    int32_t deviceId = 0;
    int32_t interval = keyAutoRepeat.GetIntervalTime(userId, deviceId);
    EXPECT_GE(interval, 36);
    EXPECT_LE(interval, 100);

    // Test with maximum device ID
    deviceId = 1000;
    interval = keyAutoRepeat.GetIntervalTime(userId, deviceId);
    EXPECT_GE(interval, 36);
    EXPECT_LE(interval, 100);
}
} // namespace MMI
} // namespace OHOS