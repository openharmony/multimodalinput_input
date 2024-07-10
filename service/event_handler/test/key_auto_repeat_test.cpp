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

#include <gtest/gtest.h>
#include <libinput.h>

#include "key_auto_repeat.h"
#include "mmi_log.h"
#include "i_preference_manager.h"
#include "timer_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyAutoRepeatTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t DEFAULT_KEY_REPEAT_DELAY = 500;
constexpr int32_t DEFAULT_KEY_REPEAT_RATE = 50;
constexpr int32_t MIN_KEY_REPEAT_RATE = 36;
const std::string KEYBOARD_FILE_NAME = "keyboard_settings.xml";
} // namespace

class KeyAutoRepeatTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: KeyAutoRepeatTest_AddDeviceConfig_001
 * @tc.desc: Test the funcation AddDeviceConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatTest, KeyAutoRepeatTest_AddDeviceConfig_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyAutoRepeat keyAutoRepeat;
    struct libinput_device *device = nullptr;
    int32_t result = keyAutoRepeat.AddDeviceConfig(device);
    EXPECT_NE(result, RET_OK);
}

/**
 * @tc.name: KeyAutoRepeatTest_SelectAutoRepeat_001
 * @tc.desc: Test the funcation SelectAutoRepeat
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatTest, KeyAutoRepeatTest_SelectAutoRepeat_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyAutoRepeat keyAutoRepeat;
    auto keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    int32_t timerId_ = 2;
    keyEvent->SetKeyCode(1);
    keyEvent->SetAction(KeyEvent::KEY_ACTION_DOWN);
    keyAutoRepeat.SelectAutoRepeat(keyEvent);
    EXPECT_EQ(timerId_, 2);
    timerId_ = TimerMgr->AddTimer(1, 1, nullptr);
    keyAutoRepeat.SelectAutoRepeat(keyEvent);
    EXPECT_EQ(timerId_, -1);
    keyEvent->SetAction(KeyEvent::KEY_ACTION_UP);
    keyAutoRepeat.SelectAutoRepeat(keyEvent);
    EXPECT_EQ(timerId_, -1);
}

/**
 * @tc.name: KeyAutoRepeatTest_GetTomlFilePath_001
 * @tc.desc: Test the funcation GetTomlFilePath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatTest, KeyAutoRepeatTest_GetTomlFilePath_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyAutoRepeat keyAutoRepeat;
    std::string fileName = "test";
    std::string expectedPath = "/vendor/etc/keymap/test.TOML";
    EXPECT_EQ(keyAutoRepeat.GetTomlFilePath(fileName), expectedPath);
    fileName = "";
    expectedPath = "/vendor/etc/keymap/.TOML";
    EXPECT_EQ(keyAutoRepeat.GetTomlFilePath(fileName), expectedPath);
}

/**
 * @tc.name: KeyAutoRepeatTest_GetIntervalTime_001
 * @tc.desc: Test the funcation GetIntervalTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatTest, KeyAutoRepeatTest_GetIntervalTime_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyAutoRepeat keyAutoRepeat;
    int32_t deviceId = 1;
    int32_t expected = DEFAULT_KEY_REPEAT_RATE;
    EXPECT_EQ(keyAutoRepeat.GetIntervalTime(deviceId), expected);
    int32_t unexpected = 0;
    EXPECT_NE(keyAutoRepeat.GetIntervalTime(deviceId), unexpected);
}

/**
 * @tc.name: KeyAutoRepeatTest_GetDelayTime_001
 * @tc.desc: Test the funcation GetDelayTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatTest, KeyAutoRepeatTest_GetDelayTime_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyAutoRepeat keyAutoRepeat;
    int32_t delayTime = keyAutoRepeat.GetDelayTime();
    EXPECT_EQ(delayTime, DEFAULT_KEY_REPEAT_DELAY);
}

/**
 * @tc.name: KeyAutoRepeatTest_GetKeyboardRepeatTime_001
 * @tc.desc: Test the funcation GetKeyboardRepeatTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatTest, KeyAutoRepeatTest_GetKeyboardRepeatTime_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyAutoRepeat keyAutoRepeat;
    int32_t deviceId = 1;
    bool isDelay = true;
    int32_t expectedRepeatTime = DEFAULT_KEY_REPEAT_DELAY;
    int32_t actualRepeatTime = keyAutoRepeat.GetKeyboardRepeatTime(deviceId, isDelay);
    EXPECT_EQ(expectedRepeatTime, actualRepeatTime);
    isDelay = false;
    expectedRepeatTime = DEFAULT_KEY_REPEAT_RATE;
    actualRepeatTime = keyAutoRepeat.GetKeyboardRepeatTime(deviceId, isDelay);
    EXPECT_EQ(expectedRepeatTime, actualRepeatTime);
}

/**
 * @tc.name: KeyAutoRepeatTest_GetAutoSwitch_001
 * @tc.desc: Test the funcation GetAutoSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatTest, KeyAutoRepeatTest_GetAutoSwitch_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyAutoRepeat keyAutoRepeat;
    std::map<int32_t, DeviceConfig> deviceConfig_;
    int32_t existingDeviceId = 1;
    DeviceConfig expectedConfig;
    deviceConfig_[existingDeviceId] = expectedConfig;
    ASSERT_NO_FATAL_FAILURE(keyAutoRepeat.GetAutoSwitch(existingDeviceId));
}

/**
 * @tc.name: KeyAutoRepeatTest_SetKeyboardRepeatDelay_001
 * @tc.desc: Test the funcation SetKeyboardRepeatDelay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatTest, KeyAutoRepeatTest_SetKeyboardRepeatDelay_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyAutoRepeat keyAutoRepeat;
    int32_t delay = 500;
    int32_t expectedResult = RET_OK;
    int32_t result = keyAutoRepeat.SetKeyboardRepeatDelay(delay);
    EXPECT_EQ(result, expectedResult);
    delay = 100;
    result = keyAutoRepeat.SetKeyboardRepeatDelay(delay);
    EXPECT_EQ(result, expectedResult);
    delay = 2000;
    result = keyAutoRepeat.SetKeyboardRepeatDelay(delay);
    EXPECT_EQ(result, expectedResult);
}

/**
 * @tc.name: KeyAutoRepeatTest_SetKeyboardRepeatRate_001
 * @tc.desc: Test the funcation SetKeyboardRepeatRate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatTest, KeyAutoRepeatTest_SetKeyboardRepeatRate_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyAutoRepeat keyAutoRepeat;
    int32_t rate = 500;
    int32_t expectedResult = RET_OK;
    int32_t result = keyAutoRepeat.SetKeyboardRepeatRate(rate);
    EXPECT_EQ(result, expectedResult);
    rate = 30;
    result = keyAutoRepeat.SetKeyboardRepeatRate(rate);
    EXPECT_EQ(result, expectedResult);
    rate = 101;
    result = keyAutoRepeat.SetKeyboardRepeatRate(rate);
    EXPECT_EQ(result, expectedResult);
    rate = -1;
    result = keyAutoRepeat.SetKeyboardRepeatRate(rate);
    EXPECT_EQ(result, expectedResult);
}

/**
 * @tc.name: KeyAutoRepeatTest_GetKeyboardRepeatDelay_001
 * @tc.desc: Test the funcation GetKeyboardRepeatDelay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatTest, KeyAutoRepeatTest_GetKeyboardRepeatDelay_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyAutoRepeat keyAutoRepeat;
    int32_t delay = 0;
    int32_t expectedDelay = 1000;
    EXPECT_EQ(keyAutoRepeat.GetKeyboardRepeatDelay(delay), RET_OK);
    EXPECT_EQ(delay, expectedDelay);
    delay = 100;
    EXPECT_EQ(keyAutoRepeat.GetKeyboardRepeatDelay(delay), RET_OK);
    EXPECT_EQ(delay, expectedDelay);
}

/**
 * @tc.name: KeyAutoRepeatTest_GetKeyboardRepeatRate_001
 * @tc.desc: Test the funcation GetKeyboardRepeatRate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatTest, KeyAutoRepeatTest_GetKeyboardRepeatRate_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyAutoRepeat keyAutoRepeat;
    int32_t rate = 0;
    EXPECT_EQ(keyAutoRepeat.GetKeyboardRepeatRate(rate), RET_OK);
    int32_t expectedRate = MIN_KEY_REPEAT_RATE;
    EXPECT_EQ(keyAutoRepeat.GetKeyboardRepeatRate(rate), RET_OK);
    EXPECT_EQ(rate, expectedRate);
    EXPECT_EQ(keyAutoRepeat.GetKeyboardRepeatRate(rate), RET_OK);
    EXPECT_EQ(rate, expectedRate);
    rate = 500;
    EXPECT_EQ(keyAutoRepeat.GetKeyboardRepeatRate(rate), RET_OK);
    EXPECT_EQ(rate, expectedRate);
}

/**
 * @tc.name: KeyAutoRepeatTest_PutConfigDataToDatabase_001
 * @tc.desc: Test the funcation PutConfigDataToDatabase
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatTest, KeyAutoRepeatTest_PutConfigDataToDatabase_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyAutoRepeat keyAutoRepeat;
    std::string testKey = "testKey";
    int32_t testValue = 123;
    int32_t result = keyAutoRepeat.PutConfigDataToDatabase(testKey, testValue);
    ASSERT_EQ(result, 0);
    ASSERT_TRUE(PREFERENCES_MGR->GetIntValue(testKey, testValue));
}

/**
 * @tc.name: KeyAutoRepeatTest_GetConfigDataFromDatabase_001
 * @tc.desc: Test the funcation GetConfigDataFromDatabase
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatTest, KeyAutoRepeatTest_GetConfigDataFromDatabase_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyAutoRepeat keyAutoRepeat;
    std::string key = "test_key";
    int32_t value = 0;
    PREFERENCES_MGR->SetIntValue(key, KEYBOARD_FILE_NAME, 42);
    int32_t ret = keyAutoRepeat.GetConfigDataFromDatabase(key, value);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(value, 0);
    key = "nonexistent_key";
    value = 0;
    ret = keyAutoRepeat.GetConfigDataFromDatabase(key, value);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(value, 0);
}
} // namespace MMI
} // namespace OHOS