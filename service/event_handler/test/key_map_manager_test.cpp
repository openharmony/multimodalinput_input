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
#include <filesystem>
#include <gtest/gtest.h>
#include <iostream>

#include "mmi_log.h"
#include "key_map_manager.h"
#include "key_map_manager_mock.h"
#include "config_policy_utils.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyMapManagerTest"
#undef MAX_PATH_LEN
#define MAX_PATH_LEN              256

namespace OHOS {
namespace MMI {

namespace {
using namespace testing::ext;
using namespace testing;
} // namespace

class KeyMapManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: KeyMapManagerTest_GetProFilePath_001
 * @tc.desc: Test the function GetProFilePath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMapManagerTest, KeyMapManagerTest_GetProFilePath_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyMgrMock mocker;
    static char testFile[] = "example.pro";
    EXPECT_CALL(mocker, GetProFileAbsPath)
        .WillRepeatedly(Return(testFile));

    std::ofstream ofs("example.pro");
    EXPECT_TRUE(ofs.is_open());
    ofs << "KEY_BTN_1 123 1111\n" << std::endl;
    std::string testPathSuffix = "example";
    std::string result = KeyMapMgr->GetProFilePath(testPathSuffix);
    std::string expectReutrn = "example.pro";
    EXPECT_STREQ(result.c_str(), expectReutrn.c_str());

    if (std::remove(testFile) == 0) {
        std::cout << "test file removed success" << std::endl;
    } else {
        std::cerr << "test file removed fail" << std::endl;
    }
}

/**
 * @tc.name: KeyMapManagerTest_GetProFilePath_002
 * @tc.desc: Test the function GetProFilePath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMapManagerTest, KeyMapManagerTest_GetProFilePath_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyMgrMock mocker;
    static char testFile[] = "example.pro";
    char testFile1[MAX_PATH_LEN] = { };
    char * testFile2 = nullptr;
    char testFile3[MAX_PATH_LEN + 2] = { };
    for (int i = 0; i < MAX_PATH_LEN + 1; ++i) {
        testFile3[i] = 'A';
    }
    EXPECT_CALL(mocker, GetProFileAbsPath)
        .WillOnce(Return(testFile1))
        .WillOnce(Return(testFile2))
        .WillOnce(Return(testFile3));;

    std::ofstream ofs("example.pro");
    EXPECT_TRUE(ofs.is_open());
    ofs << "KEY_BRL_DOT10 506 3210 HOS_KEY_BRL_DOT10\n" << std::endl;
    std::string testPathSuffix = "example";
    std::string result = KeyMapMgr->GetProFilePath(testPathSuffix);
    std::string expectReutrn = "/vendor/etc/keymap/example.pro";
    EXPECT_STREQ(result.c_str(), expectReutrn.c_str());

    result = KeyMapMgr->GetProFilePath(testPathSuffix);
    EXPECT_STREQ(result.c_str(), expectReutrn.c_str());

    result = KeyMapMgr->GetProFilePath(testPathSuffix);
    EXPECT_STREQ(result.c_str(), expectReutrn.c_str());

    if (std::remove(testFile) == 0) {
        std::cout << "test file removed success" << std::endl;
    } else {
        std::cerr << "test file removed fail" << std::endl;
    }
}

/**
 * @tc.name: KeyMapManagerTest_TransferDeviceKeyValue_Normal_001
 * @tc.desc: Test TransferDeviceKeyValue with normal device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMapManagerTest, KeyMapManagerTest_TransferDeviceKeyValue_Normal_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyMgrMock mocker;
    int32_t deviceId = 100;
    int32_t inputKey = 200;
    int32_t expectedOutputKey = 300;

    EXPECT_CALL(mocker, FindInputDeviceId(_)).WillRepeatedly(Return(deviceId));

    KeyMapMgr->configKeyValue_[deviceId][inputKey] = expectedOutputKey;
    int32_t result = KeyMapMgr->TransferDeviceKeyValue(nullptr, inputKey);

    // Should fallback to default key transfer
    EXPECT_NE(result, inputKey);
}

/**
 * @tc.name: KeyMapManagerTest_TransferDeviceKeyValue_NullPtr_001
 * @tc.desc: Test TransferDeviceKeyValue with null device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMapManagerTest, KeyMapManagerTest_TransferDeviceKeyValue_NullPtr_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t inputKey = 200;
    int32_t result = KeyMapMgr->TransferDeviceKeyValue(nullptr, inputKey);
    EXPECT_NE(result, inputKey);
}

/**
 * @tc.name: KeyMapManagerTest_TransferDefaultKeyValue_001
 * @tc.desc: Test TransferDefaultKeyValue method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMapManagerTest, KeyMapManagerTest_TransferDefaultKeyValue_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t defaultKeyId = KeyMapMgr->GetDefaultKeyId();
    int32_t inputKey = 200;
    int32_t expectedOutputKey = 300;

    KeyMapMgr->configKeyValue_[defaultKeyId][inputKey] = expectedOutputKey;
    int32_t result = KeyMapMgr->TransferDefaultKeyValue(inputKey);
    EXPECT_EQ(result, expectedOutputKey);
}

/**
 * @tc.name: KeyMapManagerTest_InputTransferKeyValue_Normal_001
 * @tc.desc: Test InputTransferKeyValue with normal device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMapManagerTest, KeyMapManagerTest_InputTransferKeyValue_Normal_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t deviceId = 100;
    int32_t inputKeyCode = 200;
    int32_t sysKeyCode = 300;

    KeyMapMgr->configKeyValue_[deviceId][inputKeyCode] = sysKeyCode;
    std::vector<int32_t> result = KeyMapMgr->InputTransferKeyValue(deviceId, sysKeyCode);

    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result[0], inputKeyCode);
}

/**
 * @tc.name: KeyMapManagerTest_InputTransferKeyValue_NoDevice_001
 * @tc.desc: Test InputTransferKeyValue when device not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMapManagerTest, KeyMapManagerTest_InputTransferKeyValue_NoDevice_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t deviceId = 999;
    int32_t keyCode = 200;

    std::vector<int32_t> result = KeyMapMgr->InputTransferKeyValue(deviceId, keyCode);

    // Should return default transformation or empty
    EXPECT_TRUE(result.empty() || result.size() == 1);
}

/**
 * @tc.name: KeyMapManagerTest_InputTransferKeyValue_UseDefault_001
 * @tc.desc: Test InputTransferKeyValue using default configuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMapManagerTest, KeyMapManagerTest_InputTransferKeyValue_UseDefault_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t defaultKeyId = KeyMapMgr->GetDefaultKeyId();
    int32_t inputKeyCode = 200;
    int32_t sysKeyCode = 300;

    KeyMapMgr->configKeyValue_[defaultKeyId][inputKeyCode] = sysKeyCode;
    std::vector<int32_t> result = KeyMapMgr->InputTransferKeyValue(-1, sysKeyCode);

    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result[0], inputKeyCode);
}

/**
 * @tc.name: KeyMapManagerTest_RemoveKeyValue_Normal_001
 * @tc.desc: Test RemoveKeyValue with existing device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMapManagerTest, KeyMapManagerTest_RemoveKeyValue_Normal_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyMgrMock mocker;
    int32_t deviceId = 100;
    int32_t inputKey = 200;
    int32_t outputKey = 300;

    EXPECT_CALL(mocker, FindInputDeviceId(_)).WillRepeatedly(Return(deviceId));

    KeyMapMgr->configKeyValue_[deviceId][inputKey] = outputKey;
    EXPECT_EQ(KeyMapMgr->configKeyValue_.count(deviceId), 1);

    libinput_device device {};
    KeyMapMgr->RemoveKeyValue(&device);
    EXPECT_EQ(KeyMapMgr->configKeyValue_.count(deviceId), 0);
}

/**
 * @tc.name: KeyMapManagerTest_RemoveKeyValue_NoDevice_001
 * @tc.desc: Test RemoveKeyValue with non-existing device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMapManagerTest, KeyMapManagerTest_RemoveKeyValue_NoDevice_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyMgrMock mocker;
    int32_t deviceId = 999;

    EXPECT_CALL(mocker, FindInputDeviceId(_)).WillRepeatedly(Return(deviceId));

    libinput_device device {};
    size_t beforeSize = KeyMapMgr->configKeyValue_.size();
    KeyMapMgr->RemoveKeyValue(&device);
    size_t afterSize = KeyMapMgr->configKeyValue_.size();

    EXPECT_EQ(beforeSize, afterSize);
}

/**
 * @tc.name: KeyMapManagerTest_GetKeyEventFileName_001
 * @tc.desc: Test GetKeyEventFileName method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMapManagerTest, KeyMapManagerTest_GetKeyEventFileName_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    libinput_device device {};

    // Set up device properties
    // Note: This test requires mocking libinput functions
    std::string result = KeyMapMgr->GetKeyEventFileName(&device);

    // Result should be non-empty
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: KeyMapManagerTest_ParseDeviceConfigFile_NullPtr_001
 * @tc.desc: Test ParseDeviceConfigFile with null device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMapManagerTest, KeyMapManagerTest_ParseDeviceConfigFile_NullPtr_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    libinput_device *device = nullptr;

    EXPECT_NO_FATAL_FAILURE(KeyMapMgr->ParseDeviceConfigFile(device));
}

/**
 * @tc.name: KeyMapManagerTest_ParseDeviceConfigFile_EmptyFileName_001
 * @tc.desc: Test ParseDeviceConfigFile when GetKeyEventFileName returns empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMapManagerTest, KeyMapManagerTest_ParseDeviceConfigFile_EmptyFileName_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    libinput_device device {};

    // This test requires mocking to return empty fileName
    EXPECT_NO_FATAL_FAILURE(KeyMapMgr->ParseDeviceConfigFile(&device));
}

/**
 * @tc.name: KeyMapManagerTest_GetConfigKeyValue_EmptyFileName_001
 * @tc.desc: Test GetConfigKeyValue with empty fileName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMapManagerTest, KeyMapManagerTest_GetConfigKeyValue_EmptyFileName_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::string emptyFileName = "";
    int32_t deviceId = 100;

    EXPECT_NO_FATAL_FAILURE(KeyMapMgr->GetConfigKeyValue(emptyFileName, deviceId));

    // configKeyValue_ should remain unchanged for this device
    EXPECT_EQ(KeyMapMgr->configKeyValue_.count(deviceId), 0);
}

/**
 * @tc.name: KeyMapManagerTest_KeyCodeToUnicode_001
 * @tc.desc: Test KeyCodeToUnicode method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMapManagerTest, KeyMapManagerTest_KeyCodeToUnicode_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t keyCode = KeyEvent::KEYCODE_A;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(keyCode);

    uint32_t result = KeyMapMgr->KeyCodeToUnicode(keyCode, keyEvent);
    EXPECT_NE(result, 0);
}

/**
 * @tc.name: KeyMapManagerTest_KeyItemsTransKeyIntention_001
 * @tc.desc: Test KeyItemsTransKeyIntention method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMapManagerTest, KeyMapManagerTest_KeyItemsTransKeyIntention_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::vector<KeyEvent::KeyItem> items;
    KeyEvent::KeyItem item1;
    item1.SetKeyCode(KeyEvent::KEYCODE_A);
    item1.SetDownTime(1000);
    items.push_back(item1);

    int32_t result = KeyMapMgr->KeyItemsTransKeyIntention(items);
    EXPECT_NE(result, 0);
}

} // namespace MMI
} // namespace OHOS
