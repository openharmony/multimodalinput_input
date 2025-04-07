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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <fstream>

#include "libinput-private.h"

#include "input_device_impl.h"
#include "key_auto_repeat.h"
#include "mmi_log.h"
#include "uds_server.h"
#include "uds_session.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputDeviceImplTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class MockUDSSession : public UDSSession {
public:
    MOCK_METHOD1(SendMsg, int32_t(NetPacket &));
    MockUDSSession(const std::string &programName, const int32_t moduleType, const int32_t fd, const int32_t uid,
        const int32_t pid) : UDSSession(programName, moduleType, fd, uid, pid) {}
};

class MockInputDevice {
public:
    MOCK_METHOD1(SetId, void(int32_t deviceId));
    MOCK_METHOD0(MakeVirtualDeviceInfo, int());
};

/**
 * @tc.name: InputDeviceImplTest_GetInputDeviceIds_001
 * @tc.desc: Test the function GetInputDeviceIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceImplTest, InputDeviceImplTest_GetInputDeviceIds_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceImpl manager;
    InputDeviceImpl::InputDeviceInfo info1;
    info1.networkIdOrigin = "device1";
    info1.enable = true;
    manager.inputDevice_[1] = info1;
    InputDeviceImpl::InputDeviceInfo info2;
    info2.networkIdOrigin = "device2";
    info2.enable = false;
    manager.inputDevice_[2] = info2;
    InputDeviceImpl::InputDeviceInfo info3;
    info3.networkIdOrigin = "device3";
    info3.enable = true;
    manager.inputDevice_[3] = info3;
    auto ids = manager.GetInputDeviceIds();
    ASSERT_EQ(ids.size(), 3);
    EXPECT_EQ(ids[0], 1);
    EXPECT_EQ(ids[1], 2);
}

/**
 * @tc.name: InputDeviceImplTest_SupportKeys_001
 * @tc.desc: Test the function SupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceImplTest, InputDeviceImplTest_SupportKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceImpl manager;
    InputDeviceImpl::InputDeviceInfo info;
    info.networkIdOrigin = "device1";
    info.enable = true;
    manager.inputDevice_[1] = info;
    std::vector<int32_t> keyCodes = {1};
    std::vector<bool> keystroke;
    int32_t ret = manager.SupportKeys(1, keyCodes, keystroke);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_EQ(keystroke.size(), 1);
    EXPECT_EQ(keystroke[0], true);
}

/**
 * @tc.name: InputDeviceImplTest_GetKeyboardType_001
 * @tc.desc: Test the function GetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceImplTest, InputDeviceImplTest_GetKeyboardType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceImpl InputDeviceImpl;
    int32_t deviceId = 1;
    int32_t keyboardType = 0;
    std::shared_ptr<InputDevice> device = std::make_shared<InputDevice>();
    InputDeviceImpl.virtualInputDevices_.insert(std::make_pair(deviceId, device));
    EXPECT_EQ(InputDeviceImpl.GetKeyboardType(deviceId, keyboardType), RET_OK);
    EXPECT_EQ(keyboardType, KEYBOARD_TYPE_NONE);
}

/**
 * @tc.name: InputDeviceImplTest_GetKeyboardType_002
 * @tc.desc: Test the function GetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceImplTest, InputDeviceImplTest_GetKeyboardType_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceImpl InputDeviceImpl;
    int32_t deviceId = 2;
    int32_t keyboardType = 0;
    std::shared_ptr<InputDevice> device = std::make_shared<InputDevice>();
    InputDeviceImpl.virtualInputDevices_.insert(std::make_pair(deviceId, device));
    EXPECT_EQ(InputDeviceImpl.GetKeyboardType(deviceId, keyboardType), RET_OK);
    EXPECT_EQ(keyboardType, KEYBOARD_TYPE_NONE);
}

/**
 * @tc.name: InputDeviceImplTest_GetKeyboardType_003
 * @tc.desc: Test the function GetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceImplTest, InputDeviceImplTest_GetKeyboardType_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceImpl InputDeviceImpl;
    int32_t deviceId = 3;
    int32_t keyboardType = 0;
    InputDeviceImpl.inputDevice_.insert(std::make_pair(deviceId, InputDeviceImpl::InputDeviceInfo()));
    InputDeviceImpl.inputDevice_[deviceId].enable = false;
    EXPECT_EQ(InputDeviceImpl.GetKeyboardType(deviceId, keyboardType), RET_ERR);
}

/**
 * @tc.name: InputDeviceImplTest_GetInputDevice_001
 * @tc.desc: Test the function GetInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceImplTest, InputDeviceImplTest_GetInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceImpl inputDevice;
    std::shared_ptr<InputDevice> inputDeviceImpl{nullptr};
    int32_t id = 1;
    bool checked = true;
    inputDeviceImpl = inputDevice.GetInputDevice(id, checked);
    EXPECT_EQ(inputDeviceManager, nullptr);
}

/**
 * @tc.name: InputDeviceImplTest_GetInputDeviceIds_001
 * @tc.desc: Test the function GetInputDeviceIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceImplTest, InputDeviceImplTest_GetInputDeviceIds_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceImpl inputDevice;
    ASSERT_NO_FATAL_FAILURE(inputDevice.GetInputDeviceIds());
}

/**
 * @tc.name: InputDeviceImplTest_SupportKeys_001
 * @tc.desc: Test the function SupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceImplTest, InputDeviceImplTest_SupportKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceImpl inputDevice;
    int32_t deviceId = 1;
    std::vector<int32_t> keyCodes{12};
    std::vector<bool> keystroke{true};
    int32_t returnCode = 401;
    int32_t ret = inputDevice.SupportKeys(deviceId, keyCodes, keystroke);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: InputDeviceImplTest_GetKeyboardType_001
 * @tc.desc: Test the function GetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceImplTest, InputDeviceImplTest_GetKeyboardType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceImpl inputDevice;
    int32_t deviceId = 1;
    int32_t keyboardType = 1;
    int32_t returnCode = 401;
    int32_t ret = inputDevice.GetKeyboardType(deviceId, keyboardType);
    EXPECT_EQ(ret, returnCode);
}
} // namespace MMI
} // namespace OHOS
 