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
#include "input_device_manager.h"
#include "key_auto_repeat.h"
#include "key_map_manager.h"
#include "libinput_mock.h"
#include "switch_subscriber_handler.h"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

void SwitchSubscriberHandler::SyncSwitchLidState(struct libinput_device *inputDevice) {}
void SwitchSubscriberHandler::SyncSwitchTabletState(struct libinput_device *inputDevice) {}

class InputDeviceManagerTestWithMock : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void InputDeviceManagerTestWithMock::SetUpTestCase()
{}

void InputDeviceManagerTestWithMock::TearDownTestCase()
{
    KeyMapManager::ReleaseInstance();
    KeyAutoRepeat::ReleaseInstance();
}

class InputDeviceObserver : public IDeviceObserver {
public:
    MOCK_METHOD(void, OnDeviceAdded, (int32_t));
    MOCK_METHOD(void, OnDeviceRemoved, (int32_t));
    MOCK_METHOD(void, UpdatePointerDevice, (bool, bool, bool));
};

/**
 * @tc.name: InputDeviceManager_001
 * @tc.desc: Test the function InputDeviceManager::InputDeviceManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, InputDeviceManager_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(INPUT_DEV_MGR->observers_.empty());
}

/**
 * @tc.name: GetLibinputDevice_001
 * @tc.desc: Test the function InputDeviceManager::GetLibinputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, GetLibinputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 888 };
    auto dev = INPUT_DEV_MGR->GetLibinputDevice(deviceId);
    EXPECT_EQ(dev, nullptr);
}

/**
 * @tc.name: GetLibinputDevice_002
 * @tc.desc: Test the function InputDeviceManager::GetLibinputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, GetLibinputDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    char sysName[] { "event1" };
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(sysName));
    EXPECT_CALL(libinputMock, DeviceGetSysname).WillRepeatedly(Return(sysName));
    EXPECT_CALL(*KeyMapMgr, InputTransferKeyValue).WillRepeatedly(Return(std::vector<int32_t>()));
    EXPECT_CALL(*KeyRepeat, GetDeviceConfig).WillRepeatedly(Return(std::map<int32_t, DeviceConfig>()));

    libinput_device rawDev {};
    INPUT_DEV_MGR->OnInputDeviceAdded(&rawDev);

    int32_t deviceId { 1 };
    auto dev = INPUT_DEV_MGR->GetLibinputDevice(deviceId);
    EXPECT_EQ(dev, &rawDev);
}

/**
 * @tc.name: Attach_001
 * @tc.desc: Test the function InputDeviceManager::Attach
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, Attach_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto observer = std::make_shared<InputDeviceObserver>();
    EXPECT_NO_FATAL_FAILURE(INPUT_DEV_MGR->Attach(observer));
    EXPECT_TRUE(std::any_of(INPUT_DEV_MGR->observers_.cbegin(), INPUT_DEV_MGR->observers_.cend(),
        [observer](const auto &item) {
            return (observer == item);
        }));
}

/**
 * @tc.name: Detach_001
 * @tc.desc: Test the function InputDeviceManager::Detach
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, Detach_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto observer = std::make_shared<InputDeviceObserver>();
    INPUT_DEV_MGR->Attach(observer);
    EXPECT_NO_FATAL_FAILURE(INPUT_DEV_MGR->Detach(observer));
    EXPECT_TRUE(std::none_of(INPUT_DEV_MGR->observers_.cbegin(), INPUT_DEV_MGR->observers_.cend(),
        [observer](const auto &item) {
            return (observer == item);
        }));
}

/**
 * @tc.name: NotifyDeviceAdded_001
 * @tc.desc: Test the function InputDeviceManager::NotifyDeviceAdded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, NotifyDeviceAdded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto observer = std::make_shared<InputDeviceObserver>();
    EXPECT_CALL(*observer, OnDeviceAdded).Times(testing::Exactly(1));
    INPUT_DEV_MGR->Attach(observer);
    int32_t deviceId { 1 };
    EXPECT_NO_FATAL_FAILURE(INPUT_DEV_MGR->NotifyDeviceAdded(deviceId));
}

/**
 * @tc.name: NotifyDeviceRemoved_001
 * @tc.desc: Test the function InputDeviceManager::NotifyDeviceRemoved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceManagerTestWithMock, NotifyDeviceRemoved_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto observer = std::make_shared<InputDeviceObserver>();
    EXPECT_CALL(*observer, OnDeviceRemoved).Times(testing::Exactly(1));
    INPUT_DEV_MGR->Attach(observer);
    int32_t deviceId { 1 };
    EXPECT_NO_FATAL_FAILURE(INPUT_DEV_MGR->NotifyDeviceRemoved(deviceId));
}
} // namespace MMI
} // namespace OHOS
