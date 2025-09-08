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

namespace OHOS {
namespace MMI {
using namespace testing::ext;

class InputDeviceManagerTestWithMock : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
};

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
    InputDeviceManager manager;
    EXPECT_TRUE(manager.observers_.empty());
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
    InputDeviceManager manager;
    EXPECT_NO_FATAL_FAILURE(manager.Attach(observer));
    EXPECT_TRUE(std::any_of(manager.observers_.cbegin(), manager.observers_.cend(),
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
    InputDeviceManager manager;
    manager.Attach(observer);
    EXPECT_NO_FATAL_FAILURE(manager.Detach(observer));
    EXPECT_TRUE(std::none_of(manager.observers_.cbegin(), manager.observers_.cend(),
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
    InputDeviceManager manager;
    manager.Attach(observer);
    int32_t deviceId { 1 };
    EXPECT_NO_FATAL_FAILURE(manager.NotifyDeviceAdded(deviceId));
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
    InputDeviceManager manager;
    manager.Attach(observer);
    int32_t deviceId { 1 };
    EXPECT_NO_FATAL_FAILURE(manager.NotifyDeviceRemoved(deviceId));
}
} // namespace MMI
} // namespace OHOS
