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

#include "define_multimodal.h"
#include "device_observer.h"
#include "input_device_manager.h"
#include "mouse_event_normalize.h"
#include "preferences_manager_mock.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MouseEventNormalizeTestWithMock"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t DEFAULT_SPEED { 10 };
}
using namespace testing;
using namespace testing::ext;

class MouseEventNormalizeTestWithMock : public testing::Test {
public:
    void SetUp() {}
    void TearDown();
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
};

void MouseEventNormalizeTestWithMock::TearDown()
{
    InputDeviceManagerMock::ReleaseInstance();
    PreferencesManagerMock::ReleaseInstance();
}

class InputDeviceObserver : public IDeviceObserver {
public:
    MOCK_METHOD(void, OnDeviceAdded, (int32_t));
    MOCK_METHOD(void, OnDeviceRemoved, (int32_t));
    MOCK_METHOD(void, UpdatePointerDevice, (bool, bool, bool));
};

/**
 * @tc.name: MouseEventNormalize_001
 * @tc.desc: Test the function MouseEventNormalize::MouseEventNormalize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTestWithMock, MouseEventNormalize_001, TestSize.Level1)
{
    EXPECT_CALL(*INPUT_DEV_MGR, Attach).Times(testing::Exactly(1));
    EXPECT_CALL(*INPUT_DEV_MGR, Detach).Times(testing::Exactly(1));
    MouseEventNormalize norm;
    EXPECT_NE(norm.inputDevObserver_, nullptr);
}

/**
 * @tc.name: SetUpDeviceObserver_001
 * @tc.desc: Test the function MouseEventNormalize::SetUpDeviceObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTestWithMock, SetUpDeviceObserver_001, TestSize.Level1)
{
    EXPECT_CALL(*INPUT_DEV_MGR, Attach).Times(testing::Exactly(1));
    EXPECT_CALL(*INPUT_DEV_MGR, Detach).Times(testing::Exactly(1));

    MouseEventNormalize norm;
    EXPECT_NO_FATAL_FAILURE(norm.SetUpDeviceObserver());
    EXPECT_NE(norm.inputDevObserver_, nullptr);
}

/**
 * @tc.name: SetUpDeviceObserver_002
 * @tc.desc: Test the function MouseEventNormalize::SetUpDeviceObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTestWithMock, SetUpDeviceObserver_002, TestSize.Level1)
{
    EXPECT_CALL(*INPUT_DEV_MGR, Attach).Times(testing::Exactly(2));
    EXPECT_CALL(*INPUT_DEV_MGR, Detach).Times(testing::Exactly(2));

    MouseEventNormalize norm;
    norm.TearDownDeviceObserver();
    EXPECT_NO_FATAL_FAILURE(norm.SetUpDeviceObserver());
    EXPECT_NE(norm.inputDevObserver_, nullptr);
}

/**
 * @tc.name: TearDownDeviceObserver_001
 * @tc.desc: Test the function MouseEventNormalize::TearDownDeviceObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTestWithMock, TearDownDeviceObserver_001, TestSize.Level1)
{
    EXPECT_CALL(*INPUT_DEV_MGR, Attach).Times(testing::Exactly(1));
    EXPECT_CALL(*INPUT_DEV_MGR, Detach).Times(testing::Exactly(1));

    MouseEventNormalize norm;
    EXPECT_NO_FATAL_FAILURE(norm.TearDownDeviceObserver());
    EXPECT_EQ(norm.inputDevObserver_, nullptr);
}

/**
 * @tc.name: TearDownDeviceObserver_002
 * @tc.desc: Test the function MouseEventNormalize::TearDownDeviceObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTestWithMock, TearDownDeviceObserver_002, TestSize.Level1)
{
    EXPECT_CALL(*INPUT_DEV_MGR, Attach).Times(testing::Exactly(2));
    EXPECT_CALL(*INPUT_DEV_MGR, Detach).Times(testing::Exactly(2));

    MouseEventNormalize norm;
    EXPECT_NO_FATAL_FAILURE(norm.TearDownDeviceObserver());

    norm.SetUpDeviceObserver();
    EXPECT_NO_FATAL_FAILURE(norm.TearDownDeviceObserver());
    EXPECT_EQ(norm.inputDevObserver_, nullptr);
}

/**
 * @tc.name: OnDeviceRemoved_001
 * @tc.desc: Test the function MouseEventNormalize::OnDeviceRemoved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTestWithMock, OnDeviceRemoved_001, TestSize.Level1)
{
    EXPECT_CALL(*INPUT_DEV_MGR, Attach).Times(testing::Exactly(1));
    EXPECT_CALL(*INPUT_DEV_MGR, Detach).Times(testing::Exactly(1));
    EXPECT_CALL(*PREFERENCES_MGR_MOCK, GetIntValue).WillOnce(Return(DEFAULT_SPEED));

    MouseEventNormalize norm;
    int32_t deviceId { 1 };
    auto [iter, _] = norm.processors_.emplace(deviceId, std::make_shared<MouseTransformProcessor>(deviceId));
    auto processor = iter->second;

    int32_t deviceId1 { 2 };
    EXPECT_NO_FATAL_FAILURE(norm.OnDeviceRemoved(deviceId1));
    auto iter1 = norm.processors_.find(deviceId);
    if (iter1 != norm.processors_.end()) {
        EXPECT_EQ(iter1->second, processor);
    }
    EXPECT_TRUE(iter1 != norm.processors_.end());

    EXPECT_NO_FATAL_FAILURE(norm.OnDeviceRemoved(deviceId));
    EXPECT_TRUE(norm.processors_.find(deviceId) == norm.processors_.end());
}
} // namespace MMI
} // namespace OHOS