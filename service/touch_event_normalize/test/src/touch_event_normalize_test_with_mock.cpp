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
#include "input_device_manager.h"
#include "touch_event_normalize.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchEventNormalizeTestWithMock"

namespace OHOS {
namespace MMI {
using namespace testing::ext;

class TouchEventNormalizeTestWithMock : public testing::Test {
public:
    void SetUp() {}
    void TearDown();
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
};

void TouchEventNormalizeTestWithMock::TearDown()
{
    InputDeviceManagerMock::ReleaseInstance();
}

/**
 * @tc.name: TouchEventNormalize_001
 * @tc.desc: Test the function MouseEventNormalize::TouchEventNormalize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTestWithMock, TouchEventNormalize_001, TestSize.Level1)
{
    EXPECT_CALL(*INPUT_DEV_MGR, Attach).Times(testing::Exactly(1));
    EXPECT_CALL(*INPUT_DEV_MGR, Detach).Times(testing::Exactly(1));
    TouchEventNormalize norm;
    EXPECT_NE(norm.inputDevObserver_, nullptr);
}

/**
 * @tc.name: SetUpDeviceObserver_001
 * @tc.desc: Test the function MouseEventNormalize::SetUpDeviceObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTestWithMock, SetUpDeviceObserver_001, TestSize.Level1)
{
    EXPECT_CALL(*INPUT_DEV_MGR, Attach).Times(testing::Exactly(1));
    EXPECT_CALL(*INPUT_DEV_MGR, Detach).Times(testing::Exactly(1));

    TouchEventNormalize norm;
    EXPECT_NO_FATAL_FAILURE(norm.SetUpDeviceObserver());
    EXPECT_NE(norm.inputDevObserver_, nullptr);
}

/**
 * @tc.name: SetUpDeviceObserver_002
 * @tc.desc: Test the function MouseEventNormalize::SetUpDeviceObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTestWithMock, SetUpDeviceObserver_002, TestSize.Level1)
{
    EXPECT_CALL(*INPUT_DEV_MGR, Attach).Times(testing::Exactly(2));
    EXPECT_CALL(*INPUT_DEV_MGR, Detach).Times(testing::Exactly(2));

    TouchEventNormalize norm;
    norm.TearDownDeviceObserver();
    EXPECT_NO_FATAL_FAILURE(norm.SetUpDeviceObserver());
    EXPECT_NE(norm.inputDevObserver_, nullptr);
}

/**
 * @tc.name: TearDownDeviceObserver_001
 * @tc.desc: Test the function TouchEventNormalize::TearDownDeviceObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTestWithMock, TearDownDeviceObserver_001, TestSize.Level1)
{
    EXPECT_CALL(*INPUT_DEV_MGR, Attach).Times(testing::Exactly(1));
    EXPECT_CALL(*INPUT_DEV_MGR, Detach).Times(testing::Exactly(1));

    TouchEventNormalize norm;
    EXPECT_NO_FATAL_FAILURE(norm.TearDownDeviceObserver());
    EXPECT_EQ(norm.inputDevObserver_, nullptr);
}

/**
 * @tc.name: TearDownDeviceObserver_002
 * @tc.desc: Test the function TouchEventNormalize::TearDownDeviceObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTestWithMock, TearDownDeviceObserver_002, TestSize.Level1)
{
    EXPECT_CALL(*INPUT_DEV_MGR, Attach).Times(testing::Exactly(2));
    EXPECT_CALL(*INPUT_DEV_MGR, Detach).Times(testing::Exactly(2));

    TouchEventNormalize norm;
    EXPECT_NO_FATAL_FAILURE(norm.TearDownDeviceObserver());

    norm.SetUpDeviceObserver();
    EXPECT_NO_FATAL_FAILURE(norm.TearDownDeviceObserver());
    EXPECT_EQ(norm.inputDevObserver_, nullptr);
}

/**
 * @tc.name: OnDeviceRemoved_001
 * @tc.desc: Test the function TouchEventNormalize::OnDeviceRemoved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTestWithMock, OnDeviceRemoved_001, TestSize.Level1)
{
    EXPECT_CALL(*INPUT_DEV_MGR, Attach).Times(testing::Exactly(1));
    EXPECT_CALL(*INPUT_DEV_MGR, Detach).Times(testing::Exactly(1));

    TouchEventNormalize norm;
    int32_t deviceId { 1 };
    auto processor = norm.MakeTransformProcessor(deviceId, TouchEventNormalize::DeviceType::TABLET_TOOL);
    auto [_, isNew] = norm.processors_.emplace(deviceId, processor);
    EXPECT_TRUE(isNew);
    EXPECT_NO_FATAL_FAILURE(norm.OnDeviceRemoved(deviceId));
    EXPECT_TRUE(norm.processors_.find(deviceId) == norm.processors_.end());
}

/**
 * @tc.name: OnDeviceRemoved_002
 * @tc.desc: Test the function TouchEventNormalize::OnDeviceRemoved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTestWithMock, OnDeviceRemoved_002, TestSize.Level1)
{
    EXPECT_CALL(*INPUT_DEV_MGR, Attach).Times(testing::Exactly(1));
    EXPECT_CALL(*INPUT_DEV_MGR, Detach).Times(testing::Exactly(1));

    TouchEventNormalize norm;
    int32_t deviceId { 1 };
    auto processor = norm.MakeTransformProcessor(deviceId, TouchEventNormalize::DeviceType::TOUCH_PAD);
    auto [_, isNew] = norm.touchpad_processors_.emplace(deviceId, processor);
    EXPECT_TRUE(isNew);
    EXPECT_NO_FATAL_FAILURE(norm.OnDeviceRemoved(deviceId));
    EXPECT_TRUE(norm.touchpad_processors_.find(deviceId) == norm.touchpad_processors_.end());
}

/**
 * @tc.name: OnDeviceRemoved_003
 * @tc.desc: Test the function TouchEventNormalize::OnDeviceRemoved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTestWithMock, OnDeviceRemoved_003, TestSize.Level1)
{
    EXPECT_CALL(*INPUT_DEV_MGR, Attach).Times(testing::Exactly(1));
    EXPECT_CALL(*INPUT_DEV_MGR, Detach).Times(testing::Exactly(1));

    TouchEventNormalize norm;
    int32_t deviceId { 1 };
    auto processor = norm.MakeTransformProcessor(deviceId, TouchEventNormalize::DeviceType::REMOTE_CONTROL);
    auto [_, isNew] = norm.remote_control_processors_.emplace(deviceId, processor);
    EXPECT_TRUE(isNew);
    EXPECT_NO_FATAL_FAILURE(norm.OnDeviceRemoved(deviceId));
    EXPECT_TRUE(norm.remote_control_processors_.find(deviceId) == norm.remote_control_processors_.end());
}

/**
 * @tc.name: OnDeviceRemoved_004
 * @tc.desc: Test the function TouchEventNormalize::OnDeviceRemoved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTestWithMock, OnDeviceRemoved_004, TestSize.Level1)
{
    EXPECT_CALL(*INPUT_DEV_MGR, Attach).Times(testing::Exactly(1));
    EXPECT_CALL(*INPUT_DEV_MGR, Detach).Times(testing::Exactly(1));

    TouchEventNormalize norm;
    int32_t deviceId { 1 };
    auto processor = norm.MakeTransformProcessor(deviceId, TouchEventNormalize::DeviceType::TABLET_TOOL);
    auto [_, isNew] = norm.processors_.emplace(deviceId, processor);
    EXPECT_TRUE(isNew);

    int32_t deviceId1 { 2 };
    EXPECT_NO_FATAL_FAILURE(norm.OnDeviceRemoved(deviceId1));
    auto iter = norm.processors_.find(deviceId);
    if (iter != norm.processors_.end()) {
        EXPECT_EQ(iter->second, processor);
    }
    EXPECT_TRUE(iter != norm.processors_.end());
}
} // namespace MMI
} // namespace OHOS