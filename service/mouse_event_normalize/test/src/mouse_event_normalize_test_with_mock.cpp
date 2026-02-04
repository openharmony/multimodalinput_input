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
#include "i_input_device_manager.h"
#include "libinput_interface.h"
#include "input_device_manager.h"
#include "input_service_context.h"
#include "mouse_event_interface.h"
#include "mouse_event_normalize.h"
#include "preferences_manager_mock.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MouseEventNormalizeTestWithMock"

namespace OHOS {
namespace MMI {

using namespace testing;
using namespace testing::ext;

class MouseEventNormalizeTestWithMock : public testing::Test {
public:
    void SetUp() {}
    void TearDown();
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    InputServiceContext env_ {};
};

void MouseEventNormalizeTestWithMock::TearDown() {}

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
    MouseEventNormalize norm(&env_);
    EXPECT_NE(norm.env_, nullptr);
    int32_t deviceId { 1 };
    norm.OnDeviceAdded(deviceId);
    std::shared_ptr<MouseTransformProcessor> processor = norm.GetProcessor(deviceId);
    EXPECT_EQ(processor, nullptr);
}

/**
 * @tc.name: OnDeviceRemoved_001
 * @tc.desc: Test the function MouseEventNormalize::OnDeviceRemoved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTestWithMock, OnDeviceRemoved_001, TestSize.Level1)
{
    struct libinput_device rawDev {
        .udevDev { 1 },
        .busType = 1,
        .version = 1,
        .product = 1,
        .vendor = 1,
        .name = "test",
    };
    MouseEventNormalize norm(&env_);
    int32_t deviceId { 1 };
    norm.OnDeviceAdded(deviceId);
    norm.OnDeviceRemoved(deviceId);
    EXPECT_TRUE(norm.processors_.find(deviceId) == norm.processors_.end());
}

/**
 * @tc.name: MouseEventNormalize_002
 * @tc.desc: Test the function MouseEventNormalize::MouseEventNormalize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTestWithMock, MouseEventNormalize_002, TestSize.Level1)
{
    MouseEventNormalize norm(&env_);
    EXPECT_NE(norm.env_, nullptr);
    int32_t deviceId { 1 };
    norm.OnDeviceAdded(deviceId);
    std::shared_ptr<PointerEvent> pointerEvent = norm.GetPointerEvent(deviceId);
    EXPECT_EQ(pointerEvent, nullptr);
}

/**
 * @tc.name: MouseEventNormalize_003
 * @tc.desc: Test the function MouseEventNormalize::MouseEventNormalize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTestWithMock, MouseEventNormalize_003, TestSize.Level1)
{
    MouseEventNormalize norm(&env_);
    EXPECT_NE(norm.env_, nullptr);
    int32_t x { 1 };
    int32_t y { 1 };
    int32_t displayId { 1 };
    double displayX { 1 };
    double displayY { 1 };
    int32_t ret = norm.SetPointerLocation(x, y, displayId);
    ret = norm.GetPointerLocation(displayId, displayX, displayY);
    EXPECT_EQ(ret, RET_OK);
}
} // namespace MMI
} // namespace OHOS