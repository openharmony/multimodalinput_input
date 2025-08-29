/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "touchpad_transform_processor.h"
#include "libinput.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchPadTransformProcessorEXTest"

struct udev_device {
    uint32_t tags;
};

struct libinput_device {
    struct udev_device udevDev;
    unsigned int busType;
    unsigned int version;
    unsigned int product;
    unsigned int vendor;
    char name[9];
};

struct libinput_event {
    enum libinput_event_type type;
    struct libinput_device *device;
};

namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
constexpr int32_t DEFAULT_POINTER_ID { 0 };
} // namespace

class TouchPadTransformProcessorEXTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void TouchPadTransformProcessorEXTest::SetUpTestCase(void)
{
}

void TouchPadTransformProcessorEXTest::TearDownTestCase(void)
{
}

void TouchPadTransformProcessorEXTest::SetUp()
{
}

void TouchPadTransformProcessorEXTest::TearDown()
{
}

/**
 * @tc.name: TouchPadTransformProcessorEXTest_OnEvent_01
 * @tc.desc: Test SetTouchpadPinchSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorEXTest, TouchPadTransformProcessorEXTest_OnEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    libinput_event event;
    event.type = LIBINPUT_EVENT_TOUCHPAD_ACTION;
    struct libinput_device libDev {
        .udevDev { 2 },
        .busType = 1,
        .version = 1,
        .product = 1,
        .vendor = 1,
        .name = "test",
    };
    event.device = &libDev;
    ASSERT_TRUE(processor.OnEvent(&event) == nullptr);
}

/**
 * @tc.name: TouchPadTransformProcessorEXTest_OnEvent_02
 * @tc.desc: Test SetTouchpadPinchSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorEXTest, TouchPadTransformProcessorEXTest_OnEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    libinput_event event;
    event.type = static_cast<libinput_event_type>(51);
    struct libinput_device libDev {
        .udevDev { 2 },
        .busType = 1,
        .version = 1,
        .product = 1,
        .vendor = 1,
        .name = "test",
    };
    event.device = &libDev;
    ASSERT_TRUE(processor.OnEvent(&event) == nullptr);
}

/**
 * @tc.name: TouchPadTransformProcessorEXTest_OnEventTouchPadAction_01
 * @tc.desc: Test SetTouchpadPinchSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorEXTest, TouchPadTransformProcessorEXTest_OnEventTouchPadAction_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    libinput_event event;
    event.type = static_cast<libinput_event_type>(51);
    struct libinput_device libDev {
        .udevDev { 2 },
        .busType = 1,
        .version = 1,
        .product = 1,
        .vendor = 1,
        .name = "test",
    };
    event.device = &libDev;
    processor.pointerEvent_ = PointerEvent::Create();
    ASSERT_TRUE(processor.OnEventTouchPadAction(&event) == RET_OK);
}

/**
 * @tc.name: TouchPadTransformProcessorEXTest_SetActionPointerItem_01
 * @tc.desc: Test SetTouchpadPinchSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchPadTransformProcessorEXTest, TouchPadTransformProcessorEXTest_SetActionPointerItem_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    TouchPadTransformProcessor processor(deviceId);
    int64_t frameTime = 10000;
    processor.pointerEvent_ = PointerEvent::Create();
    processor.SetActionPointerItem(frameTime);
    PointerEvent::PointerItem item;
    processor.pointerEvent_->GetPointerItem(DEFAULT_POINTER_ID, item);
    ASSERT_TRUE(item.GetToolType() == PointerEvent::TOOL_TYPE_TOUCHPAD);
}
} // namespace MMI
} // namespace OHOS