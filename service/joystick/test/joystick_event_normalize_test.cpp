/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "joystick_event_normalize.h"
#include "mmi_log.h"
#include "define_multimodal.h"
#include "input_device_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JoystickEventNormalizeTest"

struct udev_device {
    uint32_t tags;
};

struct libinput_device {
    struct udev_device udevDev;
    unsigned int busType;
    unsigned int version;
    unsigned int product;
    unsigned int vendor;
    std::string name;
};

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class JoystickEventNormalizeTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: JoystickEventNormalizeTest_CheckIntention
 * @tc.desc: Test GetMouseCoordsX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventNormalizeTest, JoystickEventNormalizeTest_CheckIntention, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventNormalize>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetDeviceId(2);
    std::shared_ptr<JoystickEventProcessor> proceSsor;
    struct libinput_device libDev {
        .udevDev { 2 },
        .busType = 1,
        .version = 1,
        .product = 1,
        .vendor = 1,
        .name = "test",
    };
    joystickEvent->processors_.insert(
        pair<struct libinput_device*, std::shared_ptr<JoystickEventProcessor>>(&libDev, proceSsor));
    ASSERT_NO_FATAL_FAILURE(
        joystickEvent->CheckIntention(pointerEvent, [=] (std::shared_ptr<KeyEvent>) { return; }));
}

/**
 * @tc.name: JoystickEventNormalizeTest_GetProcessor
 * @tc.desc: Test GetProcessor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventNormalizeTest, JoystickEventNormalizeTest_GetProcessor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventNormalize>();
    libinput_device libDev;
    ASSERT_NE(joystickEvent->GetProcessor(&libDev), nullptr);
}

/**
 * @tc.name: JoystickEventNormalizeTest_FindProcessor
 * @tc.desc: Test FindProcessor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventNormalizeTest, JoystickEventNormalizeTest_FindProcessor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventNormalize>();
    int32_t deviceId = 2;
    ASSERT_EQ(joystickEvent->FindProcessor(deviceId), nullptr);
}

/**
 * @tc.name: JoystickEventNormalizeTest_FindProcessor_002
 * @tc.desc: Test FindProcessor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventNormalizeTest, JoystickEventNormalizeTest_FindProcessor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventNormalize>();
    int32_t deviceId = 2;
    struct libinput_device libDev {
        .udevDev { 2 },
        .busType = 1,
        .version = 1,
        .product = 1,
        .vendor = 1,
        .name = "test",
    };
    auto joystickEventProcessor = std::make_shared<JoystickEventProcessor>(deviceId);
    joystickEvent->processors_.insert(std::make_pair(&libDev, joystickEventProcessor));
    ASSERT_EQ(joystickEvent->FindProcessor(deviceId), joystickEventProcessor);
}
} // namespace MMI
} // namespace OHOS
