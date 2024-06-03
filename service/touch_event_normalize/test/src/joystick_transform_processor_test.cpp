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

#include <cstdio>
#include <gtest/gtest.h>

#include "joystick_transform_processor.h"
#include "libinput.h"
#include "libinput-private.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JoystickTransformProcessorTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}
class JoystickTransformProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: JoystickTransformProcessorTest_OnEvent_001
 * @tc.desc: Verify that JoystickTransformProcessor can correctly handle events when receive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickTransformProcessorTest, JoystickTransformProcessorTest_OnEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    JoystickTransformProcessor processor(deviceId);
    libinput_event *event = nullptr;
    std::shared_ptr<PointerEvent> ret = processor.OnEvent(event);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: JoystickTransformProcessorTest_OnEvent_002
 * @tc.desc: Verify that JoystickTransformProcessor can correctly handle events when receive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickTransformProcessorTest, JoystickTransformProcessorTest_OnEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    JoystickTransformProcessor processor(deviceId);
    libinput_event *event = nullptr;
    std::shared_ptr<PointerEvent> ret = processor.OnEvent(event);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: JoystickTransformProcessorTest_OnEventJoystickButton_001
 * @tc.desc: test OnEventJoystickButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickTransformProcessorTest, JoystickTransformProcessorTest_OnEventJoystickButton_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    JoystickTransformProcessor processor(deviceId);
    libinput_event* event = nullptr;
    bool ret = processor.OnEventJoystickButton(event);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: JoystickTransformProcessorTest_OnEventJoystickAxis_001
 * @tc.desc: test OnEventJoystickAxis
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickTransformProcessorTest, JoystickTransformProcessorTest_OnEventJoystickAxis_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    JoystickTransformProcessor processor(deviceId);
    libinput_event* event = nullptr;
    bool ret = processor.OnEventJoystickAxis(event);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: JoystickTransformProcessorTest_LibinputButtonToPointer_001
 * @tc.desc: test LibinputButtonToPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickTransformProcessorTest, JoystickTransformProcessorTest_LibinputButtonToPointer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    uint32_t button = 1;
    JoystickTransformProcessor processor(deviceId);
    int32_t ret = processor.LibinputButtonToPointer(button);
    ASSERT_EQ(ret, -1);
}

/**
 * @tc.name: JoystickTransformProcessorTest_LibinputButtonToPointer_002
 * @tc.desc: test LibinputButtonToPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickTransformProcessorTest, JoystickTransformProcessorTest_LibinputButtonToPointer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 6;
    uint32_t button = 312;
    JoystickTransformProcessor processor(deviceId);
    int32_t ret = processor.LibinputButtonToPointer(button);
    ASSERT_EQ(ret, 0);
}
} // namespace MMI
} // namespace OHOS
