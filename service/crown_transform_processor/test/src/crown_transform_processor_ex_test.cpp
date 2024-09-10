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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <cstdio>

#include "crown_transform_processor.h"
#include "general_crown.h"
#include "i_input_windows_manager.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "libinput.h"
#include "libinput_mock.h"
#include "libinput_wrapper.h"
#include "mmi_log.h"
#include "window_info.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "CrownTransformProcessorExTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
}
class CrownTransformProcessorExTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CrownTransformProcessorExTest::SetUpTestCase(void)
{
}

void CrownTransformProcessorExTest::TearDownTestCase(void)
{
}

void CrownTransformProcessorExTest::SetUp()
{
}

void CrownTransformProcessorExTest::TearDown()
{
}

/**
 * @tc.name: CrownTransformProcessorExTest_IsCrownEvent_001
 * @tc.desc: Test GetPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorExTest, CrownTransformProcessorExTest_IsCrownEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    libinput_event event {};
    libinput_device device {};
    libinput_event_pointer pointer {};
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(&device));
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(const_cast<char*>("rotary_crown")));
    bool result = CROWN_EVENT_HDR->IsCrownEvent(&event);
    ASSERT_FALSE(result);
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(const_cast<char*>("Virtual Crown")));
    result = CROWN_EVENT_HDR->IsCrownEvent(&event);
    ASSERT_FALSE(result);
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_AXIS));
    EXPECT_CALL(libinputMock, LibinputGetPointerEvent).WillRepeatedly(Return(&pointer));
    EXPECT_CALL(libinputMock, GetAxisSource).WillRepeatedly(Return(LIBINPUT_POINTER_AXIS_SOURCE_FINGER));
    result = CROWN_EVENT_HDR->IsCrownEvent(&event);
    ASSERT_FALSE(result);
    EXPECT_CALL(libinputMock, GetAxisSource).WillRepeatedly(Return(LIBINPUT_POINTER_AXIS_SOURCE_WHEEL));
    result = CROWN_EVENT_HDR->IsCrownEvent(&event);
    ASSERT_TRUE(result);
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_MOTION));
    result = CROWN_EVENT_HDR->IsCrownEvent(&event);
    ASSERT_FALSE(result);
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(const_cast<char*>("ut_good")));
    result = CROWN_EVENT_HDR->IsCrownEvent(&event);
    ASSERT_FALSE(result);
}
} // namespace MMI
} // namespace OHOS