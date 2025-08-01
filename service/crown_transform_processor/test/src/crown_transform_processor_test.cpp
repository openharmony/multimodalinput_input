/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "crown_transform_processor.h"
#include "general_crown.h"
#include "i_input_windows_manager.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "libinput_mock.h"
#include "libinput_wrapper.h"
#include "libinput.h"
#include "mmi_log.h"
#include "timer_manager.h"
#include "window_info.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "CrownTransformProcessorTest"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace MMI {
bool TimerManager::IsExist(int32_t timerId)
{
    return true;
}

class CrownTransformProcessorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CrownTransformProcessorTest::SetUpTestCase() {}

void CrownTransformProcessorTest::TearDownTestCase() {}

void CrownTransformProcessorTest::SetUp() {}

void CrownTransformProcessorTest::TearDown() {}

/* *
 * @tc.name: CrownTransformProcessorTest_GetPointerEvent_001
 * @tc.desc: Test the funcation GetPointerEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_GetPointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CrownTransformProcessor> processor = std::make_shared<CrownTransformProcessor>();
    auto ret = processor->GetPointerEvent();
    ASSERT_NE(ret, nullptr);
}

/* *
 * @tc.name: CrownTransformProcessorTest_IsCrownEvent_001
 * @tc.desc: Test the funcation IsCrownEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_IsCrownEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CrownTransformProcessor> processor = std::make_shared<CrownTransformProcessor>();
    libinput_event *event = nullptr;
    bool ret = processor->IsCrownEvent(event);
    EXPECT_FALSE(ret);
}

/* *
 * @tc.name: CrownTransformProcessorTest_IsCrownEvent_003
 * @tc.desc: Test the funcation IsCrownEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_IsCrownEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CrownTransformProcessor> processor = std::make_shared<CrownTransformProcessor>();
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_device device;
    libinput_event_pointer touchpadButtonEvent;
    EXPECT_CALL(libinputMock, GetDevice).WillOnce(Return(&device));
    EXPECT_CALL(libinputMock, DeviceGetName).WillOnce(Return(const_cast<char *>("rotary_crown")));
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_POINTER_AXIS));
    libinput_event event;
    bool ret = processor->IsCrownEvent(&event);
    EXPECT_FALSE(ret);
}

/* *
 * @tc.name: CrownTransformProcessorTest_IsCrownEvent_004
 * @tc.desc: Test the funcation IsCrownEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_IsCrownEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CrownTransformProcessor> processor = std::make_shared<CrownTransformProcessor>();
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_device device;
    libinput_event_pointer touchpadButtonEvent;
    EXPECT_CALL(libinputMock, GetDevice).WillOnce(Return(&device));
    EXPECT_CALL(libinputMock, DeviceGetName).WillOnce(Return(const_cast<char *>("Virtual Crown")));
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_NONE));
    libinput_event event;
    bool ret = processor->IsCrownEvent(&event);
    EXPECT_FALSE(ret);
}

/* *
 * @tc.name: CrownTransformProcessorTest_IsCrownEvent_005
 * @tc.desc: Test the funcation IsCrownEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_IsCrownEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CrownTransformProcessor> processor = std::make_shared<CrownTransformProcessor>();
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_device device;
    libinput_event_pointer touchpadButtonEvent;
    EXPECT_CALL(libinputMock, GetDevice).WillOnce(Return(&device));
    EXPECT_CALL(libinputMock, DeviceGetName).WillOnce(Return(const_cast<char *>("Other")));
    libinput_event event;
    bool ret = processor->IsCrownEvent(&event);
    EXPECT_FALSE(ret);
}

/* *
 * @tc.name: CrownTransformProcessorTest_NormalizeRotateEvent_001
 * @tc.desc: Test the funcation NormalizeRotateEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_NormalizeRotateEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CrownTransformProcessor> processor = std::make_shared<CrownTransformProcessor>();
    libinput_event *event = nullptr;
    int32_t ret = processor->NormalizeRotateEvent(event);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
}

/* *
 * @tc.name: CrownTransformProcessorTest_NormalizeRotateEvent_002
 * @tc.desc: Test the funcation NormalizeRotateEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_NormalizeRotateEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CrownTransformProcessor> processor = std::make_shared<CrownTransformProcessor>();
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_device *device = nullptr;
    EXPECT_CALL(libinputMock, GetDevice).WillOnce(Return(device));
    libinput_event event;
    int32_t ret = processor->NormalizeRotateEvent(&event);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
}

/* *
 * @tc.name: CrownTransformProcessorTest_NormalizeRotateEvent_003
 * @tc.desc: Test the funcation NormalizeRotateEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_NormalizeRotateEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CrownTransformProcessor> processor = std::make_shared<CrownTransformProcessor>();
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_event_pointer touchpadButtonEvent;
    libinput_device device;
    EXPECT_CALL(libinputMock, GetDevice).WillOnce(Return(&device));
    libinput_event event;
    int32_t ret = processor->NormalizeRotateEvent(&event);
    EXPECT_EQ(ret, RET_ERR);
}

/* *
 * @tc.name: CrownTransformProcessorTest_HandleCrownRotateBegin_001
 * @tc.desc: Test the funcation HandleCrownRotateBegin
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_HandleCrownRotateBegin_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CrownTransformProcessor> processor = std::make_shared<CrownTransformProcessor>();
    libinput_event_pointer *rawPointerEvent = nullptr;
    int32_t ret = processor->HandleCrownRotateBegin(rawPointerEvent);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
}

/* *
 * @tc.name: CrownTransformProcessorTest_HandleCrownRotateUpdate_001
 * @tc.desc: Test the funcation HandleCrownRotateUpdate
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_HandleCrownRotateUpdate_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CrownTransformProcessor> processor = std::make_shared<CrownTransformProcessor>();
    libinput_event_pointer *rawPointerEvent = nullptr;
    int32_t ret = processor->HandleCrownRotateUpdate(rawPointerEvent);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
}

/* *
 * @tc.name: CrownTransformProcessorTest_HandleCrownRotateEnd_001
 * @tc.desc: Test the funcation HandleCrownRotateEnd
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_HandleCrownRotateEnd_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CrownTransformProcessor> processor = std::make_shared<CrownTransformProcessor>();
    int32_t ret = processor->HandleCrownRotateEnd();
    EXPECT_EQ(ret, RET_OK);
}

/* *
 * @tc.name: CrownTransformProcessorTest_HandleCrownRotateBeginAndUpdate_001
 * @tc.desc: Test the funcation HandleCrownRotateBeginAndUpdate
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_HandleCrownRotateBeginAndUpdate_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CrownTransformProcessor> processor = std::make_shared<CrownTransformProcessor>();
    libinput_event_pointer *rawPointerEvent = nullptr;
    int32_t action = 0;
    int32_t ret = processor->HandleCrownRotateBeginAndUpdate(rawPointerEvent, action);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
}

/* *
 * @tc.name: CrownTransformProcessorTest_HandleCrownRotateBeginAndUpdate_002
 * @tc.desc: Test the funcation HandleCrownRotateBeginAndUpdate
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_HandleCrownRotateBeginAndUpdate_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CrownTransformProcessor> processor = std::make_shared<CrownTransformProcessor>();
    libinput_event_pointer *rawPointerEvent = nullptr;
    int32_t action = PointerEvent::POINTER_ACTION_UNKNOWN;
    int32_t ret = processor->HandleCrownRotateBeginAndUpdate(rawPointerEvent, action);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
}

/* *
 * @tc.name: CrownTransformProcessorTest_HandleCrownRotatePostInner_001
 * @tc.desc: Test the funcation HandleCrownRotatePostInner
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_HandleCrownRotatePostInner_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CrownTransformProcessor> processor = std::make_shared<CrownTransformProcessor>();
    processor->pointerEvent_ = nullptr;
    double velocity = 0;
    double degree = 0;
    int32_t action = 0;
    EXPECT_NO_FATAL_FAILURE(processor->HandleCrownRotatePostInner(velocity, degree, action));
}

/* *
 * @tc.name: CrownTransformProcessorTest_Dump_001
 * @tc.desc: Test the funcation Dump
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_Dump_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CrownTransformProcessor> processor = std::make_shared<CrownTransformProcessor>();
    processor->pointerEvent_ = nullptr;
    int32_t fd = -1;
    std::vector<std::string> args;
    EXPECT_NO_FATAL_FAILURE(processor->Dump(fd, args));
}
} // namespace MMI
} // namespace OHOS
