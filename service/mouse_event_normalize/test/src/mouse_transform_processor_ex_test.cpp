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
 
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <linux/input.h>
 
#include "mmi_log.h"
#include "mock.h"
#include "mouse_transform_processor.h"
 
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MouseTransformProcessorExTest"
 
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;
}
class MouseTransformProcessorExTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
 
    static inline std::shared_ptr<MessageParcelMock> messageParcelMock_ = nullptr;
};
 
void MouseTransformProcessorExTest::SetUpTestCase(void)
{
    messageParcelMock_ = std::make_shared<MessageParcelMock>();
    MessageParcelMock::messageParcel = messageParcelMock_;
}
 
void MouseTransformProcessorExTest::TearDownTestCase(void)
{
    MessageParcelMock::messageParcel = nullptr;
    messageParcelMock_ = nullptr;
}
 
void MouseTransformProcessorExTest::SetUp() {}
 
void MouseTransformProcessorExTest::TearDown() {}
 
#ifndef OHOS_BUILD_ENABLE_WATCH
/**
 * @tc.name: MouseTransformProcessorTest_HandleTouchpadLeftButton_001
 * @tc.desc: Test the funcation HandleTouchpadRightButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorExTest, MouseTransformProcessorTest_HandleTouchpadLeftButton_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, libinput_event_pointer_get_finger_count()).WillOnce(Return(1));
    EXPECT_CALL(*messageParcelMock_, libinput_event_pointer_get_button_area()).WillOnce(Return(280));
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer* data = nullptr;
    int32_t eventType = 1;
    uint32_t button = 272;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadLeftButton(data, eventType, button));
}
 
/**
 * @tc.name: MouseTransformProcessorTest_HandleTouchpadLeftButton_002
 * @tc.desc: Test the funcation HandleTouchpadRightButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorExTest, MouseTransformProcessorTest_HandleTouchpadLeftButton_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, libinput_event_pointer_get_finger_count()).WillOnce(Return(1));
    EXPECT_CALL(*messageParcelMock_, libinput_event_pointer_get_button_area()).WillOnce(Return(273));
    int32_t deviceId = 0;
    MouseTransformProcessor processor(deviceId);
    struct libinput_event_pointer* data = nullptr;
    int32_t eventType = 1;
    uint32_t button = 272;
    ASSERT_NO_FATAL_FAILURE(processor.HandleTouchpadLeftButton(data, eventType, button));
}
#endif // OHOS_BUILD_ENABLE_WATCH

/**
 * @tc.name: MouseTransformProcessorTest_GetPointerLocation_001
 * @tc.desc: Test the funcation GetPointerLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseTransformProcessorExTest, MouseTransformProcessorTest_GetPointerLocation_001, TestSize.Level1)
{
    int32_t deviceId = 1;
    MouseTransformProcessor processor(deviceId);
    int32_t displayId = 0;
    double displayX = 0.0;
    double displayY = 0.0;
    int32_t ret = processor.GetPointerLocation(displayId, displayX, displayY);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(displayId, -1);
    EXPECT_EQ(displayX, 0);
    EXPECT_EQ(displayY, 0);
}
}
}
