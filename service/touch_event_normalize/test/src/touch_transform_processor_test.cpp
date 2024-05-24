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

#include "define_multimodal.h"
#include "libinput.h"
#include "touch_transform_processor.h"

#include "libinput-private.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class TouchTransformProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

/**
 * @tc.name: TouchTransformProcessorTest_OnEventTouchDown_001
 * @tc.desc: Test the funcation OnEventTouchDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, OnEventTouchDown_001, TestSize.Level1)
{
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    libinput_event* event = nullptr;
    bool ret = processor.OnEventTouchDown(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TouchTransformProcessorTest_UpdatePointerItemProperties_001
 * @tc.desc: Test the funcation UpdatePointerItemProperties
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, UpdatePointerItemProperties_001, TestSize.Level1)
{
    PointerEvent::PointerItem item;
    EventTouch touchInfo;
    touchInfo.point.x = 10;
    touchInfo.point.y = 20;
    touchInfo.toolRect.point.x = 30;
    touchInfo.toolRect.point.y = 40;
    touchInfo.toolRect.width = 50;
    touchInfo.toolRect.height = 60;
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    processor.UpdatePointerItemProperties(item, touchInfo);
    ASSERT_EQ(item.GetDisplayX(), touchInfo.point.x);
    ASSERT_EQ(item.GetDisplayY(), touchInfo.point.y);
    ASSERT_EQ(item.GetDisplayXPos(), touchInfo.point.x);
    ASSERT_EQ(item.GetDisplayYPos(), touchInfo.point.y);
    ASSERT_EQ(item.GetToolDisplayX(), touchInfo.toolRect.point.x);
    ASSERT_EQ(item.GetToolDisplayY(), touchInfo.toolRect.point.y);
    ASSERT_EQ(item.GetToolWidth(), touchInfo.toolRect.width);
    ASSERT_EQ(item.GetToolHeight(), touchInfo.toolRect.height);
}

/**
 * @tc.name: TouchTransformProcessorTest_OnEventTouchMotion_001
 * @tc.desc: Test the funcation OnEventTouchMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, OnEventTouchMotion_001, TestSize.Level1)
{
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    libinput_event* event = nullptr;
    bool ret = processor.OnEventTouchMotion(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TouchTransformProcessorTest_OnEventTouchUp_001
 * @tc.desc: Test the funcation OnEventTouchUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, OnEventTouchUp_001, TestSize.Level1)
{
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    libinput_event* event = nullptr;
    bool ret = processor.OnEventTouchUp(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TouchTransformProcessorTest_GetTouchToolType_001
 * @tc.desc: Test the funcation GetTouchToolType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, GetTouchToolType_001, TestSize.Level1)
{
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    struct libinput_device *device = nullptr;
    int32_t toolType = processor.GetTouchToolType(device);
    ASSERT_EQ(toolType, PointerEvent::TOOL_TYPE_FINGER);
}

/**
 * @tc.name: TouchTransformProcessorTest_InitToolTypes_001
 * @tc.desc: Test the funcation InitToolTypes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchTransformProcessorTest, InitToolTypes_001, TestSize.Level1)
{
    int32_t deviceId = 6;
    TouchTransformProcessor processor(deviceId);
    processor.InitToolTypes();
    ASSERT_EQ(processor.vecToolType_.size(), 16);
    ASSERT_EQ(processor.vecToolType_[0].first, BTN_TOOL_PEN);
    ASSERT_EQ(processor.vecToolType_[0].second, PointerEvent::TOOL_TYPE_PEN);
    ASSERT_EQ(processor.vecToolType_[1].first, BTN_TOOL_RUBBER);
    ASSERT_EQ(processor.vecToolType_[1].second, PointerEvent::TOOL_TYPE_RUBBER);
    ASSERT_EQ(processor.vecToolType_[2].first, BTN_TOOL_BRUSH);
    ASSERT_EQ(processor.vecToolType_[2].second, PointerEvent::TOOL_TYPE_BRUSH);
    ASSERT_EQ(processor.vecToolType_[3].first, BTN_TOOL_PENCIL);
    ASSERT_EQ(processor.vecToolType_[3].second, PointerEvent::TOOL_TYPE_PENCIL);
    ASSERT_EQ(processor.vecToolType_[4].first, BTN_TOOL_AIRBRUSH);
    ASSERT_EQ(processor.vecToolType_[4].second, PointerEvent::TOOL_TYPE_AIRBRUSH);
    ASSERT_EQ(processor.vecToolType_[5].first, BTN_TOOL_FINGER);
    ASSERT_EQ(processor.vecToolType_[5].second, PointerEvent::TOOL_TYPE_FINGER);
    ASSERT_EQ(processor.vecToolType_[6].first, BTN_TOOL_MOUSE);
    ASSERT_EQ(processor.vecToolType_[6].second, PointerEvent::TOOL_TYPE_MOUSE);
    ASSERT_EQ(processor.vecToolType_[7].first, BTN_TOOL_LENS);
    ASSERT_EQ(processor.vecToolType_[7].second, PointerEvent::TOOL_TYPE_LENS);
}
} // namespace MMI
} // namespace OHOS