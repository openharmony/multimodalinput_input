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

#include <gmock/gmock.h>

#include <dlfcn.h>
#include "define_multimodal.h"
#include "fingersense_wrapper.h"
#include "pointer_event.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "FingersenseWrapperTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;

const float EPSILON = 10.0;
} // namespace
class FingersenseWrapperTest : public testing::Test {
public:
    static void SetUpTestCase(void){};
    static void TearDownTestCase(void){};
    void SetUp()
    {
        wrapper_ = std::make_shared<FingersenseWrapper>();
    };
    void TearDown(){};

    std::shared_ptr<FingersenseWrapper> wrapper_;
};

#ifdef OHOS_BUILD_ENABLE_FINGERSENSE
/* *
 * @tc.name  : CrownTransformProcessorTest_SaveTouchInfo_001
 * @tc.desc: Test the function SaveTouchInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(FingersenseWrapperTest, CrownTransformProcessorTest_SaveTouchInfo_001, TestSize.Level1)
{
    float pointX = 10.0f;
    float pointY = 20.0f;
    int32_t toolType = 1;
    wrapper_->SaveTouchInfo(pointX, pointY, toolType);

    EXPECT_EQ(wrapper_->touchInfos_.size(), 1);
    EXPECT_EQ(wrapper_->touchInfos_[0].x, pointX);
    EXPECT_EQ(wrapper_->touchInfos_[0].y, pointY);
    EXPECT_EQ(wrapper_->touchInfos_[0].touch_type, toolType);
}

/* *
 * @tc.name  : CrownTransformProcessorTest_SaveTouchInfo_002
 * @tc.desc: Test the function SaveTouchInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(FingersenseWrapperTest, CrownTransformProcessorTest_SaveTouchInfo_002, TestSize.Level1)
{
    float pointX = 10.0f;
    float pointY = 20.0f;
    int32_t toolType = 1;
    size_t vectorSize = 10;
    size_t maxVectorSize = 10;

    for (size_t i = 0; i < vectorSize; i++) {
        TouchInfo touchInfo;
        touchInfo.x = pointX;
        touchInfo.y = pointY;
        touchInfo.touch_type = toolType;
        wrapper_->touchInfos_.push_back(touchInfo);
    }

    wrapper_->SaveTouchInfo(pointX, pointY, toolType);
    EXPECT_EQ(wrapper_->touchInfos_.size(), maxVectorSize);
}

/* *
 * @tc.name  : CrownTransformProcessorTest_SaveTouchInfo_003
 * @tc.desc: Test the function SaveTouchInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(FingersenseWrapperTest, CrownTransformProcessorTest_SaveTouchInfo_003, TestSize.Level1)
{
    float pointX = 10.0f;
    float pointY = 20.0f;
    int32_t toolType = 1;
    size_t vectorSize = 20;
    size_t maxVectorSize = 10;

    for (size_t i = 0; i < vectorSize; i++) {
        TouchInfo touchInfo;
        touchInfo.x = pointX;
        touchInfo.y = pointY;
        touchInfo.touch_type = toolType;
        wrapper_->touchInfos_.push_back(touchInfo);
    }

    wrapper_->SaveTouchInfo(pointX, pointY, toolType);
    EXPECT_EQ(wrapper_->touchInfos_.size(), maxVectorSize);
}

/* *
 * @tc.name  : CrownTransformProcessorTest_IsEqual_001
 * @tc.desc: Test the function IsEqual
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(FingersenseWrapperTest, CrownTransformProcessorTest_IsEqual_001, TestSize.Level1)
{
    float a = 10.0f;
    float b = 10.0f;
    float epsilon = 0.001f;

    bool result = wrapper_->IsEqual(a, b, epsilon);
    EXPECT_TRUE(result);
}

/* *
 * @tc.name  : CrownTransformProcessorTest_IsEqual_002
 * @tc.desc: Test the function IsEqual
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(FingersenseWrapperTest, CrownTransformProcessorTest_IsEqual_002, TestSize.Level1)
{
    float a = 10.0f;
    float b = 10.1f;
    float epsilon = 0.05f;

    bool result = wrapper_->IsEqual(a, b, epsilon);
    EXPECT_FALSE(result);
}

/* *
 * @tc.name  : CrownTransformProcessorTest_CheckKnuckleEvent_001
 * @tc.desc: Test the function CheckKnuckleEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(FingersenseWrapperTest, CrownTransformProcessorTest_CheckKnuckleEvent_001, TestSize.Level1)
{
    float pointX = 10.0f;
    float pointY = 20.0f;
    bool isKnuckleType = false;

    int32_t result = wrapper_->CheckKnuckleEvent(pointX, pointY, isKnuckleType);
    EXPECT_EQ(result, RET_ERR);
    EXPECT_FALSE(isKnuckleType);
}

/* *
 * @tc.name  : CrownTransformProcessorTest_CheckKnuckleEvent_002
 * @tc.desc: Test the function CheckKnuckleEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(FingersenseWrapperTest, CrownTransformProcessorTest_CheckKnuckleEvent_002, TestSize.Level1)
{
    float pointX = 10.0f;
    float pointY = 20.0f;
    int32_t toolType = MMI::PointerEvent::TOOL_TYPE_KNUCKLE;
    TouchInfo touchInfo;
    touchInfo.x = pointX;
    touchInfo.y = pointY;
    touchInfo.touch_type = toolType;
    wrapper_->touchInfos_.push_back(touchInfo);
    bool isKnuckleType = false;

    int32_t result = wrapper_->CheckKnuckleEvent(pointX, pointY, isKnuckleType);
    EXPECT_EQ(result, RET_OK);
    EXPECT_TRUE(isKnuckleType);
}

/* *
 * @tc.name  : CrownTransformProcessorTest_CheckKnuckleEvent_003
 * @tc.desc: Test the function CheckKnuckleEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(FingersenseWrapperTest, CrownTransformProcessorTest_CheckKnuckleEvent_003, TestSize.Level1)
{
    float pointX = 10.0f;
    float pointY = 20.0f;
    int32_t toolType = MMI::PointerEvent::TOOL_TYPE_KNUCKLE;
    TouchInfo touchInfo;
    touchInfo.x = pointX;
    touchInfo.y = pointY + EPSILON;
    touchInfo.touch_type = toolType;
    wrapper_->touchInfos_.push_back(touchInfo);
    bool isKnuckleType = false;

    int32_t result = wrapper_->CheckKnuckleEvent(pointX, pointY, isKnuckleType);
    EXPECT_EQ(result, RET_ERR);
    EXPECT_FALSE(isKnuckleType);
}

/* *
 * @tc.name  : CrownTransformProcessorTest_CheckKnuckleEvent_004
 * @tc.desc: Test the function CheckKnuckleEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(FingersenseWrapperTest, CrownTransformProcessorTest_CheckKnuckleEvent_004, TestSize.Level1)
{
    float pointX = 10.0f;
    float pointY = 20.0f;
    int32_t toolType = MMI::PointerEvent::TOOL_TYPE_KNUCKLE;
    TouchInfo touchInfo;
    touchInfo.x = pointX;
    touchInfo.y = pointY + EPSILON * 2;
    touchInfo.touch_type = toolType;
    wrapper_->touchInfos_.push_back(touchInfo);
    bool isKnuckleType = false;

    int32_t result = wrapper_->CheckKnuckleEvent(pointX, pointY, isKnuckleType);
    EXPECT_EQ(result, RET_ERR);
    EXPECT_FALSE(isKnuckleType);
}

/* *
 * @tc.name  : CrownTransformProcessorTest_CheckKnuckleEvent_005
 * @tc.desc: Test the function CheckKnuckleEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(FingersenseWrapperTest, CrownTransformProcessorTest_CheckKnuckleEvent_005, TestSize.Level1)
{
    float pointX = 10.0f;
    float pointY = 20.0f;
    int32_t toolType = MMI::PointerEvent::TOOL_TYPE_KNUCKLE;
    TouchInfo touchInfo;
    touchInfo.x = pointX + EPSILON;
    touchInfo.y = pointY;
    touchInfo.touch_type = toolType;
    wrapper_->touchInfos_.push_back(touchInfo);
    bool isKnuckleType = false;

    int32_t result = wrapper_->CheckKnuckleEvent(pointX, pointY, isKnuckleType);
    EXPECT_EQ(result, RET_ERR);
    EXPECT_FALSE(isKnuckleType);
}

/* *
 * @tc.name  : CrownTransformProcessorTest_CheckKnuckleEvent_006
 * @tc.desc: Test the function CheckKnuckleEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(FingersenseWrapperTest, CrownTransformProcessorTest_CheckKnuckleEvent_006, TestSize.Level1)
{
    float pointX = 10.0f;
    float pointY = 20.0f;
    int32_t toolType = MMI::PointerEvent::TOOL_TYPE_KNUCKLE;
    TouchInfo touchInfo;
    touchInfo.x = pointX + EPSILON * 2;
    touchInfo.y = pointY;
    touchInfo.touch_type = toolType;
    wrapper_->touchInfos_.push_back(touchInfo);
    bool isKnuckleType = false;

    int32_t result = wrapper_->CheckKnuckleEvent(pointX, pointY, isKnuckleType);
    EXPECT_EQ(result, RET_ERR);
    EXPECT_FALSE(isKnuckleType);
}
#endif // OHOS_BUILD_ENABLE_FINGERSENSE
} // namespace MMI
} // namespace OHOS
