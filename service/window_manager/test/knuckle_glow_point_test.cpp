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

#include "input_windows_manager.h"
#include "mmi_log.h"
#include "knuckle_glow_point.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleGlowPointTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t IMAGE_WIDTH = 1;
constexpr int32_t IMAGE_HEIGHT = 1;
} // namespace

class KnuckleGlowPointTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void) {};
    void TearDown(void) {};
};

/**
 * @tc.name: KnuckleGlowPoint_KnuckleGlowPoint_001
 * @tc.desc: Test Update
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KnuckleGlowPointTest, KnuckleGlowPoint_KnuckleGlowPoint_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    OHOS::Rosen::Drawing::Bitmap bitmap;
    OHOS::Rosen::Drawing::BitmapFormat format { OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE };
    bitmap.Build(IMAGE_WIDTH, IMAGE_HEIGHT, format);
    KnuckleGlowPoint knuckleGlowPoint(bitmap);
}

/**
 * @tc.name: KnuckleGlowPoint_Update_001
 * @tc.desc: Test Update
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KnuckleGlowPointTest, KnuckleGlowPointTest_Update_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    OHOS::Rosen::Drawing::Bitmap bitmap;
    OHOS::Rosen::Drawing::BitmapFormat format { OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE };
    bitmap.Build(IMAGE_WIDTH, IMAGE_HEIGHT, format);
    auto knuckleGlowPoint = KnuckleGlowPoint(bitmap);
    knuckleGlowPoint.Update();
}

/**
 * @tc.name: KnuckleGlowPointTest_Draw_001
 * @tc.desc: Test Draw
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KnuckleGlowPointTest, KnuckleGlowPointTest_Draw_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    OHOS::Rosen::Drawing::Bitmap bitmap;
    OHOS::Rosen::Drawing::BitmapFormat format { OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE };
    bitmap.Build(IMAGE_WIDTH, IMAGE_HEIGHT, format);
    auto knuckleGlowPoint = KnuckleGlowPoint(bitmap);
    std::shared_ptr<Rosen::RSCanvasDrawingNode> canvasNode = Rosen::RSCanvasDrawingNode::Create();
    auto canvas = static_cast<Rosen::Drawing::RecordingCanvas *>(canvasNode->BeginRecording(0, 0));
    knuckleGlowPoint.Draw(canvas);
}

/**
 * @tc.name: KnuckleGlowPointTest_Reset_001
 * @tc.desc: Test Reset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KnuckleGlowPointTest, KnuckleGlowPointTest_Reset_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    OHOS::Rosen::Drawing::Bitmap bitmap;
    OHOS::Rosen::Drawing::BitmapFormat format { OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE };
    bitmap.Build(IMAGE_WIDTH, IMAGE_HEIGHT, format);
    auto knuckleGlowPoint = KnuckleGlowPoint(bitmap);
    double pointX = 0.1;
    double pointY = 0.1;
    float lifespanoffset = 0.1f;
    knuckleGlowPoint.Reset(pointX, pointY, lifespanoffset);
}

/**
 * @tc.name: KnuckleGlowPointTest_IsEnded_001
 * @tc.desc: Test Reset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KnuckleGlowPointTest, KnuckleGlowPointTest_IsEnded_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    OHOS::Rosen::Drawing::Bitmap bitmap;
    OHOS::Rosen::Drawing::BitmapFormat format { OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE };
    bitmap.Build(IMAGE_WIDTH, IMAGE_HEIGHT, format);
    auto knuckleGlowPoint = KnuckleGlowPoint(bitmap);
    double pointX = 0.1;
    double pointY = 0.1;
    float lifespanoffset = -0.1f;
    knuckleGlowPoint.Reset(pointX, pointY, lifespanoffset);
    ASSERT_FALSE(knuckleGlowPoint.IsEnded());
}
} // namespace MMI
} // namespace OHOS