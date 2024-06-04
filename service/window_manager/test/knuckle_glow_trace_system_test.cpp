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

#include "ui/rs_canvas_drawing_node.h"

#include "i_input_windows_manager.h"
#include "mmi_log.h"
#include "knuckle_glow_trace_system.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleGlowTraceSystemTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t IMAGE_WIDTH = 1;
constexpr int32_t IMAGE_HEIGHT = 1;
} // namespace

class KnuckleGlowTraceSystemTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void) {};
    void TearDown(void) {};
};

/**
 * @tc.name: KnuckleGlowTraceSystem_Init_001
 * @tc.desc: Test Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KnuckleGlowTraceSystemTest, KnuckleGlowTraceSystemTest_Init_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t pointSize = 0;
    int32_t maxDivergenceNum = 0;
    std::shared_ptr<Rosen::Drawing::Bitmap> bitmap = std::make_shared<Rosen::Drawing::Bitmap>();
    OHOS::Rosen::Drawing::BitmapFormat format { OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE };
    bitmap->Build(IMAGE_WIDTH, IMAGE_HEIGHT, format);
    EXPECT_NO_FATAL_FAILURE(KnuckleGlowTraceSystem(pointSize, bitmap, maxDivergenceNum));
}

/**
 * @tc.name: KnuckleGlowTraceSystem_Update_001
 * @tc.desc: Test Update
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KnuckleGlowTraceSystemTest, KnuckleGlowTraceSystemTest_Update_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t pointSize = 0;
    int32_t maxDivergenceNum = 0;
    std::shared_ptr<Rosen::Drawing::Bitmap> bitmap = std::make_shared<Rosen::Drawing::Bitmap>();
    OHOS::Rosen::Drawing::BitmapFormat format { OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE };
    bitmap->Build(IMAGE_WIDTH, IMAGE_HEIGHT, format);
    auto knuckleGlowTraceSystem = KnuckleGlowTraceSystem(pointSize, bitmap, maxDivergenceNum);
    EXPECT_NO_FATAL_FAILURE(knuckleGlowTraceSystem.Update());
}

/**
 * @tc.name: KnuckleGlowTraceSystemTest_Draw_001
 * @tc.desc: Test Draw
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KnuckleGlowTraceSystemTest, KnuckleGlowTraceSystemTest_Draw_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t pointSize = 0;
    int32_t maxDivergenceNum = 0;
    std::shared_ptr<Rosen::Drawing::Bitmap> bitmap = std::make_shared<Rosen::Drawing::Bitmap>();
    OHOS::Rosen::Drawing::BitmapFormat format { OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE };
    bitmap->Build(IMAGE_WIDTH, IMAGE_HEIGHT, format);
    auto knuckleGlowTraceSystem = KnuckleGlowTraceSystem(pointSize, bitmap, maxDivergenceNum);
    std::shared_ptr<Rosen::RSCanvasDrawingNode> canvasNode = Rosen::RSCanvasDrawingNode::Create();
    auto canvas = static_cast<Rosen::Drawing::RecordingCanvas *>(canvasNode->
        BeginRecording(0, 0));
    EXPECT_NO_FATAL_FAILURE(knuckleGlowTraceSystem.Draw(canvas));
}

/**
 * @tc.name: KnuckleGlowTraceSystemTest_ResetDivergentPoints_001
 * @tc.desc: Test ResetDivergentPoints
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KnuckleGlowTraceSystemTest, KnuckleGlowTraceSystemTest_ResetDivergentPoints_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t pointSize = 0;
    int32_t maxDivergenceNum = 0;
    std::shared_ptr<Rosen::Drawing::Bitmap> bitmap = std::make_shared<Rosen::Drawing::Bitmap>();
    OHOS::Rosen::Drawing::BitmapFormat format { OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE };
    bitmap->Build(IMAGE_WIDTH, IMAGE_HEIGHT, format);
    auto knuckleGlowTraceSystem = KnuckleGlowTraceSystem(pointSize, bitmap, maxDivergenceNum);
    double pointX = 0.1;
    double pointY = 0.1;
    EXPECT_NO_FATAL_FAILURE(knuckleGlowTraceSystem.ResetDivergentPoints(pointX, pointY));
}

/**
 * @tc.name: KnuckleGlowTraceSystem_AddGlowPoints_001
 * @tc.desc: Test AddGlowPoints
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KnuckleGlowTraceSystemTest, KnuckleGlowTraceSystemTest_AddGlowPoints_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    int32_t pointSize = 0;
    int32_t maxDivergenceNum = 0;
    std::shared_ptr<Rosen::Drawing::Bitmap> bitmap = std::make_shared<Rosen::Drawing::Bitmap>();
    OHOS::Rosen::Drawing::BitmapFormat format { OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE };
    bitmap->Build(IMAGE_WIDTH, IMAGE_HEIGHT, format);
    auto knuckleGlowTraceSystem = KnuckleGlowTraceSystem(pointSize, bitmap, maxDivergenceNum);
    Rosen::Drawing::Path path;
    int64_t timeInterval = 100;
    EXPECT_NO_FATAL_FAILURE(knuckleGlowTraceSystem.AddGlowPoints(path, timeInterval));
}
} // namespace MMI
} // namespace OHOS