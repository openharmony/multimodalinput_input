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
#include <fstream>
#include <gtest/gtest.h>

#include "mmi_log.h"
#include "pointer_event.h"
#ifndef USE_ROSEN_DRAWING
#define USE_ROSEN_DRAWING
#endif
#include "touch_drawing_manager.h"
#include "window_info.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchDrawingManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
class TouchDrawingManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void) {};
};

/**
 * @tc.name: TouchDrawingManagerTest_RecordLabelsInfo
 * @tc.desc: Test RecordLabelsInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_RecordLabelsInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawMgr;
    touchDrawMgr.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawMgr.pointerEvent_, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetPressed(true);
    item.SetDisplayX(100);
    item.SetDisplayY(100);
    touchDrawMgr.pointerEvent_->AddPointerItem(item);
    touchDrawMgr.pointerEvent_->SetPointerId(0);
    touchDrawMgr.currentPointerId_ = 1;
    EXPECT_NO_FATAL_FAILURE(touchDrawMgr.RecordLabelsInfo());

    touchDrawMgr.currentPointerId_ = 0;
    touchDrawMgr.isFirstDownAction_ = true;
    touchDrawMgr.lastPointerItem_.push_back(item);
    touchDrawMgr.pointerEvent_->SetActionTime(150);
    touchDrawMgr.lastActionTime_ = 300;
    EXPECT_NO_FATAL_FAILURE(touchDrawMgr.RecordLabelsInfo());

    touchDrawMgr.pointerEvent_->SetActionTime(50);
    touchDrawMgr.lastActionTime_ = 50;
    EXPECT_NO_FATAL_FAILURE(touchDrawMgr.RecordLabelsInfo());

    item.SetPressed(false);
    touchDrawMgr.isFirstDownAction_ = false;
    touchDrawMgr.pointerEvent_->SetPointerId(10);
    touchDrawMgr.pointerEvent_->UpdatePointerItem(0, item);
    EXPECT_NO_FATAL_FAILURE(touchDrawMgr.RecordLabelsInfo());
}
} // namespace MMI
} // namespace OHOS