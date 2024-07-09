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

#include "input_manager_impl.h"
#include "multimodal_event_handler.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputManagerImplTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputManagerImplTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: InputManagerImplTest_IsValiadWindowAreas
 * @tc.desc: Test IsValiadWindowAreas
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_IsValiadWindowAreas, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowInfo windowInfo;
    windowInfo.action = WINDOW_UPDATE_ACTION::UNKNOWN;
    Rect rect;
    rect.x = 100;
    windowInfo.defaultHotAreas.push_back(rect);
    windowInfo.pointerHotAreas.push_back(rect);
    windowInfo.pointerChangeAreas.push_back(100);
    windowInfo.transform.push_back(100.5);
    std::vector<WindowInfo> windows;
    windows.push_back(windowInfo);
    EXPECT_FALSE(InputMgrImpl.IsValiadWindowAreas(windows));

    windows[0].pointerChangeAreas.clear();
    EXPECT_FALSE(InputMgrImpl.IsValiadWindowAreas(windows));
}

/**
 * @tc.name: InputManagerImplTest_PrintWindowInfo
 * @tc.desc: Test PrintWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_PrintWindowInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowInfo windowInfo;
    windowInfo.action = WINDOW_UPDATE_ACTION::UNKNOWN;
    Rect rect {
        .x = 100,
        .y = 100,
        .width = 300,
        .height = 300,
    };
    windowInfo.id = 10;
    windowInfo.pid = 1000;
    windowInfo.uid = 100;
    windowInfo.area.x = 100;
    windowInfo.area.y = 100;
    windowInfo.area.height = 200;
    windowInfo.area.width = 200;
    windowInfo.agentWindowId = 50;
    windowInfo.flags = 0;
    windowInfo.displayId = 30;
    windowInfo.zOrder = 60;
    windowInfo.defaultHotAreas.push_back(rect);
    windowInfo.pointerHotAreas.push_back(rect);
    windowInfo.pointerChangeAreas.push_back(100);
    windowInfo.transform.push_back(100.5);
    std::vector<WindowInfo> windows;
    windows.push_back(windowInfo);
    EXPECT_NO_FATAL_FAILURE(InputMgrImpl.PrintWindowInfo(windows));
}

/**
 * @tc.name: InputManagerImplTest_RecoverPointerEvent
 * @tc.desc: Test RecoverPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_RecoverPointerEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputMgrImpl.lastPointerEvent_ = PointerEvent::Create();
    ASSERT_NE(InputMgrImpl.lastPointerEvent_, nullptr);
    std::initializer_list<int32_t> pointerActionPullEvents { PointerEvent::POINTER_ACTION_MOVE,
        PointerEvent::POINTER_ACTION_UP };
    InputMgrImpl.lastPointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    EXPECT_FALSE(InputMgrImpl.RecoverPointerEvent(pointerActionPullEvents, PointerEvent::POINTER_ACTION_UP));

    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    InputMgrImpl.lastPointerEvent_->SetPointerId(1);
    InputMgrImpl.lastPointerEvent_->AddPointerItem(item);
    EXPECT_TRUE(InputMgrImpl.RecoverPointerEvent(pointerActionPullEvents, PointerEvent::POINTER_ACTION_UP));

    InputMgrImpl.lastPointerEvent_->SetPointerId(2);
    EXPECT_FALSE(InputMgrImpl.RecoverPointerEvent(pointerActionPullEvents, PointerEvent::POINTER_ACTION_UP));
}

/**
 * @tc.name: InputManagerImplTest_OnDisconnected_01
 * @tc.desc: Test OnDisconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_OnDisconnected_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_UP;

    EXPECT_NO_FATAL_FAILURE(InputMgrImpl.OnDisconnected());
}

/**
 * @tc.name: InputManagerImplTest_OnDisconnected_02
 * @tc.desc: Test OnDisconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_OnDisconnected_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_UP;

    EXPECT_NO_FATAL_FAILURE(InputMgrImpl.OnDisconnected());
}

/**
 * @tc.name: InputManagerImplTest_OnKeyEvent_01
 * @tc.desc: Test OnKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_OnKeyEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    EXPECT_NO_FATAL_FAILURE(InputMgrImpl.OnKeyEvent(keyEvent));
}

/**
 * @tc.name: InputManagerImplTest_IsValiadWindowAreas_01
 * @tc.desc: Test IsValiadWindowAreas
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_IsValiadWindowAreas_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<WindowInfo> windows;
    WindowInfo window;
    window.action = WINDOW_UPDATE_ACTION::DEL;

    bool ret = InputMgrImpl.IsValiadWindowAreas(windows);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: InputManagerImplTest_IsValiadWindowAreas_02
 * @tc.desc: Test IsValiadWindowAreas
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_IsValiadWindowAreas_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<WindowInfo> windows;
    WindowInfo window;
    window.action = WINDOW_UPDATE_ACTION::CHANGE;

    bool ret = InputMgrImpl.IsValiadWindowAreas(windows);
    EXPECT_TRUE(ret);
}
} // namespace MMI
} // namespace OHOS
