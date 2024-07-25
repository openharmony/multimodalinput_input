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

#include "input_windows_manager.h"
#include "mmi_matrix3.h"
#include "mock.h"
#include "window_info.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;
const std::string PROGRAM_NAME = "uds_session_test";
constexpr int32_t MODULE_TYPE = 1;
constexpr int32_t UDS_FD = 1;
constexpr int32_t UDS_UID = 100;
constexpr int32_t UDS_PID = 100;
} // namespace

class InputWindowsManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase();
    void SetUp() {}
    void TearDown() {}

    static inline std::shared_ptr<MessageParcelMock> messageParcelMock_ = nullptr;
};

void InputWindowsManagerTest::SetUpTestCase(void)
{
    messageParcelMock_ = std::make_shared<MessageParcelMock>();
    MessageParcelMock::messageParcel = messageParcelMock_;
}
void InputWindowsManagerTest::TearDownTestCase()
{
    IInputWindowsManager::instance_.reset();
    IInputWindowsManager::instance_ = nullptr;
    MessageParcelMock::messageParcel = nullptr;
    messageParcelMock_ = nullptr;
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
/**
 * @tc.name: UpdateTarget_001
 * @tc.desc: Test the function UpdateTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, UpdateTarget_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateTarget(keyEvent));
}

/**
 * @tc.name: UpdateTarget_002
 * @tc.desc: Test the function UpdateTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, UpdateTarget_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, GetClientFd(_)).WillOnce(Return(-1));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->displayGroupInfo_.focusWindowId = 1;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.pid = 11;
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateTarget(keyEvent));
    inputWindowsManager->displayGroupInfo_.focusWindowId = -1;
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
    inputWindowsManager->udsServer_ = nullptr;
}

/**
 * @tc.name: UpdateTarget_003
 * @tc.desc: Test the function UpdateTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, UpdateTarget_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, GetClientFd(_)).WillOnce(Return(1));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->displayGroupInfo_.focusWindowId = 1;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.pid = 11;
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateTarget(keyEvent));
    inputWindowsManager->displayGroupInfo_.focusWindowId = -1;
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
    inputWindowsManager->udsServer_ = nullptr;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
/**
 * @tc.name: PointerDrawingManagerOnDisplayInfo_001
 * @tc.desc: Test the function PointerDrawingManagerOnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, PointerDrawingManagerOnDisplayInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, HasPointerDevice()).WillOnce(Return(false));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    DisplayGroupInfo displayGroupInfo;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->PointerDrawingManagerOnDisplayInfo(displayGroupInfo));
}

/**
 * @tc.name: PointerDrawingManagerOnDisplayInfo_002
 * @tc.desc: Test the function PointerDrawingManagerOnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, PointerDrawingManagerOnDisplayInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, HasPointerDevice()).WillOnce(Return(true));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    inputWindowsManager->lastPointerEvent_ = PointerEvent::Create();
    ASSERT_NE(inputWindowsManager->lastPointerEvent_, nullptr);
    inputWindowsManager->lastPointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    DisplayGroupInfo displayGroupInfo;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->PointerDrawingManagerOnDisplayInfo(displayGroupInfo));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->lastPointerEvent_.reset();
    inputWindowsManager->lastPointerEvent_ = nullptr;
}

/**
 * @tc.name: PointerDrawingManagerOnDisplayInfo_003
 * @tc.desc: Test the function PointerDrawingManagerOnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, PointerDrawingManagerOnDisplayInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, HasPointerDevice()).WillOnce(Return(true));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    inputWindowsManager->lastPointerEvent_ = PointerEvent::Create();
    ASSERT_NE(inputWindowsManager->lastPointerEvent_, nullptr);
    inputWindowsManager->lastPointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    inputWindowsManager->lastPointerEvent_->SetButtonPressed(1);
    DisplayGroupInfo displayGroupInfo;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->PointerDrawingManagerOnDisplayInfo(displayGroupInfo));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->lastPointerEvent_.reset();
    inputWindowsManager->lastPointerEvent_ = nullptr;
}

/**
 * @tc.name: PointerDrawingManagerOnDisplayInfo_004
 * @tc.desc: Test the function PointerDrawingManagerOnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, PointerDrawingManagerOnDisplayInfo_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, HasPointerDevice()).WillOnce(Return(true));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    inputWindowsManager->lastPointerEvent_ = PointerEvent::Create();
    ASSERT_NE(inputWindowsManager->lastPointerEvent_, nullptr);
    inputWindowsManager->lastPointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    DisplayGroupInfo displayGroupInfo;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->PointerDrawingManagerOnDisplayInfo(displayGroupInfo));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->lastPointerEvent_.reset();
    inputWindowsManager->lastPointerEvent_ = nullptr;
}

/**
 * @tc.name: PointerDrawingManagerOnDisplayInfo_005
 * @tc.desc: Test the function PointerDrawingManagerOnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, PointerDrawingManagerOnDisplayInfo_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, HasPointerDevice()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillRepeatedly(Return(false));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.x = 8;
    displayInfo.y = 8;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.pid = 11;
    windowInfo.transform.push_back(1.1);
    Rect rect;
    rect.x = 5;
    rect.y = 5;
    rect.width = 10;
    rect.height = 10;
    windowInfo.pointerHotAreas.push_back(rect);
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    inputWindowsManager->lastPointerEvent_ = PointerEvent::Create();
    ASSERT_NE(inputWindowsManager->lastPointerEvent_, nullptr);
    inputWindowsManager->lastPointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    DisplayGroupInfo displayGroupInfo;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->PointerDrawingManagerOnDisplayInfo(displayGroupInfo));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
    inputWindowsManager->lastPointerEvent_.reset();
    inputWindowsManager->lastPointerEvent_ = nullptr;
}

/**
 * @tc.name: PointerDrawingManagerOnDisplayInfo_006
 * @tc.desc: Test the function PointerDrawingManagerOnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, PointerDrawingManagerOnDisplayInfo_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, HasPointerDevice()).WillOnce(Return(true));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.x = 8;
    displayInfo.y = 8;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.pid = 11;
    windowInfo.transform.push_back(1.1);
    Rect rect;
    rect.x = 5;
    rect.y = 5;
    rect.width = 10;
    rect.height = 10;
    windowInfo.pointerHotAreas.push_back(rect);
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    inputWindowsManager->lastPointerEvent_ = PointerEvent::Create();
    ASSERT_NE(inputWindowsManager->lastPointerEvent_, nullptr);
    inputWindowsManager->lastPointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    inputWindowsManager->isDragBorder_ = true;
    inputWindowsManager->dragFlag_ = true;
    DisplayGroupInfo displayGroupInfo;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->PointerDrawingManagerOnDisplayInfo(displayGroupInfo));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
    inputWindowsManager->lastPointerEvent_.reset();
    inputWindowsManager->lastPointerEvent_ = nullptr;
    inputWindowsManager->isDragBorder_ = false;
    inputWindowsManager->dragFlag_ = false;
}

/**
 * @tc.name: PointerDrawingManagerOnDisplayInfo_007
 * @tc.desc: Test the function PointerDrawingManagerOnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, PointerDrawingManagerOnDisplayInfo_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, HasPointerDevice()).WillOnce(Return(true));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.x = 8;
    displayInfo.y = 8;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.pid = 11;
    windowInfo.transform.push_back(1.1);
    Rect rect;
    rect.x = 5;
    rect.y = 5;
    rect.width = 10;
    rect.height = 10;
    windowInfo.pointerHotAreas.push_back(rect);
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    inputWindowsManager->lastPointerEvent_ = PointerEvent::Create();
    ASSERT_NE(inputWindowsManager->lastPointerEvent_, nullptr);
    inputWindowsManager->lastPointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    inputWindowsManager->isDragBorder_ = true;
    inputWindowsManager->dragFlag_ = true;
    DisplayGroupInfo displayGroupInfo;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->PointerDrawingManagerOnDisplayInfo(displayGroupInfo));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
    inputWindowsManager->lastPointerEvent_.reset();
    inputWindowsManager->lastPointerEvent_ = nullptr;
    inputWindowsManager->isDragBorder_ = false;
    inputWindowsManager->dragFlag_ = false;
}
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING

/**
 * @tc.name: SendPointerEvent_001
 * @tc.desc: Test the function SendPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, SendPointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, SendMsg(_)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, GetClientFd(_)).WillOnce(Return(1));
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    EXPECT_CALL(*messageParcelMock_, GetSession(_)).WillOnce(Return(session));
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillOnce(Return(false));

    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    int32_t pointerAction = PointerEvent::POINTER_ACTION_UNKNOWN;
    DisplayInfo displayInfo;
    displayInfo.id = 10;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    inputWindowsManager->extraData_.appended = true;
    inputWindowsManager->extraData_.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->SendPointerEvent(pointerAction));
    inputWindowsManager->udsServer_ = nullptr;
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->extraData_.appended = false;
    inputWindowsManager->extraData_.sourceType = -1;
}

/**
 * @tc.name: SendPointerEvent_002
 * @tc.desc: Test the function SendPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, SendPointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, SendMsg(_)).WillOnce(Return(false));
    EXPECT_CALL(*messageParcelMock_, GetClientFd(_)).WillOnce(Return(1));
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    EXPECT_CALL(*messageParcelMock_, GetSession(_)).WillOnce(Return(session));
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillOnce(Return(false));

    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    int32_t pointerAction = PointerEvent::POINTER_ACTION_UNKNOWN;
    DisplayInfo displayInfo;
    displayInfo.id = 10;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    inputWindowsManager->extraData_.appended = false;
    inputWindowsManager->extraData_.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->SendPointerEvent(pointerAction));
    inputWindowsManager->udsServer_ = nullptr;
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->extraData_.sourceType = -1;
}

/**
 * @tc.name: SkipNavigationWindow_001
 * @tc.desc: Test the function SkipNavigationWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, SkipNavigationWindow_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInputType windowType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    int32_t toolType = PointerEvent::TOOL_TYPE_FINGER;
    EXPECT_FALSE(inputWindowsManager->SkipNavigationWindow(windowType, toolType));

    toolType = PointerEvent::TOOL_TYPE_PEN;
    inputWindowsManager->isOpenAntiMisTakeObserver_ = false;
    inputWindowsManager->antiMistake_.isOpen = true;
    EXPECT_TRUE(inputWindowsManager->SkipNavigationWindow(windowType, toolType));

    inputWindowsManager->isOpenAntiMisTakeObserver_ = true;
    inputWindowsManager->antiMistake_.isOpen = false;
    EXPECT_FALSE(inputWindowsManager->SkipNavigationWindow(windowType, toolType));
    inputWindowsManager->isOpenAntiMisTakeObserver_ = false;
}

/**
 * @tc.name: TransformTipPoint_001
 * @tc.desc: Test the function TransformTipPoint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, TransformTipPoint_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillOnce(Return(false));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.uniq = "default0";
    displayInfo.direction = DIRECTION90;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    libinput_event_tablet_tool event {};
    PhysicalCoordinate coord;
    int32_t displayId;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->TransformTipPoint(&event, coord, displayId));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
}

/**
 * @tc.name: TransformTipPoint_002
 * @tc.desc: Test the function TransformTipPoint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, TransformTipPoint_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillOnce(Return(false));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.uniq = "default0";
    displayInfo.direction = DIRECTION270;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    libinput_event_tablet_tool event {};
    PhysicalCoordinate coord;
    int32_t displayId;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->TransformTipPoint(&event, coord, displayId));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
}

/**
 * @tc.name: TransformTipPoint_003
 * @tc.desc: Test the function TransformTipPoint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, TransformTipPoint_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.uniq = "default0";
    displayInfo.direction = DIRECTION0;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    libinput_event_tablet_tool event {};
    PhysicalCoordinate coord;
    int32_t displayId;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->TransformTipPoint(&event, coord, displayId));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
}

/**
 * @tc.name: InputWindowsManagerTest_TransformTipPoint_004
 * @tc.desc: Test the function TransformTipPoint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_TransformTipPoint_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    auto displayInfo = inputWindowsManager->FindPhysicalDisplayInfo("default0");

    libinput_event_tablet_tool event {};
    Direction direction;
    direction = DIRECTION90;
    PhysicalCoordinate coord;
    coord.x = 5.5;
    coord.y = 3.2;
    int32_t displayId = 2;
    bool ret = inputWindowsManager->TransformTipPoint(&event, coord, displayId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: InputWindowsManagerTest_TransformTipPoint_005
 * @tc.desc: Test the function TransformTipPoint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_TransformTipPoint_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    auto displayInfo = inputWindowsManager->FindPhysicalDisplayInfo("default0");

    libinput_event_tablet_tool event {};
    Direction direction;
    direction = DIRECTION270;
    PhysicalCoordinate coord;
    coord.x = 6.5;
    coord.y = 8.2;
    int32_t displayId = 3;
    bool ret = inputWindowsManager->TransformTipPoint(&event, coord, displayId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: InputWindowsManagerTest_TransformTipPoint_006
 * @tc.desc: Test the function TransformTipPoint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_TransformTipPoint_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    auto displayInfo = inputWindowsManager->FindPhysicalDisplayInfo("default0");

    libinput_event_tablet_tool event {};
    Direction direction;
    direction = DIRECTION0;
    PhysicalCoordinate coord;
    coord.x = 6.5;
    coord.y = 8.2;
    int32_t displayId = 3;
    bool ret = inputWindowsManager->TransformTipPoint(&event, coord, displayId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: InputWindowsManagerTest_IsNeedRefreshLayer_001
 * @tc.desc: Test the function IsNeedRefreshLayer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsNeedRefreshLayer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    int32_t windowId = 2;
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillOnce(Return(true));

    bool ret = inputWindowsManager->IsNeedRefreshLayer(windowId);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: InputWindowsManagerTest_IsNeedRefreshLayer_002
 * @tc.desc: Test the function IsNeedRefreshLayer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsNeedRefreshLayer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    int32_t windowId = 3;
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillOnce(Return(false));

    int32_t displayId = MouseEventHdr->GetDisplayId();
    EXPECT_FALSE(displayId < 0);

    std::optional<WindowInfo> touchWindow = inputWindowsManager->GetWindowInfo(5, 7);
    bool ret = inputWindowsManager->IsNeedRefreshLayer(windowId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: InputWindowsManagerTest_IsNeedRefreshLayer_003
 * @tc.desc: Test the function IsNeedRefreshLayer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsNeedRefreshLayer_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillOnce(Return(false));
    int32_t displayId = MouseEventHdr->GetDisplayId();
    EXPECT_FALSE(displayId < 0);

    std::optional<WindowInfo> touchWindow = inputWindowsManager->GetWindowInfo(6, 8);
    int32_t windowId = GLOBAL_WINDOW_ID;
    bool ret = inputWindowsManager->IsNeedRefreshLayer(windowId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CalculateTipPoint_001
 * @tc.desc: Test the function CalculateTipPoint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, CalculateTipPoint_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    libinput_event_tablet_tool event {};
    PhysicalCoordinate coord;
    int32_t displayId;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->CalculateTipPoint(&event, displayId, coord));
}

/**
 * @tc.name: CalculateTipPoint_002
 * @tc.desc: Test the function CalculateTipPoint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, CalculateTipPoint_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.uniq = "default0";
    displayInfo.direction = DIRECTION0;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    libinput_event_tablet_tool event {};
    PhysicalCoordinate coord;
    int32_t displayId;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->CalculateTipPoint(&event, displayId, coord));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
}

/**
 * @tc.name: CalculateTipPoint_003
 * @tc.desc: Test the function CalculateTipPoint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, CalculateTipPoint_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);

    libinput_event_tablet_tool event {};
    int32_t targetDisplayId = 3;
    PhysicalCoordinate coord;
    coord.x = 3.5;
    coord.y = 5.2;
    bool result = inputWindowsManager->TransformTipPoint(&event, coord, targetDisplayId);
    EXPECT_FALSE(result);
    bool ret = inputWindowsManager->CalculateTipPoint(&event, targetDisplayId, coord);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: UpdateMouseTarget_001
 * @tc.desc: Test the function UpdateMouseTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, UpdateMouseTarget_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.displayDirection = DIRECTION0;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateMouseTarget(pointerEvent));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
}

/**
 * @tc.name: UpdateMouseTarget_002
 * @tc.desc: Test the function UpdateMouseTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, UpdateMouseTarget_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.displayDirection = DIRECTION0;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateMouseTarget(pointerEvent));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
}

/**
 * @tc.name: UpdateMouseTarget_003
 * @tc.desc: Test the function UpdateMouseTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, UpdateMouseTarget_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    inputWindowsManager->mouseDownInfo_.id = 1;
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.displayDirection = DIRECTION0;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateMouseTarget(pointerEvent));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->mouseDownInfo_.id = -1;
}

/**
 * @tc.name: UpdateMouseTarget_004
 * @tc.desc: Test the function UpdateMouseTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, UpdateMouseTarget_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillRepeatedly(Return(false));
    EXPECT_CALL(*messageParcelMock_, GetMouseDisplayState()).WillRepeatedly(Return(false));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->mouseDownInfo_.id = 1;
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.displayDirection = DIRECTION0;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateMouseTarget(pointerEvent));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->mouseDownInfo_.id = -1;
    inputWindowsManager->udsServer_ = nullptr;
}

/**
 * @tc.name: UpdateMouseTarget_005
 * @tc.desc: Test the function UpdateMouseTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, UpdateMouseTarget_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, GetBoolValue(_, _)).WillOnce(Return(false));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo windowInfo;
    windowInfo.id = -1;
    windowInfo.pid = 11;
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->mouseDownInfo_.id = 1;
    inputWindowsManager->displayGroupInfo_.focusWindowId = 1;
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.displayDirection = DIRECTION0;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateMouseTarget(pointerEvent));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->displayGroupInfo_.focusWindowId = -1;
    inputWindowsManager->mouseDownInfo_.id = -1;
    inputWindowsManager->udsServer_ = nullptr;
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
}

/**
 * @tc.name: UpdateMouseTarget_006
 * @tc.desc: Test the function UpdateMouseTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, UpdateMouseTarget_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, GetBoolValue(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillRepeatedly(Return(false));
    EXPECT_CALL(*messageParcelMock_, GetMouseDisplayState()).WillRepeatedly(Return(false));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo windowInfo;
    windowInfo.id = -1;
    windowInfo.pid = 11;
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->mouseDownInfo_.id = 1;
    inputWindowsManager->displayGroupInfo_.focusWindowId = -1;
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.displayDirection = DIRECTION0;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateMouseTarget(pointerEvent));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->mouseDownInfo_.id = -1;
    inputWindowsManager->udsServer_ = nullptr;
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
}

/**
 * @tc.name: UpdateMouseTarget_007
 * @tc.desc: Test the function UpdateMouseTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, UpdateMouseTarget_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, GetBoolValue(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillRepeatedly(Return(true));
    EXPECT_CALL(*messageParcelMock_, GetMouseDisplayState()).WillRepeatedly(Return(false));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo windowInfo;
    windowInfo.id = -1;
    windowInfo.pid = 11;
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->mouseDownInfo_.id = 1;
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.displayDirection = DIRECTION0;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateMouseTarget(pointerEvent));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->mouseDownInfo_.id = -1;
    inputWindowsManager->udsServer_ = nullptr;
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
}

/**
 * @tc.name: UpdateMouseTarget_008
 * @tc.desc: Test the function UpdateMouseTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, UpdateMouseTarget_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, GetBoolValue(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillRepeatedly(Return(true));
    EXPECT_CALL(*messageParcelMock_, GetMouseDisplayState()).WillRepeatedly(Return(true));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo windowInfo;
    windowInfo.id = -1;
    windowInfo.pid = 11;
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->mouseDownInfo_.id = 1;
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.displayDirection = DIRECTION0;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateMouseTarget(pointerEvent));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->mouseDownInfo_.id = -1;
    inputWindowsManager->udsServer_ = nullptr;
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
}

/**
 * @tc.name: UpdateMouseTarget_009
 * @tc.desc: Test the function UpdateMouseTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, UpdateMouseTarget_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, GetBoolValue(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillRepeatedly(Return(false));
    EXPECT_CALL(*messageParcelMock_, GetMouseDisplayState()).WillRepeatedly(Return(true));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo windowInfo;
    windowInfo.id = -1;
    windowInfo.pid = 11;
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->mouseDownInfo_.id = 1;
    inputWindowsManager->isUiExtension_ = true;
    inputWindowsManager->displayGroupInfo_.focusWindowId = -1;
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.displayDirection = DIRECTION0;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateMouseTarget(pointerEvent));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->isUiExtension_ = false;
    inputWindowsManager->mouseDownInfo_.id = -1;
    inputWindowsManager->udsServer_ = nullptr;
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
}

/**
 * @tc.name: UpdateMouseTarget_010
 * @tc.desc: Test the function UpdateMouseTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, UpdateMouseTarget_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillRepeatedly(Return(false));
    EXPECT_CALL(*messageParcelMock_, GetMouseDisplayState()).WillRepeatedly(Return(true));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo windowInfo;
    windowInfo.id = -1;
    windowInfo.pid = 11;
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->mouseDownInfo_.id = 1;
    inputWindowsManager->dragFlag_ = true;
    inputWindowsManager->isDragBorder_ = true;
    inputWindowsManager->isUiExtension_ = true;
    inputWindowsManager->displayGroupInfo_.focusWindowId = -1;
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.displayDirection = DIRECTION0;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateMouseTarget(pointerEvent));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->dragFlag_ = false;
    inputWindowsManager->isDragBorder_ = false;
    inputWindowsManager->isUiExtension_ = false;
    inputWindowsManager->mouseDownInfo_.id = -1;
    inputWindowsManager->udsServer_ = nullptr;
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
}

/**
 * @tc.name: UpdateMouseTarget_011
 * @tc.desc: Test the function UpdateMouseTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, UpdateMouseTarget_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillRepeatedly(Return(false));
    EXPECT_CALL(*messageParcelMock_, GetMouseDisplayState()).WillRepeatedly(Return(true));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo windowInfo;
    windowInfo.id = -1;
    windowInfo.pid = 11;
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->mouseDownInfo_.id = 1;
    inputWindowsManager->dragFlag_ = true;
    inputWindowsManager->isDragBorder_ = true;
    inputWindowsManager->isUiExtension_ = false;
    inputWindowsManager->displayGroupInfo_.focusWindowId = -1;
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.displayDirection = DIRECTION90;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateMouseTarget(pointerEvent));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->dragFlag_ = false;
    inputWindowsManager->isDragBorder_ = false;
    inputWindowsManager->isUiExtension_ = false;
    inputWindowsManager->mouseDownInfo_.id = -1;
    inputWindowsManager->udsServer_ = nullptr;
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
}

/**
 * @tc.name: UpdateMouseTarget_012
 * @tc.desc: Test the function UpdateMouseTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, UpdateMouseTarget_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillRepeatedly(Return(false));
    EXPECT_CALL(*messageParcelMock_, GetMouseDisplayState()).WillRepeatedly(Return(true));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo windowInfo;
    windowInfo.id = -1;
    windowInfo.pid = 11;
    windowInfo.transform.push_back(1.1);
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->mouseDownInfo_.id = 1;
    inputWindowsManager->dragFlag_ = true;
    inputWindowsManager->isDragBorder_ = true;
    inputWindowsManager->isUiExtension_ = false;
    inputWindowsManager->displayGroupInfo_.focusWindowId = -1;
    inputWindowsManager->captureModeInfo_.isCaptureMode = true;
    inputWindowsManager->captureModeInfo_.windowId = 1;
    inputWindowsManager->extraData_.appended = true;
    inputWindowsManager->extraData_.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.displayDirection = DIRECTION90;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateMouseTarget(pointerEvent));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->dragFlag_ = false;
    inputWindowsManager->isDragBorder_ = false;
    inputWindowsManager->isUiExtension_ = false;
    inputWindowsManager->captureModeInfo_.isCaptureMode = false;
    inputWindowsManager->captureModeInfo_.windowId = -1;
    inputWindowsManager->mouseDownInfo_.id = -1;
    inputWindowsManager->udsServer_ = nullptr;
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
    inputWindowsManager->extraData_.appended = false;
    inputWindowsManager->extraData_.sourceType = -1;
}

/**
 * @tc.name: UpdateMouseTarget_013
 * @tc.desc: Test the function UpdateMouseTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, UpdateMouseTarget_013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillRepeatedly(Return(false));
    EXPECT_CALL(*messageParcelMock_, GetMouseDisplayState()).WillRepeatedly(Return(true));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo windowInfo;
    windowInfo.id = -1;
    windowInfo.pid = 11;
    windowInfo.transform.push_back(1.1);
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->mouseDownInfo_.id = 1;
    inputWindowsManager->dragFlag_ = true;
    inputWindowsManager->isDragBorder_ = true;
    inputWindowsManager->isUiExtension_ = false;
    inputWindowsManager->displayGroupInfo_.focusWindowId = -1;
    inputWindowsManager->captureModeInfo_.isCaptureMode = true;
    inputWindowsManager->captureModeInfo_.windowId = -1;
    inputWindowsManager->extraData_.appended = true;
    inputWindowsManager->extraData_.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.displayDirection = DIRECTION90;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_UP);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateMouseTarget(pointerEvent));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->dragFlag_ = false;
    inputWindowsManager->isDragBorder_ = false;
    inputWindowsManager->isUiExtension_ = false;
    inputWindowsManager->captureModeInfo_.isCaptureMode = false;
    inputWindowsManager->mouseDownInfo_.id = -1;
    inputWindowsManager->udsServer_ = nullptr;
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
    inputWindowsManager->extraData_.appended = false;
    inputWindowsManager->extraData_.sourceType = -1;
}

/**
 * @tc.name: UpdateMouseTarget_014
 * @tc.desc: Test the function UpdateMouseTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, UpdateMouseTarget_014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillRepeatedly(Return(false));
    EXPECT_CALL(*messageParcelMock_, GetMouseDisplayState()).WillRepeatedly(Return(true));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo windowInfo;
    windowInfo.id = -1;
    windowInfo.pid = 11;
    windowInfo.transform.push_back(1.1);
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->mouseDownInfo_.id = 1;
    inputWindowsManager->dragFlag_ = true;
    inputWindowsManager->isDragBorder_ = true;
    inputWindowsManager->isUiExtension_ = false;
    inputWindowsManager->displayGroupInfo_.focusWindowId = -1;
    inputWindowsManager->captureModeInfo_.isCaptureMode = true;
    inputWindowsManager->captureModeInfo_.windowId = -1;
    inputWindowsManager->extraData_.appended = false;
    inputWindowsManager->extraData_.sourceType = -1;
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.displayDirection = DIRECTION90;
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_UP);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateMouseTarget(pointerEvent));
    inputWindowsManager->displayGroupInfo_.displaysInfo.clear();
    inputWindowsManager->dragFlag_ = false;
    inputWindowsManager->isDragBorder_ = false;
    inputWindowsManager->isUiExtension_ = false;
    inputWindowsManager->captureModeInfo_.isCaptureMode = false;
    inputWindowsManager->mouseDownInfo_.id = -1;
    inputWindowsManager->udsServer_ = nullptr;
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
}

/**
 * @tc.name: IsNeedDrawPointer_001
 * @tc.desc: Test the function IsNeedDrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, IsNeedDrawPointer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->IsNeedDrawPointer(pointerItem));
}

/**
 * @tc.name: IsNeedDrawPointer_002
 * @tc.desc: Test the function IsNeedDrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, IsNeedDrawPointer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, GetInputDevice(_, _)).WillOnce(Return(nullptr));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetToolType(PointerEvent::TOOL_TYPE_PEN);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->IsNeedDrawPointer(pointerItem));
}

/**
 * @tc.name: IsNeedDrawPointer_003
 * @tc.desc: Test the function IsNeedDrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, IsNeedDrawPointer_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    inputDevice->SetBus(BUS_USB);
    EXPECT_CALL(*messageParcelMock_, GetInputDevice(_, _)).WillOnce(Return(inputDevice));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetToolType(PointerEvent::TOOL_TYPE_PEN);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->IsNeedDrawPointer(pointerItem));
}

/**
 * @tc.name: IsNeedDrawPointer_004
 * @tc.desc: Test the function IsNeedDrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, IsNeedDrawPointer_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    inputDevice->SetBus(BUS_HIL);
    EXPECT_CALL(*messageParcelMock_, GetInputDevice(_, _)).WillOnce(Return(inputDevice));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetToolType(PointerEvent::TOOL_TYPE_PEN);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->IsNeedDrawPointer(pointerItem));
}

/**
 * @tc.name: DispatchTouch_001
 * @tc.desc: Test the function DispatchTouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, DispatchTouch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->lastTouchEvent_ = PointerEvent::Create();
    ASSERT_NE(inputWindowsManager->lastTouchEvent_, nullptr);
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.pid = 11;
    windowInfo.flags = 1;
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    int32_t pointerAction = PointerEvent::POINTER_ACTION_PULL_IN_WINDOW;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->DispatchTouch(pointerAction));
    inputWindowsManager->udsServer_ = nullptr;
    inputWindowsManager->lastTouchEvent_ = nullptr;
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
}

/**
 * @tc.name: DispatchTouch_002
 * @tc.desc: Test the function DispatchTouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, DispatchTouch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->lastTouchEvent_ = PointerEvent::Create();
    ASSERT_NE(inputWindowsManager->lastTouchEvent_, nullptr);
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.pid = 11;
    windowInfo.flags = 0;
    windowInfo.transform.push_back(1.1);
    Rect rect;
    rect.x = 5;
    rect.y = 5;
    rect.width = 10;
    rect.height = 10;
    windowInfo.defaultHotAreas.push_back(rect);
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    inputWindowsManager->lastTouchLogicX_ = 8;
    inputWindowsManager->lastTouchLogicY_ = 8;
    int32_t pointerAction = PointerEvent::POINTER_ACTION_PULL_IN_WINDOW;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->DispatchTouch(pointerAction));
    inputWindowsManager->udsServer_ = nullptr;
    inputWindowsManager->lastTouchEvent_ = nullptr;
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
    inputWindowsManager->lastTouchLogicX_ = -1;
    inputWindowsManager->lastTouchLogicY_ = -1;
    inputWindowsManager->lastTouchWindowInfo_.id = -1;
    inputWindowsManager->lastTouchWindowInfo_.pid = -1;
    inputWindowsManager->lastTouchWindowInfo_.uid = -1;
    inputWindowsManager->lastTouchWindowInfo_.agentWindowId = -1;
    inputWindowsManager->lastTouchWindowInfo_.area = { 0, 0, 0, 0 };
    inputWindowsManager->lastTouchWindowInfo_.flags = -1;
    inputWindowsManager->lastTouchWindowInfo_.windowType = 0;
}

/**
 * @tc.name: DispatchTouch_003
 * @tc.desc: Test the function DispatchTouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, DispatchTouch_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, GetClientFd(_)).WillOnce(Return(1));
    EXPECT_CALL(*messageParcelMock_, GetSession(_)).WillOnce(Return(nullptr));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->lastTouchEvent_ = PointerEvent::Create();
    ASSERT_NE(inputWindowsManager->lastTouchEvent_, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    inputWindowsManager->lastTouchEvent_->AddPointerItem(item);
    inputWindowsManager->lastTouchEvent_->SetPointerId(1);
    WindowInfo windowInfo;
    windowInfo.id = -1;
    windowInfo.pid = 11;
    windowInfo.flags = 0;
    windowInfo.transform.push_back(1.1);
    Rect rect;
    rect.x = 5;
    rect.y = 5;
    rect.width = 10;
    rect.height = 10;
    windowInfo.defaultHotAreas.push_back(rect);
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    inputWindowsManager->lastTouchLogicX_ = 8;
    inputWindowsManager->lastTouchLogicY_ = 8;
    int32_t pointerAction = PointerEvent::POINTER_ACTION_PULL_IN_WINDOW;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->DispatchTouch(pointerAction));
    inputWindowsManager->udsServer_ = nullptr;
    inputWindowsManager->lastTouchEvent_ = nullptr;
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
    inputWindowsManager->lastTouchLogicX_ = -1;
    inputWindowsManager->lastTouchLogicY_ = -1;
}

/**
 * @tc.name: DispatchTouch_004
 * @tc.desc: Test the function DispatchTouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, DispatchTouch_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, GetClientFd(_)).WillOnce(Return(1));
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    EXPECT_CALL(*messageParcelMock_, GetSession(_)).WillOnce(Return(session));
    EXPECT_CALL(*messageParcelMock_, SendMsg(_)).WillOnce(Return(false));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->lastTouchEvent_ = PointerEvent::Create();
    ASSERT_NE(inputWindowsManager->lastTouchEvent_, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    inputWindowsManager->lastTouchEvent_->AddPointerItem(item);
    inputWindowsManager->lastTouchEvent_->SetPointerId(1);
    WindowInfo windowInfo;
    windowInfo.id = -1;
    windowInfo.pid = 11;
    windowInfo.flags = 0;
    windowInfo.transform.push_back(1.1);
    Rect rect;
    rect.x = 5;
    rect.y = 5;
    rect.width = 10;
    rect.height = 10;
    windowInfo.defaultHotAreas.push_back(rect);
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    inputWindowsManager->lastTouchLogicX_ = 8;
    inputWindowsManager->lastTouchLogicY_ = 8;
    int32_t pointerAction = PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->DispatchTouch(pointerAction));
    inputWindowsManager->udsServer_ = nullptr;
    inputWindowsManager->lastTouchEvent_ = nullptr;
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
    inputWindowsManager->lastTouchLogicX_ = -1;
    inputWindowsManager->lastTouchLogicY_ = -1;
}

/**
 * @tc.name: DispatchTouch_005
 * @tc.desc: Test the function DispatchTouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, DispatchTouch_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, GetClientFd(_)).WillOnce(Return(1));
    SessionPtr session = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    EXPECT_CALL(*messageParcelMock_, GetSession(_)).WillOnce(Return(session));
    EXPECT_CALL(*messageParcelMock_, SendMsg(_)).WillOnce(Return(true));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->lastTouchEvent_ = PointerEvent::Create();
    ASSERT_NE(inputWindowsManager->lastTouchEvent_, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    inputWindowsManager->lastTouchEvent_->AddPointerItem(item);
    inputWindowsManager->lastTouchEvent_->SetPointerId(1);
    WindowInfo windowInfo;
    windowInfo.id = -1;
    windowInfo.pid = 11;
    windowInfo.flags = 0;
    windowInfo.transform.push_back(1.1);
    Rect rect;
    rect.x = 5;
    rect.y = 5;
    rect.width = 10;
    rect.height = 10;
    windowInfo.defaultHotAreas.push_back(rect);
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    inputWindowsManager->lastTouchLogicX_ = 8;
    inputWindowsManager->lastTouchLogicY_ = 8;
    int32_t pointerAction = PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->DispatchTouch(pointerAction));
    inputWindowsManager->udsServer_ = nullptr;
    inputWindowsManager->lastTouchEvent_ = nullptr;
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
    inputWindowsManager->lastTouchLogicX_ = -1;
    inputWindowsManager->lastTouchLogicY_ = -1;
}

/**
 * @tc.name: DispatchTouch_006
 * @tc.desc: Test the function DispatchTouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, DispatchTouch_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    ASSERT_NE(inputWindowsManager->udsServer_, nullptr);

    inputWindowsManager->lastTouchEvent_ = PointerEvent::Create();
    ASSERT_NE(inputWindowsManager->lastTouchEvent_, nullptr);

    int32_t pointerAction = PointerEvent::POINTER_ACTION_PULL_IN_WINDOW;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->DispatchTouch(pointerAction));
}

/**
 * @tc.name: DispatchTouch_007
 * @tc.desc: Test the function DispatchTouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, DispatchTouch_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    ASSERT_NE(inputWindowsManager->udsServer_, nullptr);

    inputWindowsManager->lastTouchEvent_ = PointerEvent::Create();
    ASSERT_NE(inputWindowsManager->lastTouchEvent_, nullptr);

    int32_t pointerAction = PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->DispatchTouch(pointerAction));
}

/**
 * @tc.name: TransformWindowXY_001
 * @tc.desc: Test the function TransformWindowXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, TransformWindowXY_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    window.transform = { 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0 };
    double logicX = 1.1;
    double logicY = 1.1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->TransformWindowXY(window, logicX, logicY));
}

/**
 * @tc.name: TransformWindowXY_002
 * @tc.desc: Test the function TransformWindowXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, TransformWindowXY_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    window.transform = { 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0 };
    double logicX = 1.1;
    double logicY = 1.1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->TransformWindowXY(window, logicX, logicY));
}

/**
 * @tc.name: TransformWindowXY_003
 * @tc.desc: Test the function TransformWindowXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, TransformWindowXY_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);

    WindowInfo window;
    window.transform = { 1.0, 2.0, 3.0 };
    Matrix3f transforms(window.transform);

    EXPECT_TRUE(window.transform.size() == 3);
    bool ret = transforms.IsIdentity();
    EXPECT_FALSE(ret);

    double logicX = 1.1;
    double logicY = 2.1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->TransformWindowXY(window, logicX, logicY));
}

/**
 * @tc.name: TransformWindowXY_004
 * @tc.desc: Test the function TransformWindowXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, TransformWindowXY_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);

    WindowInfo window;
    window.transform = { 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0 };
    Matrix3f transforms(window.transform);

    EXPECT_TRUE(window.transform.size() == 9);
    bool ret = transforms.IsIdentity();
    EXPECT_FALSE(ret);

    double logicX = 3.2;
    double logicY = 5.1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->TransformWindowXY(window, logicX, logicY));
}

/**
 * @tc.name: IsValidZorderWindow_001
 * @tc.desc: Test the function IsValidZorderWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, IsValidZorderWindow_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NO_MONITOR);
    pointerEvent->SetZOrder(-6.6);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->IsValidZorderWindow(window, pointerEvent));
}

/**
 * @tc.name: IsValidZorderWindow_002
 * @tc.desc: Test the function IsValidZorderWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, IsValidZorderWindow_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NO_MONITOR);
    pointerEvent->SetZOrder(6.6);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->IsValidZorderWindow(window, pointerEvent));
}

/**
 * @tc.name: IsValidZorderWindow_003
 * @tc.desc: Test the function IsValidZorderWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, IsValidZorderWindow_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);
    pointerEvent->SetZOrder(-6.6);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->IsValidZorderWindow(window, pointerEvent));
}

/**
 * @tc.name: IsValidZorderWindow_004
 * @tc.desc: Test the function IsValidZorderWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, IsValidZorderWindow_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    window.zOrder = 8.8;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);
    pointerEvent->SetZOrder(6.6);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->IsValidZorderWindow(window, pointerEvent));
}

/**
 * @tc.name: IsValidZorderWindow_005
 * @tc.desc: Test the function IsValidZorderWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, IsValidZorderWindow_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    window.zOrder = 1.1;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);
    pointerEvent->SetZOrder(6.6);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->IsValidZorderWindow(window, pointerEvent));
}

/**
 * @tc.name: IsValidZorderWindow_006
 * @tc.desc: Test the function IsValidZorderWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, IsValidZorderWindow_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);

    uint32_t flag;
    WindowInfo window;
    window.zOrder = 1.1;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    flag = InputEvent::EVENT_FLAG_SIMULATE;
    EXPECT_FALSE(pointerEvent->HasFlag(flag));

    bool ret = inputWindowsManager->IsValidZorderWindow(window, pointerEvent);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: IsValidZorderWindow_007
 * @tc.desc: Test the function IsValidZorderWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, IsValidZorderWindow_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);

    uint32_t flag;
    WindowInfo window;
    window.zOrder = 3.2;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    flag = InputEvent::EVENT_FLAG_TOUCHPAD_POINTER;
    EXPECT_FALSE(pointerEvent->HasFlag(flag));

    bool ret = inputWindowsManager->IsValidZorderWindow(window, pointerEvent);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: HandleWindowInputType_001
 * @tc.desc: Test the function HandleWindowInputType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, HandleWindowInputType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->HandleWindowInputType(window, pointerEvent));
}

/**
 * @tc.name: HandleWindowInputType_002
 * @tc.desc: Test the function HandleWindowInputType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, HandleWindowInputType_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    window.windowInputType = WindowInputType::NORMAL;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(1);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->HandleWindowInputType(window, pointerEvent));
}

/**
 * @tc.name: HandleWindowInputType_003
 * @tc.desc: Test the function HandleWindowInputType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, HandleWindowInputType_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    window.windowInputType = WindowInputType::TRANSMIT_ALL;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(1);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->HandleWindowInputType(window, pointerEvent));
}

/**
 * @tc.name: HandleWindowInputType_004
 * @tc.desc: Test the function HandleWindowInputType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, HandleWindowInputType_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    window.windowInputType = WindowInputType::TRANSMIT_EXCEPT_MOVE;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(1);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->HandleWindowInputType(window, pointerEvent));
}

/**
 * @tc.name: HandleWindowInputType_005
 * @tc.desc: Test the function HandleWindowInputType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, HandleWindowInputType_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    window.windowInputType = WindowInputType::ANTI_MISTAKE_TOUCH;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(1);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->HandleWindowInputType(window, pointerEvent));
}

/**
 * @tc.name: HandleWindowInputType_006
 * @tc.desc: Test the function HandleWindowInputType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, HandleWindowInputType_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    window.windowInputType = WindowInputType::TRANSMIT_AXIS_MOVE;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(1);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->HandleWindowInputType(window, pointerEvent));
}

/**
 * @tc.name: HandleWindowInputType_007
 * @tc.desc: Test the function HandleWindowInputType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, HandleWindowInputType_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    window.windowInputType = WindowInputType::TRANSMIT_MOUSE_MOVE;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(1);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->HandleWindowInputType(window, pointerEvent));
}

/**
 * @tc.name: HandleWindowInputType_008
 * @tc.desc: Test the function HandleWindowInputType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, HandleWindowInputType_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    window.windowInputType = WindowInputType::TRANSMIT_LEFT_RIGHT;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(1);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->HandleWindowInputType(window, pointerEvent));
}

/**
 * @tc.name: HandleWindowInputType_009
 * @tc.desc: Test the function HandleWindowInputType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, HandleWindowInputType_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    window.windowInputType = WindowInputType::TRANSMIT_BUTTOM;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(1);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->HandleWindowInputType(window, pointerEvent));
}

/**
 * @tc.name: HandleWindowInputType_010
 * @tc.desc: Test the function HandleWindowInputType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, HandleWindowInputType_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    window.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(1);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->HandleWindowInputType(window, pointerEvent));
}

/**
 * @tc.name: HandleWindowInputType_011
 * @tc.desc: Test the function HandleWindowInputType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, HandleWindowInputType_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    window.windowInputType = WindowInputType::MIX_BUTTOM_ANTI_AXIS_MOVE;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(1);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->HandleWindowInputType(window, pointerEvent));
}

/**
 * @tc.name: HandleWindowInputType_012
 * @tc.desc: Test the function HandleWindowInputType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, HandleWindowInputType_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    WindowInfo window;
    window.windowInputType = static_cast<WindowInputType>(8);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(1);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->HandleWindowInputType(window, pointerEvent));
}

/**
 * @tc.name: DrawTouchGraphic_001
 * @tc.desc: Test the function DrawTouchGraphic
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, DrawTouchGraphic_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    inputWindowsManager->knuckleDrawMgr_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->DrawTouchGraphic(pointerEvent));
}

/**
 * @tc.name: DrawTouchGraphic_002
 * @tc.desc: Test the function DrawTouchGraphic
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, DrawTouchGraphic_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    inputWindowsManager->knuckleDrawMgr_ = std::make_shared<KnuckleDrawingManager>();
    ASSERT_NE(inputWindowsManager->knuckleDrawMgr_, nullptr);
    inputWindowsManager->knuckleDynamicDrawingManager_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->DrawTouchGraphic(pointerEvent));
}

/**
 * @tc.name: DrawTouchGraphic_003
 * @tc.desc: Test the function DrawTouchGraphic
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, DrawTouchGraphic_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    inputWindowsManager->knuckleDrawMgr_ = std::make_shared<KnuckleDrawingManager>();
    ASSERT_NE(inputWindowsManager->knuckleDrawMgr_, nullptr);

    inputWindowsManager->knuckleDynamicDrawingManager_ = std::make_shared<KnuckleDynamicDrawingManager>();
    ASSERT_NE(inputWindowsManager->knuckleDynamicDrawingManager_, nullptr);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->DrawTouchGraphic(pointerEvent));
}
} // namespace MMI
} // namespace OHOS