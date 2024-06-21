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
#include <libinput.h>

#include "input_windows_manager.h"
#include "mock.h"

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
    EXPECT_CALL(*messageParcelMock_, IsFoldable()).WillOnce(Return(false));
    IInputWindowsManager::instance_.reset();
    IInputWindowsManager::instance_ = nullptr;
    MessageParcelMock::messageParcel = nullptr;
    messageParcelMock_ = nullptr;
}

/**
 * @tc.name: RegisterFoldStatusListener_001
 * @tc.desc: Test the function RegisterFoldStatusListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, RegisterFoldStatusListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, IsFoldable()).WillOnce(Return(false));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->RegisterFoldStatusListener());
}

/**
 * @tc.name: RegisterFoldStatusListener_002
 * @tc.desc: Test the function RegisterFoldStatusListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, RegisterFoldStatusListener_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, IsFoldable()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, RegisterFoldStatusListener(_))
        .WillOnce(Return(Rosen::DMError::DM_ERROR_INIT_DMS_PROXY_LOCKED));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->RegisterFoldStatusListener());
}

/**
 * @tc.name: RegisterFoldStatusListener_003
 * @tc.desc: Test the function RegisterFoldStatusListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, RegisterFoldStatusListener_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, IsFoldable()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, RegisterFoldStatusListener(_)).WillOnce(Return(Rosen::DMError::DM_OK));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->RegisterFoldStatusListener());
    inputWindowsManager->foldStatusListener_ = nullptr;
}

/**
 * @tc.name: OnFoldStatusChanged_001
 * @tc.desc: Test the function OnFoldStatusChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, OnFoldStatusChanged_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, IsFoldable()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, RegisterFoldStatusListener(_)).WillOnce(Return(Rosen::DMError::DM_OK));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    inputWindowsManager->RegisterFoldStatusListener();
    ASSERT_NE(inputWindowsManager->foldStatusListener_, nullptr);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->foldStatusListener_->OnFoldStatusChanged(Rosen::FoldStatus::UNKNOWN));
    inputWindowsManager->foldStatusListener_ = nullptr;
}

/**
 * @tc.name: OnFoldStatusChanged_002
 * @tc.desc: Test the function OnFoldStatusChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, OnFoldStatusChanged_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, IsFoldable()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, RegisterFoldStatusListener(_)).WillOnce(Return(Rosen::DMError::DM_OK));
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    inputWindowsManager->RegisterFoldStatusListener();
    ASSERT_NE(inputWindowsManager->foldStatusListener_, nullptr);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->foldStatusListener_->OnFoldStatusChanged(Rosen::FoldStatus::EXPAND));
    inputWindowsManager->foldStatusListener_ = nullptr;
}

/**
 * @tc.name: OnFoldStatusChanged_003
 * @tc.desc: Test the function OnFoldStatusChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, OnFoldStatusChanged_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    inputWindowsManager->lastPointerEventForFold_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->OnFoldStatusChanged(Rosen::FoldStatus::EXPAND));
}

/**
 * @tc.name: OnFoldStatusChanged_004
 * @tc.desc: Test the function OnFoldStatusChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, OnFoldStatusChanged_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    inputWindowsManager->lastPointerEventForFold_ = PointerEvent::Create();
    ASSERT_NE(inputWindowsManager->lastPointerEventForFold_, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetPressed(false);
    inputWindowsManager->lastPointerEventForFold_->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->OnFoldStatusChanged(Rosen::FoldStatus::EXPAND));
    inputWindowsManager->lastPointerEventForFold_->RemoveAllPointerItems();
    inputWindowsManager->lastPointerEventForFold_.reset();
    inputWindowsManager->lastPointerEventForFold_ = nullptr;
}

/**
 * @tc.name: OnFoldStatusChanged_005
 * @tc.desc: Test the function OnFoldStatusChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, OnFoldStatusChanged_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    inputWindowsManager->lastPointerEventForFold_ = PointerEvent::Create();
    ASSERT_NE(inputWindowsManager->lastPointerEventForFold_, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetPressed(true);
    inputWindowsManager->lastPointerEventForFold_->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->OnFoldStatusChanged(Rosen::FoldStatus::EXPAND));
    inputWindowsManager->lastPointerEventForFold_->RemoveAllPointerItems();
    inputWindowsManager->lastPointerEventForFold_.reset();
    inputWindowsManager->lastPointerEventForFold_ = nullptr;
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
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillOnce(Return(false));
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
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled())
        .WillOnce(Return(false)).WillOnce(Return(false))
        .WillOnce(Return(false)).WillOnce(Return(false))
        .WillOnce(Return(false));
    EXPECT_CALL(*messageParcelMock_, GetMouseDisplayState())
        .WillOnce(Return(false)).WillOnce(Return(false))
        .WillOnce(Return(false)).WillOnce(Return(false));
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
    EXPECT_CALL(*messageParcelMock_, GetBoolValue(_, _)).WillOnce(Return(false));
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillOnce(Return(false));
    EXPECT_CALL(*messageParcelMock_, GetMouseDisplayState())
        .WillOnce(Return(false)).WillOnce(Return(false))
        .WillOnce(Return(false)).WillOnce(Return(false));
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
    EXPECT_CALL(*messageParcelMock_, GetBoolValue(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, GetMouseDisplayState()).WillOnce(Return(false));
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
    EXPECT_CALL(*messageParcelMock_, GetBoolValue(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, GetMouseDisplayState()).WillOnce(Return(true));
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
    EXPECT_CALL(*messageParcelMock_, GetBoolValue(_, _)).WillOnce(Return(false));
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillOnce(Return(false));
    EXPECT_CALL(*messageParcelMock_, GetMouseDisplayState()).WillOnce(Return(true));
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
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillOnce(Return(false));
    EXPECT_CALL(*messageParcelMock_, GetMouseDisplayState()).WillOnce(Return(true));
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
    EXPECT_CALL(*messageParcelMock_, IsSceneBoardEnabled()).WillOnce(Return(false));
    EXPECT_CALL(*messageParcelMock_, GetMouseDisplayState()).WillOnce(Return(true));
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
} // namespace MMI
} // namespace OHOS