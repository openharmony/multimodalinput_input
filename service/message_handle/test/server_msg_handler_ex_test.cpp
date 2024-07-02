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

#include "server_msg_handler.h"

#include "i_input_windows_manager.h"
#include "input_event_handler.h"
#include "mmi_log.h"
#include "mock.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ServerMsgHandlerExTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
const std::string PROGRAM_NAME = "uds_session_test";
constexpr int32_t MODULE_TYPE = 1;
constexpr int32_t UDS_FD = 1;
constexpr int32_t UDS_UID = 100;
constexpr int32_t UDS_PID = 100;
constexpr uint32_t NUM = 1;
} // namespace

class ServerMsgHandlerExTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

    static inline std::shared_ptr<MessageParcelMock> messageParcelMock_ = nullptr;
};

void ServerMsgHandlerExTest::SetUpTestCase(void)
{
    messageParcelMock_ = std::make_shared<MessageParcelMock>();
    MessageParcelMock::messageParcel = messageParcelMock_;
}

void ServerMsgHandlerExTest::TearDownTestCase()
{
    MessageParcelMock::messageParcel = nullptr;
    messageParcelMock_ = nullptr;
}

/**
 * @tc.name: ServerMsgHandlerExTest_AccelerateMotion
 * @tc.desc: Test the function AccelerateMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerExTest, ServerMsgHandlerExTest_AccelerateMotion, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorPosition cursorPos;
    cursorPos.displayId = 1;
    cursorPos.cursorPos.x = 100;
    cursorPos.cursorPos.y = 100;
    EXPECT_CALL(*messageParcelMock_, GetCursorPos()).WillRepeatedly(Return(cursorPos));
    DisplayInfo displayInfo;
    displayInfo.displayDirection = DIRECTION0;
    EXPECT_CALL(*messageParcelMock_, GetPhysicalDisplay(_)).WillRepeatedly(Return(&displayInfo));
    ServerMsgHandler handler;
    PointerEvent::PointerItem item;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_RAW_POINTER_MOVEMENT;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(1);
    item.SetPointerId(1);
    item.SetRawDx(100);
    item.SetRawDy(100);
    pointerEvent->AddPointerItem(item);
    EXPECT_EQ(handler.AccelerateMotion(pointerEvent), RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerExTest_AccelerateMotion_001
 * @tc.desc: Test the function AccelerateMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerExTest, ServerMsgHandlerExTest_AccelerateMotion_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorPosition cursorPos;
    cursorPos.displayId = 1;
    cursorPos.cursorPos.x = 100;
    cursorPos.cursorPos.y = 100;
    EXPECT_CALL(*messageParcelMock_, GetCursorPos()).WillRepeatedly(Return(cursorPos));
    DisplayInfo displayInfo;
    displayInfo.displayDirection = DIRECTION90;
    EXPECT_CALL(*messageParcelMock_, GetPhysicalDisplay(_)).WillRepeatedly(Return(&displayInfo));
    ServerMsgHandler handler;
    PointerEvent::PointerItem item;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->bitwise_ = 0x00000030;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(1);
    item.SetPointerId(1);
    item.SetRawDx(100);
    item.SetRawDy(100);
    pointerEvent->AddPointerItem(item);
    EXPECT_EQ(handler.AccelerateMotion(pointerEvent), RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerExTest_CalculateOffset
 * @tc.desc: Test the function CalculateOffset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerExTest, ServerMsgHandlerExTest_CalculateOffset, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    Direction direction = DIRECTION90;
    Offset offset;
    offset.dx = 100;
    offset.dy = 100;
    EXPECT_NO_FATAL_FAILURE(handler.CalculateOffset(direction, offset));
    direction = DIRECTION180;
    EXPECT_NO_FATAL_FAILURE(handler.CalculateOffset(direction, offset));
    direction = DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(handler.CalculateOffset(direction, offset));
    direction = DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(handler.CalculateOffset(direction, offset));
}

/**
 * @tc.name: ServerMsgHandlerExTest_OnAuthorize
 * @tc.desc: Test the function OnAuthorize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerExTest, ServerMsgHandlerExTest_OnAuthorize, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    bool isAuthorize = true;
    handler.CurrentPID_ = 1;
    handler.InjectionType_ = InjectionType::KEYEVENT;
    handler.injectNotice_ = std::make_shared<InjectNoticeManager>();
    EXPECT_EQ(handler.OnAuthorize(isAuthorize), RET_OK);
    handler.InjectionType_ = InjectionType::POINTEREVENT;
    EXPECT_EQ(handler.OnAuthorize(isAuthorize), RET_OK);
    isAuthorize = false;
    EXPECT_EQ(handler.OnAuthorize(isAuthorize), RET_OK);
    handler.CurrentPID_ = 2;
    EXPECT_EQ(handler.OnAuthorize(isAuthorize), RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerExTest_OnDisplayInfo
 * @tc.desc: Test the function OnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerExTest, ServerMsgHandlerExTest_OnDisplayInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    DisplayGroupInfo displayGroupInfo {
        .width = 100,
        .height = 100,
        .focusWindowId = 10,
        .currentUserId = 20,
    };
    pkt << displayGroupInfo.width << displayGroupInfo.height
        << displayGroupInfo.focusWindowId << displayGroupInfo.currentUserId << NUM;
    pkt.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_WRITE;
    EXPECT_EQ(handler.OnDisplayInfo(sess, pkt), RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerExTest_OnDisplayInfo_001
 * @tc.desc: Test the function OnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerExTest, ServerMsgHandlerExTest_OnDisplayInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.width = 100,
    displayGroupInfo.height = 100,
    displayGroupInfo.focusWindowId = 10,
    displayGroupInfo.currentUserId = 20,
    pkt << displayGroupInfo.width << displayGroupInfo.height
        << displayGroupInfo.focusWindowId << displayGroupInfo.currentUserId << NUM;
    WindowInfo info;
    info.id = 10;
    info.pid = 100;
    info.uid = 150;
    info.area = { 100, 100, 300, 300 };
    info.defaultHotAreas.push_back({ 100, 100, 300, 300 });
    info.pointerHotAreas.push_back({ 100, 100, 300, 300 });
    info.agentWindowId = 15;
    info.flags = 100;
    info.displayId = 30;
    info.zOrder = 300.0f;
    info.pointerChangeAreas.push_back(100);
    info.transform.push_back(100.0f);
    info.windowType = 1;
    int32_t byteCount = 1;
    pkt << info.id << info.pid << info.uid << info.area << info.defaultHotAreas << info.pointerHotAreas
        << info.agentWindowId << info.flags << info.action << info.displayId << info.zOrder << info.pointerChangeAreas
        << info.transform << info.windowInputType << info.privacyMode << info.windowType << byteCount << NUM;
    DisplayInfo displayinfo;
    displayinfo.id = 10,
    displayinfo.x = 100,
    displayinfo.y = 10,
    displayinfo.width = 300,
    displayinfo.height = 300,
    displayinfo.dpi = 50,
    displayinfo.name = "touch_screen_test",
    displayinfo.uniq = "uniq_test",
    displayinfo.direction = DIRECTION0,
    displayinfo.displayDirection  = DIRECTION0,
    pkt << displayinfo.id << displayinfo.x << displayinfo.y << displayinfo.width << displayinfo.height
        << displayinfo.dpi << displayinfo.name << displayinfo.uniq << displayinfo.direction
        << displayinfo.displayDirection << displayinfo.displayMode;
    EXPECT_EQ(handler.OnDisplayInfo(sess, pkt), RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerExTest_OnDisplayInfo_002
 * @tc.desc: Test the function OnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerExTest, ServerMsgHandlerExTest_OnDisplayInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.width = 100,
    displayGroupInfo.height = 100,
    displayGroupInfo.focusWindowId = 10,
    displayGroupInfo.currentUserId = 20,
    pkt << displayGroupInfo.width << displayGroupInfo.height
        << displayGroupInfo.focusWindowId << displayGroupInfo.currentUserId << NUM;
    std::vector<Rect> rect { { 100, 100, 300, 300 } };
    std::vector<int32_t> pointerChangeAreas { 100 };
    std::vector<float> transform { 100.0f };
    WindowInfo info;
    info.id = 10;
    info.pid = 100;
    info.uid = 150;
    info.area = { 100, 100, 300, 300 };
    info.defaultHotAreas.push_back({ 100, 100, 300, 300 });
    info.pointerHotAreas.push_back({ 100, 100, 300, 300 });
    info.agentWindowId = 15;
    info.flags = 100;
    info.displayId = 30;
    info.zOrder = 300.0f;
    info.pointerChangeAreas.push_back(100);
    info.transform.push_back(100.0f);
    info.windowType = 1;
    int32_t num = 0;
    int32_t byteCount = 0;
    pkt << info.id << info.pid << info.uid << info.area << info.defaultHotAreas << info.pointerHotAreas
        << info.agentWindowId << info.flags << info.action << info.displayId << info.zOrder << info.pointerChangeAreas
        << info.transform << info.windowInputType << info.privacyMode << info.windowType << byteCount << num;
    EXPECT_EQ(handler.OnDisplayInfo(sess, pkt), RET_OK);
}
} // namespace MMI
} // namespace OHOS