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

#include "input_event_handler.h"
#include "libinput_mock.h"
#include "libinput_wrapper.h"
#include "x_key_event_processor.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "XKeyEventProcessorTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
}
class XKeyEventProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void){};
    static void TearDownTestCase(void){};
    void SetUp(){};
    void TearDown(){};
    libinput_event *GetEvent();

private:
    static LibinputWrapper libinput_;
};

LibinputWrapper XKeyEventProcessorTest::libinput_;

libinput_event *XKeyEventProcessorTest::GetEvent()
{
    libinput_event *event = nullptr;
    libinput_event *evt = libinput_.Dispatch();
    while (evt != nullptr) {
        auto type = libinput_event_get_type(evt);
        if (type == LIBINPUT_EVENT_POINTER_AXIS) {
            event = evt;
        }
        evt = libinput_.Dispatch();
    }
    return event;
}

#ifdef OHOS_BUILD_ENABLE_X_KEY
/**
 * @tc.name: XKeyEventProcessorTest_IsXKeyEvent_001
 * @tc.desc: Test IsXKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(XKeyEventProcessorTest, XKeyEventProcessorTest_IsXKeyEvent_001, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event;
    struct libinput_device device;
    bool ret = XKeyEventHdr->IsXKeyEvent(&event);
    EXPECT_FALSE(ret);
    EXPECT_CALL(mock, GetDevice)
        .WillRepeatedly(Return(&device));
    EXPECT_CALL(mock, DeviceGetName)
        .WillRepeatedly(Return(const_cast<char*>("not_xKey")));
    EXPECT_FALSE(XKeyEventHdr->IsXKeyEvent(&event));
    EXPECT_CALL(mock, DeviceGetName)
        .WillRepeatedly(Return(const_cast<char*>("fkey")));
    EXPECT_TRUE(XKeyEventHdr->IsXKeyEvent(&event));
}

/**
 * @tc.name: XKeyEventProcessorTest_HandleXKeyEvent_001
 * @tc.desc: Test HandleXKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(XKeyEventProcessorTest, XKeyEventProcessorTest_HandleXKeyEvent_001, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event;
    struct libinput_device device;
    struct libinput_event_keyboard keyBoardEvent;
    EXPECT_CALL(mock, GetDevice)
        .WillRepeatedly(Return(&device));
    EXPECT_CALL(mock, DeviceGetName)
        .WillRepeatedly(Return(const_cast<char*>("fkey")));
    EXPECT_CALL(mock, LibinputEventGetKeyboardEvent)
        .WillOnce(Return(&keyBoardEvent));
    EXPECT_CALL(mock, LibinputEventKeyboardGetKeyState)
        .WillOnce(Return(LIBINPUT_KEY_STATE_PRESSED));
    int32_t ret = XKeyEventHdr->HandleXKeyEvent(&event);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: XKeyEventProcessorTest_HandleXKeyEvent_002
 * @tc.desc: Test HandleXKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(XKeyEventProcessorTest, XKeyEventProcessorTest_HandleXKeyEvent_002, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event;
    struct libinput_device device;
    EXPECT_CALL(mock, GetDevice)
        .WillRepeatedly(Return(&device));
    EXPECT_CALL(mock, DeviceGetName)
        .WillRepeatedly(Return(const_cast<char*>("not fkey")));
    int32_t ret = XKeyEventHdr->HandleXKeyEvent(&event);
    EXPECT_EQ(ret, PARAM_INPUT_INVALID);
}

/**
 * @tc.name: XKeyEventProcessorTest_AnalyseKeyEvent_001
 * @tc.desc: Test AnalyseKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(XKeyEventProcessorTest, XKeyEventProcessorTest_AnalyseKeyEvent_001, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event;
    struct libinput_event_keyboard keyBoardEvent;
    EXPECT_CALL(mock, LibinputEventGetKeyboardEvent)
        .WillOnce(Return(&keyBoardEvent));
    EXPECT_CALL(mock, LibinputEventKeyboardGetKeyState)
        .WillOnce(Return(LIBINPUT_KEY_STATE_PRESSED));
    EXPECT_EQ(XKeyEventHdr->AnalyseKeyEvent(&event), ERR_OK);
}

/**
 * @tc.name: XKeyEventProcessorTest_AnalyseKeyEvent_002
 * @tc.desc: Test AnalyseKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(XKeyEventProcessorTest, XKeyEventProcessorTest_AnalyseKeyEvent_002, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event;
    struct libinput_event_keyboard keyBoardEvent;
    EXPECT_CALL(mock, LibinputEventGetKeyboardEvent)
        .WillOnce(Return(&keyBoardEvent));
    EXPECT_CALL(mock, LibinputEventKeyboardGetKeyState)
        .WillRepeatedly(Return(LIBINPUT_KEY_STATE_RELEASED));
    EXPECT_EQ(XKeyEventHdr->AnalyseKeyEvent(&event), ERR_OK);
}

/**
 * @tc.name: XKeyEventProcessorTest_InterceptXKeyDown_001
 * @tc.desc: Test InterceptXKeyDown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(XKeyEventProcessorTest, XKeyEventProcessorTest_InterceptXKeyDown_001, TestSize.Level1)
{
    XKeyEventHdr->pressCount_ = 0;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->InterceptXKeyDown());
    XKeyEventHdr->pressCount_ = 2;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->InterceptXKeyDown());
    XKeyEventHdr->pressCount_ = 1;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->InterceptXKeyDown());
}

/**
 * @tc.name: XKeyEventProcessorTest_StartLongPressTimer_001
 * @tc.desc: Test StartLongPressTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(XKeyEventProcessorTest, XKeyEventProcessorTest_StartLongPressTimer_001, TestSize.Level1)
{
    XKeyEventHdr->pressCount_ = 1;
    XKeyEventHdr->handledLongPress_ = true;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->StartLongPressTimer());
    XKeyEventHdr->pressCount_ = 5;
    XKeyEventHdr->handledLongPress_ = true;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->StartLongPressTimer());
    XKeyEventHdr->pressCount_ = 1;
    XKeyEventHdr->handledLongPress_ = false;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->StartLongPressTimer());
    XKeyEventHdr->pressCount_ = 5;
    XKeyEventHdr->handledLongPress_ = false;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->StartLongPressTimer());
    XKeyEventHdr->pressCount_ = 2;
    XKeyEventHdr->handledLongPress_ = true;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->StartLongPressTimer());
    XKeyEventHdr->pressCount_ = 2;
    XKeyEventHdr->handledLongPress_ = false;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->StartLongPressTimer());
}

/**
 * @tc.name: XKeyEventProcessorTest_InterceptXKeyUp_001
 * @tc.desc: Test InterceptXKeyUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(XKeyEventProcessorTest, XKeyEventProcessorTest_InterceptXKeyUp_001, TestSize.Level1)
{
    XKeyEventHdr->pressCount_ = 2;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->InterceptXKeyUp());
    XKeyEventHdr->pressCount_ = 5;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->InterceptXKeyUp());
}

/**
 * @tc.name: XKeyEventProcessorTest_StartSingleClickTimer_001
 * @tc.desc: Test StartSingleClickTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(XKeyEventProcessorTest, XKeyEventProcessorTest_StartSingleClickTimer_001, TestSize.Level1)
{
    XKeyEventHdr->pressCount_ = 1;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->StartSingleClickTimer());
    XKeyEventHdr->pressCount_ = 2;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->StartSingleClickTimer());
    XKeyEventHdr->pressCount_ = 5;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->StartSingleClickTimer());
}

/**
 * @tc.name: XKeyEventProcessorTest_RemoveTimer_001
 * @tc.desc: Test RemoveTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(XKeyEventProcessorTest, XKeyEventProcessorTest_RemoveTimer_001, TestSize.Level1)
{
    XKeyEventHdr->singleClickTimerId_ = 5;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->RemoveTimer());
    XKeyEventHdr->singleClickTimerId_ = -1;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->RemoveTimer());
    XKeyEventHdr->longPressTimerId_ = 5;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->RemoveTimer());
    XKeyEventHdr->longPressTimerId_ = -1;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->RemoveTimer());
}

/**
 * @tc.name: XKeyEventProcessorTest_HandleQuickAccessMenu_001
 * @tc.desc: Test HandleQuickAccessMenu
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(XKeyEventProcessorTest, XKeyEventProcessorTest_HandleQuickAccessMenu_001, TestSize.Level1)
{
    int32_t xKeyEventType = 0;
    int32_t ret = XKeyEventHdr->HandleQuickAccessMenu(xKeyEventType);
    ASSERT_EQ(ret, RET_OK);
    xKeyEventType = 1;
    ret = XKeyEventHdr->HandleQuickAccessMenu(xKeyEventType);
    ASSERT_EQ(ret, RET_OK);
    xKeyEventType = 2;
    ret = XKeyEventHdr->HandleQuickAccessMenu(xKeyEventType);
    ASSERT_EQ(ret, RET_OK);
    xKeyEventType = 3;
    ret = XKeyEventHdr->HandleQuickAccessMenu(xKeyEventType);
    ASSERT_EQ(ret, RET_OK);
    xKeyEventType = 4;
    ret = XKeyEventHdr->HandleQuickAccessMenu(xKeyEventType);
    ASSERT_EQ(ret, RET_OK);
    xKeyEventType = 5;
    ret = XKeyEventHdr->HandleQuickAccessMenu(xKeyEventType);
    ASSERT_EQ(ret, RET_OK);
}

#if (defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)) && defined(OHOS_BUILD_ENABLE_MONITOR)
/**
 * @tc.name: XKeyEventProcessorTest_HandleQuickAccessMenu_002
 * @tc.desc: Test HandleQuickAccessMenu
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(XKeyEventProcessorTest, XKeyEventProcessorTest_HandleQuickAccessMenu_002, TestSize.Level1)
{
    int32_t xKeyEventType = 5;
    InputHandler->eventMonitorHandler_ = std::make_shared<EventMonitorHandler>();
    int32_t ret = XKeyEventHdr->HandleQuickAccessMenu(xKeyEventType);
    ASSERT_EQ(ret, RET_OK);
    InputHandler->eventMonitorHandler_ = nullptr;
    ret = XKeyEventHdr->HandleQuickAccessMenu(xKeyEventType);
    ASSERT_EQ(ret, RET_OK);
}
#endif // (OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH) && OHOS_BUILD_ENABLE_MONITOR

/**
 * @tc.name: XKeyEventProcessorTest_StartXKeyIfNeeded_001
 * @tc.desc: Test StartXKeyIfNeeded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(XKeyEventProcessorTest, XKeyEventProcessorTest_StartXKeyIfNeeded_001, TestSize.Level1)
{
    int32_t xKeyEventType = 1;
    XKeyEventHdr->isStartedXKey_ = false;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->StartXKeyIfNeeded(xKeyEventType));
    XKeyEventHdr->isStartedXKey_ = true;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->StartXKeyIfNeeded(xKeyEventType));
    xKeyEventType = 2;
    XKeyEventHdr->isStartedXKey_ = false;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->StartXKeyIfNeeded(xKeyEventType));
    xKeyEventType = 3;
    XKeyEventHdr->isStartedXKey_ = false;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->StartXKeyIfNeeded(xKeyEventType));
    xKeyEventType = 4;
    XKeyEventHdr->isStartedXKey_ = false;
    ASSERT_NO_FATAL_FAILURE(XKeyEventHdr->StartXKeyIfNeeded(xKeyEventType));
}
#endif // OHOS_BUILD_ENABLE_X_KEY
} // namespace MMI
} // namespace OHOS