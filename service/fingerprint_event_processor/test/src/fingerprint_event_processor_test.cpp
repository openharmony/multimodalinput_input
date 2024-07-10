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

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "fingerprint_event_processor.h"
#include "input_event_handler.h"
#include "libinput_mock.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "FingerprintEventProcessorTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
}
class FingerprintEventProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void){};
    static void TearDownTestCase(void){};
    void SetUp(){};
    void TearDown(){};
};

#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
/**
 * @tc.name: FingerprintEventProcessorTest_IsFingerprintEvent_EventIsNull
 * @tc.desc: Test IsFingerprintEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_IsFingerprintEvent_EventIsNull, TestSize.Level1)
{
    struct libinput_event* event = NULL;
    EXPECT_FALSE(FingerprintEventHdr->IsFingerprintEvent(event));
}

/**
 * @tc.name: FingerprintEventProcessorTest_IsFingerprintEvent_NameIsNotFingerprint
 * @tc.desc: Test IsFingerprintEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest,
    FingerprintEventProcessorTest_IsFingerprintEvent_NameIsNotFingerprint, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event;
    struct libinput_device device;
    EXPECT_CALL(mock, GetDevice)
        .WillRepeatedly(Return(&device));
    EXPECT_CALL(mock, DeviceGetName)
        .WillOnce(Return(const_cast<char*>("not_fingerprint_source_key")))
        .WillOnce(Return(const_cast<char*>("hw_fingerprint_mouse")));
    EXPECT_FALSE(FingerprintEventHdr->IsFingerprintEvent(&event));
    EXPECT_TRUE(FingerprintEventHdr->IsFingerprintEvent(&event));
}

/**
 * @tc.name: FingerprintEventProcessorTest_IsFingerprintEvent_NameIsFingerprintSourceKey_001
 * @tc.desc: Test IsFingerprintEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest,
    FingerprintEventProcessorTest_IsFingerprintEvent_NameIsFingerprintSourceKey_001, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event;
    struct libinput_device device;
    struct libinput_event_keyboard keyBoardEvent;
    EXPECT_CALL(mock, GetDevice)
        .WillOnce(Return(&device));
    EXPECT_CALL(mock, DeviceGetName)
        .WillOnce(Return(const_cast<char*>("fingerprint")));
    EXPECT_CALL(mock, LibinputEventGetKeyboardEvent)
        .WillOnce(Return(&keyBoardEvent));
    EXPECT_CALL(mock, LibinputEventKeyboardGetKey)
        .WillOnce(Return(100));
    EXPECT_FALSE(FingerprintEventHdr->IsFingerprintEvent(&event));
}

/**
 * @tc.name: FingerprintEventProcessorTest_IsFingerprintEvent_NameIsFingerprintSourceKey_002
 * @tc.desc: Test IsFingerprintEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest,
    FingerprintEventProcessorTest_IsFingerprintEvent_NameIsFingerprintSourceKey_002, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event;
    struct libinput_device device;
    struct libinput_event_keyboard keyBoardEvent;
    EXPECT_CALL(mock, GetDevice)
        .WillRepeatedly(Return(&device));
    EXPECT_CALL(mock, DeviceGetName)
        .WillRepeatedly(Return(const_cast<char*>("fingerprint")));
    EXPECT_CALL(mock, LibinputEventGetKeyboardEvent)
        .WillRepeatedly(Return(&keyBoardEvent));
    EXPECT_CALL(mock, LibinputEventKeyboardGetKey)
        .WillOnce(Return(FingerprintEventProcessor::FINGERPRINT_CODE_DOWN))
        .WillOnce(Return(FingerprintEventProcessor::FINGERPRINT_CODE_UP))
        .WillOnce(Return(FingerprintEventProcessor::FINGERPRINT_CODE_CLICK))
        .WillOnce(Return(FingerprintEventProcessor::FINGERPRINT_CODE_RETOUCH));
    EXPECT_TRUE(FingerprintEventHdr->IsFingerprintEvent(&event));
    EXPECT_TRUE(FingerprintEventHdr->IsFingerprintEvent(&event));
    EXPECT_TRUE(FingerprintEventHdr->IsFingerprintEvent(&event));
    EXPECT_TRUE(FingerprintEventHdr->IsFingerprintEvent(&event));
}

/**L
 * @tc.name: FingerprintEventProcessorTest_HandleFingerprintEvent_NameIsFingerprintSourceKey
 * @tc.desc: Test HandleFingerprintEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest,
    FingerprintEventProcessorTest_HandleFingerprintEvent_NameIsFingerprintSourceKey, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event;
    struct libinput_device device;
    struct libinput_event_keyboard keyBoardEvent;
    EXPECT_CALL(mock, GetDevice)
        .WillOnce(Return(&device));
    EXPECT_CALL(mock, DeviceGetName)
        .WillOnce(Return(const_cast<char*>("fingerprint")));
    EXPECT_CALL(mock, LibinputEventGetKeyboardEvent)
        .WillOnce(Return(&keyBoardEvent));
    EXPECT_CALL(mock, LibinputEventKeyboardGetKey)
        .WillOnce(Return(100));
    EXPECT_CALL(mock, LibinputEventKeyboardGetKeyState)
        .WillOnce(Return(LIBINPUT_KEY_STATE_PRESSED));
    EXPECT_EQ(FingerprintEventHdr->HandleFingerprintEvent(&event), ERR_OK);
}

/**
 * @tc.name: FingerprintEventProcessorTest_HandleFingerprintEvent_NameIsFingerprintSourcePoint
 * @tc.desc: Test HandleFingerprintEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest,
    FingerprintEventProcessorTest_HandleFingerprintEvent_NameIsFingerprintSourcePoint, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event;
    struct libinput_device device;
    struct libinput_event_keyboard keyBoardEvent;
    struct libinput_event_pointer rawPointerEvent;
    EXPECT_CALL(mock, GetDevice)
        .WillRepeatedly(Return(&device));
    EXPECT_CALL(mock, DeviceGetName)
        .WillRepeatedly(Return(const_cast<char*>("hw_fingerprint_mouse")));
    EXPECT_CALL(mock, LibinputGetPointerEvent)
        .WillRepeatedly(Return(&rawPointerEvent));
    EXPECT_CALL(mock, PointerGetDxUnaccelerated)
        .WillRepeatedly(Return(0));
    EXPECT_CALL(mock, PointerGetDyUnaccelerated)
        .WillRepeatedly(Return(0));
    EXPECT_EQ(FingerprintEventHdr->HandleFingerprintEvent(&event), RET_OK);
    InputHandler->BuildInputHandlerChain();
    EXPECT_EQ(FingerprintEventHdr->HandleFingerprintEvent(&event), RET_OK);
}

/**
 * @tc.name: FingerprintEventProcessorTest_HandleFingerprintEvent_NameNotFingerprintSourceKey_001
 * @tc.desc: Test HandleFingerprintEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest,
    FingerprintEventProcessorTest_HandleFingerprintEvent_NameNotFingerprintSourceKey_001, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event;
    struct libinput_device device;
    struct libinput_event_keyboard keyBoardEvent;
    EXPECT_CALL(mock, GetDevice)
        .WillOnce(Return(&device));
    EXPECT_CALL(mock, DeviceGetName)
        .WillOnce(Return(const_cast<char*>("not_fingerprint_source_key")));
    EXPECT_EQ(FingerprintEventHdr->HandleFingerprintEvent(&event), MMI::PARAM_INPUT_INVALID);
}

/**
 * @tc.name: FingerprintEventProcessorTest_AnalyseKeyEvent_StateIsLibinputKeyStatePressed
 * @tc.desc: Test AnalyseKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest,
    FingerprintEventProcessorTest_AnalyseKeyEvent_StateIsLibinputKeyStatePressed, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event;
    struct libinput_event_keyboard keyBoardEvent;
    EXPECT_CALL(mock, LibinputEventGetKeyboardEvent)
        .WillOnce(Return(&keyBoardEvent));
    EXPECT_CALL(mock, LibinputEventKeyboardGetKey)
        .WillOnce(Return(FingerprintEventProcessor::FINGERPRINT_CODE_DOWN));
    EXPECT_CALL(mock, LibinputEventKeyboardGetKeyState)
        .WillOnce(Return(LIBINPUT_KEY_STATE_PRESSED));
    EXPECT_EQ(FingerprintEventHdr->AnalyseKeyEvent(&event), ERR_OK);
}

/**
 * @tc.name: FingerprintEventProcessorTest_AnalyseKeyEvent_StateNotLibinputKeyStatePressed
 * @tc.desc: Test AnalyseKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest,
    FingerprintEventProcessorTest_AnalyseKeyEvent_StateNotLibinputKeyStatePressed, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event;
    struct libinput_event_keyboard keyBoardEvent;
    EXPECT_CALL(mock, LibinputEventGetKeyboardEvent)
        .WillRepeatedly(Return(&keyBoardEvent));
    EXPECT_CALL(mock, LibinputEventKeyboardGetKey)
        .WillOnce(Return(FingerprintEventProcessor::FINGERPRINT_CODE_DOWN))
        .WillOnce(Return(FingerprintEventProcessor::FINGERPRINT_CODE_UP))
        .WillOnce(Return(FingerprintEventProcessor::FINGERPRINT_CODE_RETOUCH))
        .WillOnce(Return(FingerprintEventProcessor::FINGERPRINT_CODE_CLICK))
        .WillOnce(Return(100));
    EXPECT_CALL(mock, LibinputEventKeyboardGetKeyState)
        .WillRepeatedly(Return(LIBINPUT_KEY_STATE_RELEASED));
    InputHandler->BuildInputHandlerChain();
    EXPECT_EQ(FingerprintEventHdr->AnalyseKeyEvent(&event), ERR_OK);
    EXPECT_EQ(FingerprintEventHdr->AnalyseKeyEvent(&event), ERR_OK);
    EXPECT_EQ(FingerprintEventHdr->AnalyseKeyEvent(&event), ERR_OK);
    EXPECT_EQ(FingerprintEventHdr->AnalyseKeyEvent(&event), ERR_OK);
    EXPECT_EQ(FingerprintEventHdr->AnalyseKeyEvent(&event), MMI::UNKNOWN_EVENT);
}
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
} // namespace MMI
} // namespace OHOS