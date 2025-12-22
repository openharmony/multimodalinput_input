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
#include "res_type.h"
#include "special_input_device_parser.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "FingerprintEventProcessorTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
const std::string FINGERPRINT_MOUSE { SPECIAL_INPUT_DEVICE_PARSER.GetInputDevName("FINGER_PRINT_MOUSE")} ;
}
class FingerprintEventProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void){};
    static void TearDownTestCase(void){};
    void SetUp() override {
        FingerprintEventHdr = std::make_unique<FingerprintEventProcessor>();
    }
    void TearDown() override {
        FingerprintEventHdr.reset();
    }
protected:
    static constexpr int32_t VOLUME_KEY_CODE = 114;
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
    struct libinput_event event{};
    struct libinput_device device;
    EXPECT_CALL(mock, GetDevice)
        .WillRepeatedly(Return(&device));
    EXPECT_CALL(mock, DeviceGetName)
        .WillOnce(Return(const_cast<char*>("not_fingerprint_source_key")))
        .WillOnce(Return(const_cast<char*>(FINGERPRINT_MOUSE.c_str())));
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
    struct libinput_event event{};
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
    struct libinput_event event{};
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

/**
 * @tc.name: FingerprintEventProcessorTest_HandleFingerprintEvent_NameIsFingerprintSourceKey
 * @tc.desc: Test HandleFingerprintEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest,
    FingerprintEventProcessorTest_HandleFingerprintEvent_NameIsFingerprintSourceKey, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event{};
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
    struct libinput_event event{};
    struct libinput_device device;
    struct libinput_event_keyboard keyBoardEvent;
    struct libinput_event_pointer rawPointerEvent;
    InputHandler->BuildInputHandlerChain();
    EXPECT_CALL(mock, GetDevice)
        .WillOnce(Return(&device));
    EXPECT_CALL(mock, DeviceGetName)
        .WillOnce(Return(const_cast<char*>(FINGERPRINT_MOUSE.c_str())));
    EXPECT_CALL(mock, LibinputGetPointerEvent)
        .WillOnce(Return(&rawPointerEvent));
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
    struct libinput_event event{};
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
    struct libinput_event event{};
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
    struct libinput_event event{};
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
    EXPECT_EQ(FingerprintEventHdr->AnalyseKeyEvent(&event), ERR_OK);
    EXPECT_EQ(FingerprintEventHdr->AnalyseKeyEvent(&event), ERR_OK);
    EXPECT_EQ(FingerprintEventHdr->AnalyseKeyEvent(&event), ERR_OK);
    EXPECT_EQ(FingerprintEventHdr->AnalyseKeyEvent(&event), ERR_OK);
    EXPECT_EQ(FingerprintEventHdr->AnalyseKeyEvent(&event), MMI::UNKNOWN_EVENT);
}

/**
 * @tc.name: FingerprintEventProcessorTest_SetPowerAndVolumeKeyState_001
 * @tc.desc: Test HandleFingerprintEvent (keyCode != KEY_POWER) Branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_SetPowerAndVolumeKeyState_001, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event{};
    struct libinput_device device;
    struct libinput_event_keyboard keyBoardEvent;
    EXPECT_CALL(mock, GetDevice)
        .WillOnce(Return(&device));
    EXPECT_CALL(mock, LibinputEventGetKeyboardEvent)
        .WillOnce(Return(&keyBoardEvent));
    EXPECT_CALL(mock, LibinputEventKeyboardGetKey)
        .WillOnce(Return(100));
    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->SetPowerAndVolumeKeyState(&event));
}

/**
 * @tc.name: FingerprintEventProcessorTest_SetPowerAndVolumeKeyState_002
 * @tc.desc: Test HandleFingerprintEvent (keyAction == KeyEvent::KEY_ACTION_DOWN) Branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_SetPowerAndVolumeKeyState_002, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event{};
    struct libinput_device device;
    struct libinput_event_keyboard keyBoardEvent;
    EXPECT_CALL(mock, GetDevice)
        .WillOnce(Return(&device));
    EXPECT_CALL(mock, LibinputEventGetKeyboardEvent)
        .WillOnce(Return(&keyBoardEvent));
    EXPECT_CALL(mock, LibinputEventKeyboardGetKey)
        .WillOnce(Return(116));
    EXPECT_CALL(mock, LibinputEventKeyboardGetKeyState)
        .WillOnce(Return(LIBINPUT_KEY_STATE_PRESSED));
    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->SetPowerAndVolumeKeyState(&event));
}

/**
 * @tc.name: FingerprintEventProcessorTest_SetPowerAndVolumeKeyState_003
 * @tc.desc: Test HandleFingerprintEvent (keyAction != KeyEvent::KEY_ACTION_DOWN) Branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_SetPowerAndVolumeKeyState_003, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event{};
    struct libinput_device device;
    struct libinput_event_keyboard keyBoardEvent;
    EXPECT_CALL(mock, GetDevice)
        .WillOnce(Return(&device));
    EXPECT_CALL(mock, LibinputEventGetKeyboardEvent)
        .WillOnce(Return(&keyBoardEvent));
    EXPECT_CALL(mock, LibinputEventKeyboardGetKey)
        .WillOnce(Return(116));
    EXPECT_CALL(mock, LibinputEventKeyboardGetKeyState)
        .WillOnce(Return(LIBINPUT_KEY_STATE_RELEASED));
    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->SetPowerAndVolumeKeyState(&event));
}

/**
 * @tc.name: FingerprintEventProcessorTest_ChangeScreenMissTouchFlag_001
 * @tc.desc: Test ChangeScreenMissTouchFlag when screenMissTouchFlag_ is false and finger pressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_ChangeScreenMissTouchFlag_001, TestSize.Level1)
{
    FingerprintEventHdr->screenMissTouchFlag_ = false;
    FingerprintEventHdr->fingerprintFlag_ = false;

    FingerprintEventHdr->ChangeScreenMissTouchFlag(false);

    EXPECT_FALSE(FingerprintEventHdr->screenMissTouchFlag_);
}

/**
 * @tc.name: FingerprintEventProcessorTest_ChangeScreenMissTouchFlag_002
 * @tc.desc: Test ChangeScreenMissTouchFlag when screenMissTouchFlag_ is false and finger pressed with fingerprint event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_ChangeScreenMissTouchFlag_002, TestSize.Level1)
{
    FingerprintEventHdr->screenMissTouchFlag_ = false;
    FingerprintEventHdr->fingerprintFlag_ = true;

    FingerprintEventHdr->ChangeScreenMissTouchFlag(false);

    EXPECT_FALSE(FingerprintEventHdr->screenMissTouchFlag_);
}

/**
 * @tc.name: FingerprintEventProcessorTest_ChangeScreenMissTouchFlag_003
 * @tc.desc: Test ChangeScreenMissTouchFlag when screenMissTouchFlag_ is true and finger released with cancel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_ChangeScreenMissTouchFlag_003, TestSize.Level1)
{
    FingerprintEventHdr->screenMissTouchFlag_ = true;

    FingerprintEventHdr->ChangeScreenMissTouchFlag(true);

    EXPECT_FALSE(FingerprintEventHdr->screenMissTouchFlag_);
}

/**
 * @tc.name: FingerprintEventProcessorTest_ChangeScreenMissTouchFlag_004
 * @tc.desc: Test ChangeScreenMissTouchFlag when screenMissTouchFlag_ is true but no cancel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_ChangeScreenMissTouchFlag_004, TestSize.Level1)
{
    FingerprintEventHdr->screenMissTouchFlag_ = true;

    FingerprintEventHdr->ChangeScreenMissTouchFlag(false);

    EXPECT_TRUE(FingerprintEventHdr->screenMissTouchFlag_);
}

/**
 * @tc.name: FingerprintEventProcessorTest_CheckMisTouchState_001
 * @tc.desc: Test CheckMisTouchState when all conditions are false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CheckMisTouchState_001, TestSize.Level1)
{
    FingerprintEventHdr->antiFalseTouchSwitch_ = false;
    FingerprintEventHdr->screenMissTouchFlag_ = false;

    FingerprintEventHdr->keyStateMap_.clear();

    bool result = FingerprintEventHdr->CheckMisTouchState();

    EXPECT_FALSE(result);
}

/**
 * @tc.name: FingerprintEventProcessorTest_CheckMisTouchState_002
 * @tc.desc: Test CheckMisTouchState when antiFalseTouchSwitch_ is false but other conditions are true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CheckMisTouchState_002, TestSize.Level1)
{
    FingerprintEventHdr->antiFalseTouchSwitch_ = false;
    FingerprintEventHdr->screenMissTouchFlag_ = true;

    FingerprintEventHdr->keyStateMap_[FingerprintEventProcessor::KEY_POWER].first = 1;

    bool result = FingerprintEventHdr->CheckMisTouchState();

    EXPECT_FALSE(result);
}

/**
 * @tc.name: FingerprintEventProcessorTest_CheckMisTouchState_003
 * @tc.desc: Test CheckMisTouchState when only key mis-touch state is true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CheckMisTouchState_003, TestSize.Level1)
{
    FingerprintEventHdr->antiFalseTouchSwitch_ = true;
    FingerprintEventHdr->screenMissTouchFlag_ = false;

    FingerprintEventHdr->keyStateMap_[FingerprintEventProcessor::KEY_POWER].first = 1;

    bool result = FingerprintEventHdr->CheckMisTouchState();

    EXPECT_TRUE(result);
}

/**
 * @tc.name: FingerprintEventProcessorTest_CheckMisTouchState_004
 * @tc.desc: Test CheckMisTouchState when only screen mis-touch state is true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CheckMisTouchState_004, TestSize.Level1)
{
    FingerprintEventHdr->antiFalseTouchSwitch_ = true;
    FingerprintEventHdr->screenMissTouchFlag_ = true;

    FingerprintEventHdr->keyStateMap_.clear();

    bool result = FingerprintEventHdr->CheckMisTouchState();

    EXPECT_TRUE(result);
}

/**
 * @tc.name: FingerprintEventProcessorTest_CheckMisTouchState_005
 * @tc.desc: Test CheckMisTouchState when both key and screen mis-touch states are true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CheckMisTouchState_005, TestSize.Level1)
{
    FingerprintEventHdr->antiFalseTouchSwitch_ = true;
    FingerprintEventHdr->screenMissTouchFlag_ = true;

    FingerprintEventHdr->keyStateMap_[FingerprintEventProcessor::KEY_POWER].first = 1;

    bool result = FingerprintEventHdr->CheckMisTouchState();

    EXPECT_TRUE(result);
}

/**
 * @tc.name: FingerprintEventProcessorTest_CheckMisTouchState_006
 * @tc.desc: Test CheckMisTouchState when key is released but within timeout period
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CheckMisTouchState_006, TestSize.Level1)
{
    FingerprintEventHdr->antiFalseTouchSwitch_ = true;
    FingerprintEventHdr->screenMissTouchFlag_ = false;

    FingerprintEventHdr->keyStateMap_[FingerprintEventProcessor::KEY_POWER].first = 2;
    FingerprintEventHdr->keyStateMap_[FingerprintEventProcessor::KEY_POWER].second = std::chrono::steady_clock::now();

    bool result = FingerprintEventHdr->CheckMisTouchState();

    EXPECT_TRUE(result);
}

/**
 * @tc.name: FingerprintEventProcessorTest_CheckMisTouchState_007
 * @tc.desc: Test CheckMisTouchState when key is released and beyond timeout period
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CheckMisTouchState_007, TestSize.Level1)
{
    FingerprintEventHdr->antiFalseTouchSwitch_ = true;
    FingerprintEventHdr->screenMissTouchFlag_ = false;

    FingerprintEventHdr->keyStateMap_[FingerprintEventProcessor::KEY_POWER].first = 2;
    auto pastTime = std::chrono::steady_clock::now() - std::chrono::milliseconds(1500);
    FingerprintEventHdr->keyStateMap_[FingerprintEventProcessor::KEY_POWER].second = pastTime;

    bool result = FingerprintEventHdr->CheckMisTouchState();

    EXPECT_FALSE(result);
}

/**
 * @tc.name: FingerprintEventProcessorTest_CheckScreenMisTouchState_001
 * @tc.desc: Test CheckScreenMisTouchState when screenMissTouchFlag_ is false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CheckScreenMisTouchState_001, TestSize.Level1)
{
    FingerprintEventHdr->screenMissTouchFlag_ = false;

    bool result = FingerprintEventHdr->CheckScreenMisTouchState();

    EXPECT_FALSE(result);
}

/**
 * @tc.name: FingerprintEventProcessorTest_CheckScreenMisTouchState_002
 * @tc.desc: Test CheckScreenMisTouchState when screenMissTouchFlag_ is true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CheckScreenMisTouchState_002, TestSize.Level1)
{
    FingerprintEventHdr->screenMissTouchFlag_ = true;

    bool result = FingerprintEventHdr->CheckScreenMisTouchState();

    EXPECT_TRUE(result);
}

/**
 * @tc.name: FingerprintEventProcessorTest_CheckKeyMisTouchState_001
 * @tc.desc: Test CheckKeyMisTouchState with empty keyStateMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CheckKeyMisTouchState_001, TestSize.Level1)
{
    FingerprintEventHdr->keyStateMap_.clear();

    bool result = FingerprintEventHdr->CheckKeyMisTouchState();

    EXPECT_FALSE(result);
}

/**
 * @tc.name: FingerprintEventProcessorTest_CheckKeyMisTouchState_002
 * @tc.desc: Test CheckKeyMisTouchState with MUTE_KEY_DOWN state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CheckKeyMisTouchState_002, TestSize.Level1)
{
    FingerprintEventHdr->keyStateMap_.clear();
    FingerprintEventHdr->keyStateMap_[FingerprintEventProcessor::KEY_POWER].first = 1;
    FingerprintEventHdr->keyStateMap_[FingerprintEventProcessor::KEY_POWER].second = std::chrono::steady_clock::now();

    bool result = FingerprintEventHdr->CheckKeyMisTouchState();

    EXPECT_TRUE(result);
}

/**
 * @tc.name: FingerprintEventProcessorTest_CheckKeyMisTouchState_003
 * @tc.desc: Test CheckKeyMisTouchState with MUTE_KEY_UP state within timeout period
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CheckKeyMisTouchState_003, TestSize.Level1)
{
    FingerprintEventHdr->keyStateMap_.clear();
    FingerprintEventHdr->keyStateMap_[FingerprintEventProcessor::KEY_POWER].first = 2;
    FingerprintEventHdr->keyStateMap_[FingerprintEventProcessor::KEY_POWER].second = std::chrono::steady_clock::now();

    bool result = FingerprintEventHdr->CheckKeyMisTouchState();

    EXPECT_TRUE(result);
}

/**
 * @tc.name: FingerprintEventProcessorTest_CheckKeyMisTouchState_004
 * @tc.desc: Test CheckKeyMisTouchState with MUTE_KEY_UP state beyond timeout period
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CheckKeyMisTouchState_004, TestSize.Level1)
{
    FingerprintEventHdr->keyStateMap_.clear();
    FingerprintEventHdr->keyStateMap_[FingerprintEventProcessor::KEY_POWER].first = 2;
    auto pastTime = std::chrono::steady_clock::now() - std::chrono::milliseconds(1500);
    FingerprintEventHdr->keyStateMap_[FingerprintEventProcessor::KEY_POWER].second = pastTime;

    bool result = FingerprintEventHdr->CheckKeyMisTouchState();

    EXPECT_FALSE(result);
    EXPECT_EQ(FingerprintEventHdr->keyStateMap_[FingerprintEventProcessor::KEY_POWER].first, 0);
}

/**
 * @tc.name: FingerprintEventProcessorTest_CheckKeyMisTouchState_005
 * @tc.desc: Test CheckKeyMisTouchState with volume key MUTE_KEY_UP state within timeout period
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CheckKeyMisTouchState_005, TestSize.Level1)
{
    FingerprintEventHdr->keyStateMap_.clear();
    FingerprintEventHdr->keyStateMap_[VOLUME_KEY_CODE].first = 2;
    FingerprintEventHdr->keyStateMap_[VOLUME_KEY_CODE].second = std::chrono::steady_clock::now();

    bool result = FingerprintEventHdr->CheckKeyMisTouchState();

    EXPECT_TRUE(result);
}

/**
 * @tc.name: FingerprintEventProcessorTest_CheckKeyMisTouchState_006
 * @tc.desc: Test CheckKeyMisTouchState with volume key MUTE_KEY_UP state beyond timeout period
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CheckKeyMisTouchState_006, TestSize.Level1)
{
    FingerprintEventHdr->keyStateMap_.clear();
    FingerprintEventHdr->keyStateMap_[VOLUME_KEY_CODE].first = 2;
    auto pastTime = std::chrono::steady_clock::now() - std::chrono::milliseconds(600);
    FingerprintEventHdr->keyStateMap_[VOLUME_KEY_CODE].second = pastTime;

    bool result = FingerprintEventHdr->CheckKeyMisTouchState();

    EXPECT_FALSE(result);
    EXPECT_EQ(FingerprintEventHdr->keyStateMap_[VOLUME_KEY_CODE].first, 0);
}

/**
 * @tc.name: FingerprintEventProcessorTest_CheckKeyMisTouchState_007
 * @tc.desc: Test CheckKeyMisTouchState with multiple keys, one in mis-touch state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CheckKeyMisTouchState_007, TestSize.Level1)
{
    FingerprintEventHdr->keyStateMap_.clear();
    FingerprintEventHdr->keyStateMap_[FingerprintEventProcessor::KEY_POWER].first = 2;
    auto pastTime = std::chrono::steady_clock::now() - std::chrono::milliseconds(1500);
    FingerprintEventHdr->keyStateMap_[FingerprintEventProcessor::KEY_POWER].second = pastTime;

    FingerprintEventHdr->keyStateMap_[114].first = 1;
    FingerprintEventHdr->keyStateMap_[114].second = std::chrono::steady_clock::now();

    bool result = FingerprintEventHdr->CheckKeyMisTouchState();

    EXPECT_TRUE(result);

    EXPECT_EQ(FingerprintEventHdr->keyStateMap_[FingerprintEventProcessor::KEY_POWER].first, 0);
}

/**
 * @tc.name: FingerprintEventProcessorTest_SendFingerprintCancelEvent_001
 * @tc.desc: Test SendFingerprintCancelEvent function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_SendFingerprintCancelEvent_001, TestSize.Level1)
{
    EXPECT_EQ(FingerprintEventHdr->SendFingerprintCancelEvent(), ERR_OK);
}

/**
 * @tc.name: FingerprintEventProcessorTest_AnalysePointEvent_001
 * @tc.desc: Test AnalysePointEvent with valid pointer event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_AnalysePointEvent_001, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event{};
    struct libinput_event_pointer rawPointerEvent{};

    EXPECT_CALL(mock, LibinputGetPointerEvent)
        .WillOnce(Return(&rawPointerEvent));
    EXPECT_CALL(mock, PointerGetDxUnaccelerated)
        .WillOnce(Return(1.5));
    EXPECT_CALL(mock, PointerGetDyUnaccelerated)
        .WillOnce(Return(2.5));

    EXPECT_EQ(FingerprintEventHdr->AnalysePointEvent(&event), RET_OK);
}

/**
 * @tc.name: FingerprintEventProcessorTest_AnalysePointEvent_002
 * @tc.desc: Test AnalysePointEvent when libinput_event_get_pointer_event returns null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_AnalysePointEvent_002, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event{};

    EXPECT_CALL(mock, LibinputGetPointerEvent)
        .WillOnce(Return(nullptr));

    EXPECT_EQ(FingerprintEventHdr->AnalysePointEvent(&event), ERROR_NULL_POINTER);
}

/**
 * @tc.name: FingerprintEventProcessorTest_AnalysePointEvent_003
 * @tc.desc: Test AnalysePointEvent when CheckMisTouchState returns true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_AnalysePointEvent_003, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event{};
    struct libinput_event_pointer rawPointerEvent;

    FingerprintEventHdr->antiFalseTouchSwitch_ = true;
    FingerprintEventHdr->screenMissTouchFlag_ = true;

    EXPECT_CALL(mock, LibinputGetPointerEvent)
        .WillOnce(Return(&rawPointerEvent));
    EXPECT_CALL(mock, PointerGetDxUnaccelerated)
        .WillOnce(Return(1.0));
    EXPECT_CALL(mock, PointerGetDyUnaccelerated)
        .WillOnce(Return(1.0));

    EXPECT_EQ(FingerprintEventHdr->AnalysePointEvent(&event), ERR_OK);

    FingerprintEventHdr->antiFalseTouchSwitch_ = false;
    FingerprintEventHdr->screenMissTouchFlag_ = false;
}

/**
 * @tc.name: FingerprintEventProcessorTest_AnalyseMsdpPointEvent_001
 * @tc.desc: Test AnalyseMsdpPointEvent with valid event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_AnalyseMsdpPointEvent_001, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event{};

    EXPECT_CALL(mock, GetHandFeature)
        .WillOnce(Return(100));

    EXPECT_EQ(FingerprintEventHdr->AnalyseMsdpPointEvent(&event), RET_OK);
}

/**
 * @tc.name: FingerprintEventProcessorTest_AnalyseMsdpPointEvent_002
 * @tc.desc: Test AnalyseMsdpPointEvent with different hand feature values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_AnalyseMsdpPointEvent_002, TestSize.Level1)
{
    NiceMock<LibinputInterfaceMock> mock;
    struct libinput_event event{};

    EXPECT_CALL(mock, GetHandFeature)
        .WillOnce(Return(0))
        .WillOnce(Return(-1))
        .WillOnce(Return(255));

    EXPECT_EQ(FingerprintEventHdr->AnalyseMsdpPointEvent(&event), RET_OK);
    EXPECT_EQ(FingerprintEventHdr->AnalyseMsdpPointEvent(&event), RET_OK);
    EXPECT_EQ(FingerprintEventHdr->AnalyseMsdpPointEvent(&event), RET_OK);
}

/**
 * @tc.name: FingerprintEventProcessorTest_CreateStatusConfigObserver_001
 * @tc.desc: Test CreateStatusConfigObserver with valid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CreateStatusConfigObserver_001, TestSize.Level1)
{
    SmartKeySwitch testItem;
    testItem.keyString = "test_key";
    testItem.valueString = "test_value";

    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->CreateStatusConfigObserver(testItem));
}

/**
 * @tc.name: FingerprintEventProcessorTest_CreateStatusConfigObserver_002
 * @tc.desc: Test CreateStatusConfigObserver with empty key string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CreateStatusConfigObserver_002, TestSize.Level1)
{
    SmartKeySwitch testItem;
    testItem.keyString = "";
    testItem.valueString = "default_value";

    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->CreateStatusConfigObserver(testItem));
}

/**
 * @tc.name: FingerprintEventProcessorTest_CreateStatusConfigObserver_003
 * @tc.desc: Test CreateStatusConfigObserver with special key string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_CreateStatusConfigObserver_003, TestSize.Level1)
{
    SmartKeySwitch testItem;
    testItem.keyString = "!@#$%^&*()";
    testItem.valueString = "special_value";

    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->CreateStatusConfigObserver(testItem));
}

/**
 * @tc.name: FingerprintEventProcessorTest_StartSmartKeyIfNeeded_001
 * @tc.desc: Test StartSmartKeyIfNeeded basic execution
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_StartSmartKeyIfNeeded_001, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->StartSmartKeyIfNeeded());
}

/**
 * @tc.name: FingerprintEventProcessorTest_StartSmartKey_001
 * @tc.desc: Test StartSmartKey with isShowDialog true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_StartSmartKey_001, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->StartSmartKey(true));
}

/**
 * @tc.name: FingerprintEventProcessorTest_StartSmartKey_002
 * @tc.desc: Test StartSmartKey with isShowDialog false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_StartSmartKey_002, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->StartSmartKey(false));
}

/**
 * @tc.name: FingerprintEventProcessorTest_ProcessSlideEvent_001
 * @tc.desc: Test ProcessSlideEvent when condition is met
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_ProcessSlideEvent_001, TestSize.Level1)
{
    FingerprintEventHdr->smartKeySwitch_.valueString = "1";
    FingerprintEventHdr->isStartedSmartKeyBySlide_ = false;
    
    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->ProcessSlideEvent());
    EXPECT_TRUE(FingerprintEventHdr->isStartedSmartKeyBySlide_);
}

/**
 * @tc.name: FingerprintEventProcessorTest_ProcessSlideEvent_002
 * @tc.desc: Test ProcessSlideEvent when valueString is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_ProcessSlideEvent_002, TestSize.Level1)
{
    FingerprintEventHdr->smartKeySwitch_.valueString = "";
    FingerprintEventHdr->isStartedSmartKeyBySlide_ = false;
    
    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->ProcessSlideEvent());
    EXPECT_TRUE(FingerprintEventHdr->isStartedSmartKeyBySlide_);
}

/**
 * @tc.name: FingerprintEventProcessorTest_ProcessSlideEvent_003
 * @tc.desc: Test ProcessSlideEvent when already started
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_ProcessSlideEvent_003, TestSize.Level1)
{
    FingerprintEventHdr->smartKeySwitch_.valueString = "1";
    FingerprintEventHdr->isStartedSmartKeyBySlide_ = true;
    
    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->ProcessSlideEvent());
    EXPECT_TRUE(FingerprintEventHdr->isStartedSmartKeyBySlide_); // Should remain true
}

/**
 * @tc.name: FingerprintEventProcessorTest_ProcessSlideEvent_004
 * @tc.desc: Test ProcessSlideEvent when condition is not met
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_ProcessSlideEvent_004, TestSize.Level1)
{
    FingerprintEventHdr->smartKeySwitch_.valueString = "0";
    FingerprintEventHdr->isStartedSmartKeyBySlide_ = false;
    
    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->ProcessSlideEvent());
    EXPECT_FALSE(FingerprintEventHdr->isStartedSmartKeyBySlide_);
}

/**
 * @tc.name: FingerprintEventProcessorTest_ProcessClickEvent_001
 * @tc.desc: Test ProcessClickEvent when condition is met
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_ProcessClickEvent_001, TestSize.Level1)
{
    FingerprintEventHdr->smartKeySwitch_.valueString = "1";
    
    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->ProcessClickEvent());
}

/**
 * @tc.name: FingerprintEventProcessorTest_ProcessClickEvent_002
 * @tc.desc: Test ProcessClickEvent when valueString is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_ProcessClickEvent_002, TestSize.Level1)
{
    FingerprintEventHdr->smartKeySwitch_.valueString = "";
    
    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->ProcessClickEvent());
}

/**
 * @tc.name: FingerprintEventProcessorTest_ProcessClickEvent_003
 * @tc.desc: Test ProcessClickEvent when condition is not met
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_ProcessClickEvent_003, TestSize.Level1)
{
    FingerprintEventHdr->smartKeySwitch_.valueString = "0";
    
    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->ProcessClickEvent());
}

/**
 * @tc.name: FingerprintEventProcessorTest_ReportResSched_001
 * @tc.desc: Test ReportResSched with RES_TYPE_CLICK_RECOGNIZE and TOUCH_EVENT_DOWN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_ReportResSched_001, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->ReportResSched(
        ResourceSchedule::ResType::RES_TYPE_CLICK_RECOGNIZE,
        ResourceSchedule::ResType::ClickEventType::TOUCH_EVENT_DOWN));
}

/**
 * @tc.name: FingerprintEventProcessorTest_ReportResSched_002
 * @tc.desc: Test ReportResSched with RES_TYPE_CLICK_RECOGNIZE and TOUCH_EVENT_UP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_ReportResSched_002, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->ReportResSched(
        ResourceSchedule::ResType::RES_TYPE_CLICK_RECOGNIZE,
        ResourceSchedule::ResType::ClickEventType::TOUCH_EVENT_UP));
}

/**
 * @tc.name: FingerprintEventProcessorTest_ReportResSched_003
 * @tc.desc: Test ReportResSched with different resType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_ReportResSched_003, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(FingerprintEventHdr->ReportResSched(0, 0));
}
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
} // namespace MMI
} // namespace OHOS