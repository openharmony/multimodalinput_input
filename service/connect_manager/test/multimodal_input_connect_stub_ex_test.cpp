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

#include "message_parcel_mock.h"
#include "multimodal_input_connect_def_parcel.h"
#include "multimodal_input_connect_stub.h"
#include "mmi_log.h"
#include "mmi_service.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MultimodalInputConnectStubTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;
class MMIServiceTest : public MultimodalInputConnectStub {
public:
    MMIServiceTest() = default;
    virtual ~MMIServiceTest() = default;

    bool IsRunning() const override
    {
        return (state_ == ServiceRunningState::STATE_RUNNING);
    }
    int32_t AllocSocketFd(const std::string &programName, const int32_t moduleType,
        int32_t &socketFd, int32_t &tokenType) override
    {
        if (programName == "fail") {
            return -1;
        }
        return 0;
    }
    int32_t AddInputEventFilter(sptr<IEventFilter> filter, int32_t filterId, int32_t priority,
        uint32_t deviceTags) override { return 0; }
    int32_t NotifyNapOnline() override { return 0; }
    int32_t RemoveInputEventObserver() override { return 0; }
    int32_t RemoveInputEventFilter(int32_t filterId) override { return 0; }
    int32_t SetMouseScrollRows(int32_t rows) override { return 0; }
    int32_t GetMouseScrollRows(int32_t &rows) override { return 0; }
    int32_t SetCustomCursor(int32_t pid, int32_t windowId, int32_t focusX, int32_t focusY, void* pixelMap) override
    {
        return 0;
    }
    int32_t SetMouseIcon(int32_t pid, int32_t windowId, void* pixelMap) override { return 0; }
    int32_t SetPointerSize(int32_t size) override { return 0; }
    int32_t SetNapStatus(int32_t pid, int32_t uid, std::string bundleName, int32_t napStatus) override { return 0; }
    int32_t GetPointerSize(int32_t &size) override { return 0; }
    int32_t SetMouseHotSpot(int32_t pid, int32_t windowId, int32_t hotSpotX, int32_t hotSpotY) override { return 0; }
    int32_t SetMousePrimaryButton(int32_t primaryButton) override { return 0; }
    int32_t GetMousePrimaryButton(int32_t &primaryButton) override { return 0; }
    int32_t SetHoverScrollState(bool state) override { return 0; }
    int32_t GetHoverScrollState(bool &state) override { return 0; }
    int32_t SetPointerVisible(bool visible, int32_t priority) override { return 0; }
    int32_t IsPointerVisible(bool &visible) override { return 0; }
    int32_t MarkProcessed(int32_t eventType, int32_t eventId) override { return 0; }
    int32_t SetPointerColor(int32_t color) override { return 0; }
    int32_t GetPointerColor(int32_t &color) override { return 0; }
    int32_t EnableCombineKey(bool enable) override { return 0; }
    int32_t SetPointerSpeed(int32_t speed) override { return 0; }
    int32_t GetPointerSpeed(int32_t &speed) override { return 0; }
    int32_t SetPointerStyle(int32_t windowId, PointerStyle pointerStyle, bool isUiExtension = false) override
    {
        return 0;
    }
    int32_t GetPointerStyle(int32_t windowId, PointerStyle &pointerStyle, bool isUiExtension = false) override
    {
        return 0;
    }
    int32_t SupportKeys(int32_t deviceId, std::vector<int32_t> &keys, std::vector<bool> &keystroke) override
    {
        return 0;
    }
    int32_t GetDeviceIds(std::vector<int32_t> &ids) override { return 0; }
    int32_t GetDevice(int32_t deviceId, std::shared_ptr<InputDevice> &inputDevice) override { return 0; }
    int32_t RegisterDevListener() override { return 0; }
    int32_t UnregisterDevListener() override { return 0; }
    int32_t GetKeyboardType(int32_t deviceId, int32_t &keyboardType) override { return 0; }
    int32_t SetKeyboardRepeatDelay(int32_t delay) override { return 0; }
    int32_t SetKeyboardRepeatRate(int32_t rate) override { return 0; }
    int32_t GetKeyboardRepeatDelay(int32_t &delay) override { return 0; }
    int32_t GetKeyboardRepeatRate(int32_t &rate) override { return 0; }
    int32_t AddInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags) override { return 0; }
    int32_t RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags) override { return 0; }
    int32_t MarkEventConsumed(int32_t eventId) override { return 0; }
    int32_t MoveMouseEvent(int32_t offsetX, int32_t offsetY) override { return 0; }
    int32_t InjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent, bool isNativeInject) override { return 0; }
    int32_t SubscribeKeyEvent(int32_t subscribeId, const std::shared_ptr<KeyOption> option) override { return 0; }
    int32_t UnsubscribeKeyEvent(int32_t subscribeId) override { return 0; }
    int32_t SubscribeSwitchEvent(int32_t subscribeId, int32_t switchType) override { return 0; }
    int32_t UnsubscribeSwitchEvent(int32_t subscribeId) override { return 0; }
    int32_t InjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent, bool isNativeInject) override
    {
        return 0;
    }
    int32_t SetAnrObserver() override { return 0; }
    int32_t GetDisplayBindInfo(DisplayBindInfos &infos) override { return 0; }
    int32_t GetAllMmiSubscribedEvents(std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> &datas) override
    {
        return 0;
    }
    int32_t SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg) override { return 0; }
    int32_t GetFunctionKeyState(int32_t funckey, bool &state) override { return 0; }
    int32_t SetFunctionKeyState(int32_t funcKey, bool enable) override { return 0; }
    int32_t SetPointerLocation(int32_t x, int32_t y) override { return 0; }
    int32_t ClearWindowPointerStyle(int32_t pid, int32_t windowId) override { return 0; }
    int32_t SetMouseCaptureMode(int32_t windowId, bool isCaptureMode) override { return 0; }
    int32_t GetWindowPid(int32_t windowId) override { return 0; }
    int32_t AppendExtraData(const ExtraData& extraData) override { return 0; }
    int32_t EnableInputDevice(bool enable) override { return 0; }
    int32_t SetKeyDownDuration(const std::string &businessId, int32_t delay) override { return 0; }
    int32_t SetTouchpadScrollSwitch(bool switchFlag) override { return 0; }
    int32_t GetTouchpadScrollSwitch(bool &switchFlag) override { return 0; }
    int32_t SetTouchpadScrollDirection(bool state) override { return 0; }
    int32_t GetTouchpadScrollDirection(bool &state) override { return 0; }
    int32_t SetTouchpadTapSwitch(bool switchFlag) override { return 0; }
    int32_t GetTouchpadTapSwitch(bool &switchFlag) override { return 0; }
    int32_t SetTouchpadPointerSpeed(int32_t speed) override { return 0; }
    int32_t GetTouchpadPointerSpeed(int32_t &speed) override { return 0; }
    int32_t SetTouchpadPinchSwitch(bool switchFlag) override { return 0; }
    int32_t GetTouchpadPinchSwitch(bool &switchFlag) override { return 0; }
    int32_t SetTouchpadSwipeSwitch(bool switchFlag) override { return 0; }
    int32_t GetTouchpadSwipeSwitch(bool &switchFlag) override { return 0; }
    int32_t SetTouchpadRightClickType(int32_t type) override { return 0; }
    int32_t GetTouchpadRightClickType(int32_t &type) override { return 0; }
    int32_t SetTouchpadRotateSwitch(bool rotateSwitch) override { return 0; }
    int32_t GetTouchpadRotateSwitch(bool &rotateSwitch) override { return 0; }
    int32_t SetShieldStatus(int32_t shieldMode, bool isShield) override { return 0; }
    int32_t GetShieldStatus(int32_t shieldMode, bool &isShield) override { return 0; }
    int32_t GetKeyState(std::vector<int32_t> &pressedKeys, std::map<int32_t, int32_t> &specialKeysState) override
    {
        return 0;
    }
    int32_t Authorize(bool isAuthorize) override { return 0; }
    int32_t CancelInjection() override { return 0; }
    int32_t HasIrEmitter(bool &hasIrEmitter) override { return 0; }
    int32_t GetInfraredFrequencies(std::vector<InfraredFrequency>& requencys) override { return 0; }
    int32_t TransmitInfrared(int64_t number, std::vector<int64_t>& pattern) override { return 0; }
    int32_t SetPixelMapData(int32_t infoId, void* pixelMap) override { return 0; }
    int32_t SetCurrentUser(int32_t userId) override { return 0; }
    int32_t EnableHardwareCursorStats(bool enable) override { return 0; }
    int32_t GetHardwareCursorStats(uint32_t &frameCount, uint32_t &vsyncCount) override { return 0; }

    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
};
} // namespace

class MultimodalInputConnectStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase();
    void SetUp() {}
    void TearDown() {}

    static inline std::shared_ptr<MessageParcelMock> messageParcelMock_ = nullptr;
};

void MultimodalInputConnectStubTest::SetUpTestCase(void)
{
    messageParcelMock_ = std::make_shared<MessageParcelMock>();
    MessageParcelMock::messageParcel = messageParcelMock_;
}
void MultimodalInputConnectStubTest::TearDownTestCase()
{
    MessageParcelMock::messageParcel = nullptr;
    messageParcelMock_ = nullptr;
}

/**
 * @tc.name: OnRemoteRequest_012
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInterfaceToken()).WillOnce(Return(IMultimodalInputConnect::GetDescriptor()));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TP_ROTATE_SWITCH);
    EXPECT_NO_FATAL_FAILURE(stub->OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: OnRemoteRequest_013
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInterfaceToken()).WillOnce(Return(IMultimodalInputConnect::GetDescriptor()));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TP_ROTATE_SWITCH);
    EXPECT_NO_FATAL_FAILURE(stub->OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: OnRemoteRequest_014
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInterfaceToken()).WillOnce(Return(IMultimodalInputConnect::GetDescriptor()));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NATIVE_INFRARED_OWN);
    EXPECT_NO_FATAL_FAILURE(stub->OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: OnRemoteRequest_015
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_015, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInterfaceToken()).WillOnce(Return(IMultimodalInputConnect::GetDescriptor()));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NATIVE_INFRARED_FREQUENCY);
    EXPECT_NO_FATAL_FAILURE(stub->OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: OnRemoteRequest_016
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_016, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInterfaceToken()).WillOnce(Return(IMultimodalInputConnect::GetDescriptor()));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NATIVE_CANCEL_TRANSMIT);
    EXPECT_NO_FATAL_FAILURE(stub->OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: OnRemoteRequest_017
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_017, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInterfaceToken()).WillOnce(Return(IMultimodalInputConnect::GetDescriptor()));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_CURRENT_USERID);
    EXPECT_NO_FATAL_FAILURE(stub->OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: OnRemoteRequest_018
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_018, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInterfaceToken()).WillOnce(Return(IMultimodalInputConnect::GetDescriptor()));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIService> service = std::static_pointer_cast<MMIService>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = 1000;
    EXPECT_NO_FATAL_FAILURE(stub->OnRemoteRequest(code, data, reply, option));
}
} // namespace MMI
} // namespace OHOS