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
#include "mmi_log.h"
#include "mmi_service.h"
#include "multimodal_input_connect_def_parcel.h"
#include "multimodal_input_connect_stub.h"

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

    MOCK_METHOD4(SendRequest, int(uint32_t, MessageParcel &, MessageParcel &, MessageOption &));

    bool IsRunning() const override
    {
        return (state_ == ServiceRunningState::STATE_RUNNING);
    }
    int32_t AllocSocketFd(const std::string &programName, const int32_t moduleType,
        int32_t &socketFd, int32_t &tokenType) override
    {
        socketFd = moduleType;
        if (programName == "fail") {
            return -1;
        }
        return 0;
    }
    int32_t AddInputEventFilter(sptr<IEventFilter> filter, int32_t filterId, int32_t priority,
        uint32_t deviceTags) override { return filterId; }
    int32_t NotifyNapOnline() override { return 0; }
    int32_t RemoveInputEventObserver() override { return 0; }
    int32_t RemoveInputEventFilter(int32_t filterId) override { return filterId; }
    int32_t SetMouseScrollRows(int32_t rows) override
    {
        rows_ = rows;
        return rows_;
    }
    int32_t GetMouseScrollRows(int32_t &rows) override { return rows_; }
    int32_t SetCustomCursor(int32_t pid, int32_t windowId, int32_t focusX, int32_t focusY, void* pixelMap) override
    {
        return 0;
    }
    int32_t SetMouseIcon(int32_t pid, int32_t windowId, void* pixelMap) override { return 0; }
    int32_t SetPointerSize(int32_t size) override
    {
        size_ = size;
        return size_;
    }
    int32_t SetNapStatus(int32_t pid, int32_t uid, std::string bundleName, int32_t napStatus) override { return pid; }
    int32_t GetPointerSize(int32_t &size) override { return size_; }
    int32_t SetMouseHotSpot(int32_t pid, int32_t windowId, int32_t hotSpotX, int32_t hotSpotY) override { return pid; }
    int32_t SetMousePrimaryButton(int32_t primaryButton) override
    {
        primaryButton_ = primaryButton;
        return primaryButton_;
    }
    int32_t GetMousePrimaryButton(int32_t &primaryButton) override { return primaryButton_; }
    int32_t SetHoverScrollState(bool state) override
    {
        scrollState_ = state;
        return static_cast<int32_t>(scrollState_);
    }
    int32_t GetHoverScrollState(bool &state) override { return static_cast<int32_t>(scrollState_); }
    int32_t SetPointerVisible(bool visible, int32_t priority) override
    {
        visible_ = visible;
        return static_cast<int32_t>(visible_);
    }
    int32_t IsPointerVisible(bool &visible) override { return static_cast<int32_t>(visible_); }
    int32_t MarkProcessed(int32_t eventType, int32_t eventId) override { return eventType; }
    int32_t SetPointerColor(int32_t color) override
    {
        color_ = color;
        return color_;
    }
    int32_t GetPointerColor(int32_t &color) override { return color_; }
    int32_t EnableCombineKey(bool enable) override { return static_cast<int32_t>(enable); }
    int32_t SetPointerSpeed(int32_t speed) override
    {
        speed_ = speed;
        return speed_;
    }
    int32_t GetPointerSpeed(int32_t &speed) override { return speed_; }
    int32_t SetPointerStyle(int32_t windowId, PointerStyle pointerStyle, bool isUiExtension = false) override
    {
        return windowId;
    }
    int32_t GetPointerStyle(int32_t windowId, PointerStyle &pointerStyle, bool isUiExtension = false) override
    {
        return windowId;
    }
    int32_t SupportKeys(int32_t deviceId, std::vector<int32_t> &keys, std::vector<bool> &keystroke) override
    {
        return deviceId;
    }
    int32_t GetDeviceIds(std::vector<int32_t> &ids) override { return retIds_; }
    int32_t GetDevice(int32_t deviceId, std::shared_ptr<InputDevice> &inputDevice) override { return deviceId; }
    int32_t RegisterDevListener() override { return 0; }
    int32_t UnregisterDevListener() override { return 0; }
    int32_t GetKeyboardType(int32_t deviceId, int32_t &keyboardType) override { return deviceId; }
    int32_t SetKeyboardRepeatDelay(int32_t delay) override { return 0; }
    int32_t SetKeyboardRepeatRate(int32_t rate) override { return 0; }
    int32_t GetKeyboardRepeatDelay(int32_t &delay) override { return 0; }
    int32_t GetKeyboardRepeatRate(int32_t &rate) override { return 0; }
    int32_t AddInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags) override { return priority; }
    int32_t RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags) override { return priority; }
    int32_t MarkEventConsumed(int32_t eventId) override { return eventId; }
    int32_t MoveMouseEvent(int32_t offsetX, int32_t offsetY) override { return offsetX; }
    int32_t InjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent, bool isNativeInject) override
    {
        return static_cast<int32_t>(isNativeInject);
    }
    int32_t SubscribeKeyEvent(int32_t subscribeId, const std::shared_ptr<KeyOption> option) override
    {
        return subscribeId;
    }
    int32_t UnsubscribeKeyEvent(int32_t subscribeId) override { return subscribeId; }
    int32_t SubscribeSwitchEvent(int32_t subscribeId, int32_t switchType) override { return subscribeId; }
    int32_t UnsubscribeSwitchEvent(int32_t subscribeId) override { return subscribeId; }
    int32_t InjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent, bool isNativeInject) override
    {
        return static_cast<int32_t>(isNativeInject);
    }
    int32_t SetAnrObserver() override { return retObserver_; }
    int32_t GetDisplayBindInfo(DisplayBindInfos &infos) override { return retBindInfo_; }
    int32_t GetAllMmiSubscribedEvents(std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> &datas) override
    {
        return retMmiSubscribedEvents_;
    }
    int32_t SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg) override { return deviceId; }
    int32_t GetFunctionKeyState(int32_t funckey, bool &state) override { return funckey; }
    int32_t SetFunctionKeyState(int32_t funcKey, bool enable) override { return funcKey; }
    int32_t SetPointerLocation(int32_t x, int32_t y) override { return x; }
    int32_t ClearWindowPointerStyle(int32_t pid, int32_t windowId) override { return pid; }
    int32_t SetMouseCaptureMode(int32_t windowId, bool isCaptureMode) override { return windowId; }
    int32_t GetWindowPid(int32_t windowId) override { return windowId; }
    int32_t AppendExtraData(const ExtraData& extraData) override { return extraData.sourceType; }
    int32_t EnableInputDevice(bool enable) override { return static_cast<int32_t>(enable); }
    int32_t SetKeyDownDuration(const std::string &businessId, int32_t delay) override { return delay; }
    int32_t SetTouchpadScrollSwitch(bool switchFlag) override
    {
        switchFlag_ = switchFlag;
        return static_cast<int32_t>(switchFlag_);
    }
    int32_t GetTouchpadScrollSwitch(bool &switchFlag) override { return static_cast<int32_t>(switchFlag_); }
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
    int32_t SetCurrentUser(int32_t userId) override { return userId; }
    int32_t AddVirtualInputDevice(std::shared_ptr<InputDevice> device, int32_t &deviceId) { return 0; }
    int32_t RemoveVirtualInputDevice(int32_t deviceId) { return 0; }
    int32_t EnableHardwareCursorStats(bool enable) override { return 0; }
    int32_t GetHardwareCursorStats(uint32_t &frameCount, uint32_t &vsyncCount) override { return 0; }

    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t rows_ = 0;
    int32_t size_ = 0;
    int32_t primaryButton_ = 0;
    bool scrollState_ = false;
    bool visible_ = false;
    int32_t color_ = 0;
    int32_t speed_ = 0;
    int32_t retIds_ = 0;
    int32_t retObserver_ = 0;
    int32_t retBindInfo_ = 0;
    int32_t retMmiSubscribedEvents_ = 0;
    bool switchFlag_ = false;
};
class RemoteObjectTest : public IRemoteObject {
public:
    explicit RemoteObjectTest(std::u16string descriptor) : IRemoteObject(descriptor) {}
    ~RemoteObjectTest() {}

    int32_t GetObjectRefCount() { return 0; }
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) { return 0; }
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; }
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; }
    int Dump(int fd, const std::vector<std::u16string> &args) { return 0; }
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
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
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
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
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
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
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
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
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = 1000;
    EXPECT_NO_FATAL_FAILURE(stub->OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: OnRemoteRequest_019
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_019, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInterfaceToken()).WillOnce(Return(u"fail"));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = 1000;
    EXPECT_NO_FATAL_FAILURE(stub->OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: OnRemoteRequest_020
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_020, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInterfaceToken()).WillOnce(Return(IMultimodalInputConnect::GetDescriptor()));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ADD_VIRTUAL_INPUT_DEVICE);
    EXPECT_NO_FATAL_FAILURE(stub->OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: OnRemoteRequest_021
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_021, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInterfaceToken()).WillOnce(Return(IMultimodalInputConnect::GetDescriptor()));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::REMOVE_VIRTUAL_INPUT_DEVICE);
    EXPECT_NO_FATAL_FAILURE(stub->OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: StubHandleAllocSocketFd_003
 * @tc.desc: Test the function StubHandleAllocSocketFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubHandleAllocSocketFd_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_NOT_START;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubHandleAllocSocketFd(data, reply));
}

/**
 * @tc.name: StubHandleAllocSocketFd_004
 * @tc.desc: Test the function StubHandleAllocSocketFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubHandleAllocSocketFd_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32()).WillOnce(Return(1));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadString()).WillOnce(Return("fail"));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubHandleAllocSocketFd(data, reply));
}

/**
 * @tc.name: StubHandleAllocSocketFd_005
 * @tc.desc: Test the function StubHandleAllocSocketFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubHandleAllocSocketFd_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t sockFds[2] = { -1 };
    auto ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sockFds);
    ASSERT_TRUE(ret == 0);
    EXPECT_CALL(*messageParcelMock_, ReadInt32()).WillOnce(Return(1));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(sockFds[1]), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadString()).WillOnce(Return("fail"));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubHandleAllocSocketFd(data, reply));
    close(sockFds[0]);
}

/**
 * @tc.name: StubHandleAllocSocketFd_006
 * @tc.desc: Test the function StubHandleAllocSocketFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubHandleAllocSocketFd_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32()).WillOnce(Return(1));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadString()).WillOnce(Return("success"));
    EXPECT_CALL(*messageParcelMock_, WriteFileDescriptor(_)).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubHandleAllocSocketFd(data, reply));
}

/**
 * @tc.name: StubHandleAllocSocketFd_007
 * @tc.desc: Test the function StubHandleAllocSocketFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubHandleAllocSocketFd_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t sockFds[2] = { -1 };
    auto ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sockFds);
    ASSERT_TRUE(ret == 0);
    EXPECT_CALL(*messageParcelMock_, ReadInt32()).WillOnce(Return(1));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(sockFds[1]), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadString()).WillOnce(Return("success"));
    EXPECT_CALL(*messageParcelMock_, WriteFileDescriptor(_)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, WriteInt32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubHandleAllocSocketFd(data, reply));
    close(sockFds[0]);
}

/**
 * @tc.name: StubAddInputEventFilter_001
 * @tc.desc: Test the function StubAddInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubAddInputEventFilter_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    EXPECT_CALL(*messageParcelMock_, ReadRemoteObject()).WillOnce(Return(remote));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubAddInputEventFilter(data, reply));
}

/**
 * @tc.name: StubAddInputEventFilter_002
 * @tc.desc: Test the function StubAddInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubAddInputEventFilter_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    EXPECT_CALL(*messageParcelMock_, ReadRemoteObject()).WillOnce(Return(remote));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubAddInputEventFilter(data, reply));
}

/**
 * @tc.name: StubAddInputEventFilter_003
 * @tc.desc: Test the function StubAddInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubAddInputEventFilter_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubAddInputEventFilter(data, reply));
}

/**
 * @tc.name: StubRemoveInputEventFilter_001
 * @tc.desc: Test the function StubRemoveInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubRemoveInputEventFilter_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubRemoveInputEventFilter(data, reply));
}

/**
 * @tc.name: StubRemoveInputEventFilter_002
 * @tc.desc: Test the function StubRemoveInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubRemoveInputEventFilter_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubRemoveInputEventFilter(data, reply));
}

/**
 * @tc.name: StubRemoveInputEventFilter_003
 * @tc.desc: Test the function StubRemoveInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubRemoveInputEventFilter_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubRemoveInputEventFilter(data, reply));
}

/**
 * @tc.name: StubSetMouseScrollRows_001
 * @tc.desc: Test the function StubSetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseScrollRows_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMouseScrollRows(data, reply));
}

/**
 * @tc.name: StubSetMouseScrollRows_002
 * @tc.desc: Test the function StubSetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseScrollRows_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMouseScrollRows(data, reply));
}

/**
 * @tc.name: StubSetMouseScrollRows_003
 * @tc.desc: Test the function StubSetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseScrollRows_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMouseScrollRows(data, reply));
}

/**
 * @tc.name: StubSetMouseScrollRows_004
 * @tc.desc: Test the function StubSetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseScrollRows_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMouseScrollRows(data, reply));
}

/**
 * @tc.name: StubSetCustomCursor_001
 * @tc.desc: Test the function StubSetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetCustomCursor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetCustomCursor(data, reply));
}

/**
 * @tc.name: StubSetCustomCursor_002
 * @tc.desc: Test the function StubSetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetCustomCursor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetCustomCursor(data, reply));
}

/**
 * @tc.name: StubSetCustomCursor_003
 * @tc.desc: Test the function StubSetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetCustomCursor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32())
        .WillOnce(Return(4))
        .WillOnce(Return(3))
        .WillOnce(Return(5))
        .WillOnce(Return(2))
        .WillOnce(Return(0))
        .WillOnce(Return(0))
        .WillOnce(Return(2))
        .WillOnce(Return(-1))
        .WillOnce(Return(12))
        .WillOnce(Return(36));
    EXPECT_CALL(*messageParcelMock_, ReadBool())
        .WillOnce(Return(false))
        .WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetCustomCursor(data, reply));
}

/**
 * @tc.name: StubSetMouseIcon_001
 * @tc.desc: Test the function StubSetMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseIcon_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMouseIcon(data, reply));
}

/**
 * @tc.name: StubSetMouseIcon_002
 * @tc.desc: Test the function StubSetMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseIcon_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32())
        .WillOnce(Return(4))
        .WillOnce(Return(3))
        .WillOnce(Return(5))
        .WillOnce(Return(2))
        .WillOnce(Return(0))
        .WillOnce(Return(0))
        .WillOnce(Return(2))
        .WillOnce(Return(-1))
        .WillOnce(Return(12))
        .WillOnce(Return(36));
    EXPECT_CALL(*messageParcelMock_, ReadBool())
        .WillOnce(Return(false))
        .WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMouseIcon(data, reply));
}

/**
 * @tc.name: StubSetMouseHotSpot_001
 * @tc.desc: Test the function StubSetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseHotSpot_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMouseHotSpot(data, reply));
}

/**
 * @tc.name: StubSetMouseHotSpot_002
 * @tc.desc: Test the function StubSetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseHotSpot_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMouseHotSpot(data, reply));
}

/**
 * @tc.name: StubSetMouseHotSpot_003
 * @tc.desc: Test the function StubSetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseHotSpot_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMouseHotSpot(data, reply));
}

/**
 * @tc.name: StubSetMouseHotSpot_004
 * @tc.desc: Test the function StubSetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseHotSpot_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMouseHotSpot(data, reply));
}

/**
 * @tc.name: StubGetMouseScrollRows_001
 * @tc.desc: Test the function StubGetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetMouseScrollRows_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetMouseScrollRows(data, reply));
}

/**
 * @tc.name: StubGetMouseScrollRows_002
 * @tc.desc: Test the function StubGetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetMouseScrollRows_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetMouseScrollRows(data, reply));
}

/**
 * @tc.name: StubGetMouseScrollRows_003
 * @tc.desc: Test the function StubGetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetMouseScrollRows_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMouseScrollRows(data, reply));
    EXPECT_NO_FATAL_FAILURE(stub->StubGetMouseScrollRows(data, reply));
}

/**
 * @tc.name: StubGetMouseScrollRows_004
 * @tc.desc: Test the function StubGetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetMouseScrollRows_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    EXPECT_CALL(*messageParcelMock_, WriteInt32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMouseScrollRows(data, reply));
    EXPECT_NO_FATAL_FAILURE(stub->StubGetMouseScrollRows(data, reply));
}

/**
 * @tc.name: StubSetPointerSize_001
 * @tc.desc: Test the function StubSetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerSize_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerSize(data, reply));
}

/**
 * @tc.name: StubSetPointerSize_002
 * @tc.desc: Test the function StubSetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerSize_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerSize(data, reply));
}

/**
 * @tc.name: StubSetPointerSize_003
 * @tc.desc: Test the function StubSetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerSize_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerSize(data, reply));
}

/**
 * @tc.name: StubSetPointerSize_004
 * @tc.desc: Test the function StubSetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerSize_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerSize(data, reply));
}

/**
 * @tc.name: StubSetNapStatus_001
 * @tc.desc: Test the function StubSetNapStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetNapStatus_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetNapStatus(data, reply));
}

/**
 * @tc.name: StubSetNapStatus_002
 * @tc.desc: Test the function StubSetNapStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetNapStatus_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadString(_))
        .WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetNapStatus(data, reply));
}

/**
 * @tc.name: StubSetNapStatus_003
 * @tc.desc: Test the function StubSetNapStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetNapStatus_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadString(_))
        .WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetNapStatus(data, reply));
}

/**
 * @tc.name: StubGetPointerSize_001
 * @tc.desc: Test the function StubGetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetPointerSize_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetPointerSize(data, reply));
}

/**
 * @tc.name: StubGetPointerSize_002
 * @tc.desc: Test the function StubGetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetPointerSize_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetPointerSize(data, reply));
}

/**
 * @tc.name: StubGetPointerSize_003
 * @tc.desc: Test the function StubGetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetPointerSize_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerSize(data, reply));
    EXPECT_NO_FATAL_FAILURE(stub->StubGetPointerSize(data, reply));
}

/**
 * @tc.name: StubGetPointerSize_004
 * @tc.desc: Test the function StubGetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetPointerSize_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    EXPECT_CALL(*messageParcelMock_, WriteInt32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerSize(data, reply));
    EXPECT_NO_FATAL_FAILURE(stub->StubGetPointerSize(data, reply));
}

/**
 * @tc.name: StubSetMousePrimaryButton_001
 * @tc.desc: Test the function StubSetMousePrimaryButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMousePrimaryButton_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMousePrimaryButton(data, reply));
}

/**
 * @tc.name: StubSetMousePrimaryButton_002
 * @tc.desc: Test the function StubSetMousePrimaryButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMousePrimaryButton_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMousePrimaryButton(data, reply));
}

/**
 * @tc.name: StubSetMousePrimaryButton_003
 * @tc.desc: Test the function StubSetMousePrimaryButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMousePrimaryButton_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMousePrimaryButton(data, reply));
}

/**
 * @tc.name: StubGetMousePrimaryButton_001
 * @tc.desc: Test the function StubGetMousePrimaryButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetMousePrimaryButton_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetMousePrimaryButton(data, reply));
}

/**
 * @tc.name: StubGetMousePrimaryButton_002
 * @tc.desc: Test the function StubGetMousePrimaryButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetMousePrimaryButton_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMousePrimaryButton(data, reply));
    EXPECT_NO_FATAL_FAILURE(stub->StubGetMousePrimaryButton(data, reply));
}

/**
 * @tc.name: StubGetMousePrimaryButton_003
 * @tc.desc: Test the function StubGetMousePrimaryButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetMousePrimaryButton_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    EXPECT_CALL(*messageParcelMock_, WriteInt32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMousePrimaryButton(data, reply));
    EXPECT_NO_FATAL_FAILURE(stub->StubGetMousePrimaryButton(data, reply));
}

/**
 * @tc.name: StubSetHoverScrollState_001
 * @tc.desc: Test the function StubSetHoverScrollState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetHoverScrollState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetHoverScrollState(data, reply));
}

/**
 * @tc.name: StubSetHoverScrollState_002
 * @tc.desc: Test the function StubSetHoverScrollState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetHoverScrollState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetHoverScrollState(data, reply));
}

/**
 * @tc.name: StubSetHoverScrollState_003
 * @tc.desc: Test the function StubSetHoverScrollState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetHoverScrollState_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(false), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetHoverScrollState(data, reply));
}

/**
 * @tc.name: StubGetHoverScrollState_001
 * @tc.desc: Test the function StubGetHoverScrollState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetHoverScrollState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetHoverScrollState(data, reply));
}

/**
 * @tc.name: StubGetHoverScrollState_002
 * @tc.desc: Test the function StubGetHoverScrollState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetHoverScrollState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetHoverScrollState(data, reply));
    EXPECT_NO_FATAL_FAILURE(stub->StubGetHoverScrollState(data, reply));
}

/**
 * @tc.name: StubGetHoverScrollState_003
 * @tc.desc: Test the function StubGetHoverScrollState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetHoverScrollState_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(false), Return(true)));
    EXPECT_CALL(*messageParcelMock_, WriteBool(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetHoverScrollState(data, reply));
    EXPECT_NO_FATAL_FAILURE(stub->StubGetHoverScrollState(data, reply));
}

/**
 * @tc.name: StubSetPointerVisible_001
 * @tc.desc: Test the function StubSetPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerVisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerVisible(data, reply));
}

/**
 * @tc.name: StubSetPointerVisible_002
 * @tc.desc: Test the function StubSetPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerVisible_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(false), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerVisible(data, reply));
}

/**
 * @tc.name: StubIsPointerVisible_001
 * @tc.desc: Test the function StubIsPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubIsPointerVisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerVisible(data, reply));
    EXPECT_NO_FATAL_FAILURE(stub->StubIsPointerVisible(data, reply));
}

/**
 * @tc.name: StubIsPointerVisible_002
 * @tc.desc: Test the function StubIsPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubIsPointerVisible_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(false), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, WriteBool(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerVisible(data, reply));
    EXPECT_NO_FATAL_FAILURE(stub->StubIsPointerVisible(data, reply));
}

/**
 * @tc.name: StubMarkProcessed_001
 * @tc.desc: Test the function StubMarkProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubMarkProcessed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubMarkProcessed(data, reply));
}

/**
 * @tc.name: StubMarkProcessed_002
 * @tc.desc: Test the function StubMarkProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubMarkProcessed_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubMarkProcessed(data, reply));
}

/**
 * @tc.name: StubMarkProcessed_003
 * @tc.desc: Test the function StubMarkProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubMarkProcessed_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubMarkProcessed(data, reply));
}

/**
 * @tc.name: StubSetPointerColor_001
 * @tc.desc: Test the function StubSetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerColor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerColor(data, reply));
}

/**
 * @tc.name: StubSetPointerColor_002
 * @tc.desc: Test the function StubSetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerColor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerColor(data, reply));
}

/**
 * @tc.name: StubSetPointerColor_003
 * @tc.desc: Test the function StubSetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerColor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerColor(data, reply));
}

/**
 * @tc.name: StubSetPointerColor_004
 * @tc.desc: Test the function StubSetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerColor_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerColor(data, reply));
}

/**
 * @tc.name: StubGetPointerColor_001
 * @tc.desc: Test the function StubGetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetPointerColor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetPointerColor(data, reply));
}

/**
 * @tc.name: StubGetPointerColor_002
 * @tc.desc: Test the function StubGetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetPointerColor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetPointerColor(data, reply));
}

/**
 * @tc.name: StubGetPointerColor_003
 * @tc.desc: Test the function StubGetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetPointerColor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerColor(data, reply));
    EXPECT_NO_FATAL_FAILURE(stub->StubGetPointerColor(data, reply));
}

/**
 * @tc.name: StubGetPointerColor_004
 * @tc.desc: Test the function StubGetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetPointerColor_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    EXPECT_CALL(*messageParcelMock_, WriteInt32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerColor(data, reply));
    EXPECT_NO_FATAL_FAILURE(stub->StubGetPointerColor(data, reply));
}

/**
 * @tc.name: StubSetPointerSpeed_001
 * @tc.desc: Test the function StubSetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerSpeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerSpeed(data, reply));
}

/**
 * @tc.name: StubSetPointerSpeed_002
 * @tc.desc: Test the function StubSetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerSpeed_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerSpeed(data, reply));
}

/**
 * @tc.name: StubSetPointerSpeed_003
 * @tc.desc: Test the function StubSetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerSpeed_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerSpeed(data, reply));
}

/**
 * @tc.name: StubGetPointerSpeed_001
 * @tc.desc: Test the function StubGetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetPointerSpeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetPointerSpeed(data, reply));
}

/**
 * @tc.name: StubGetPointerSpeed_002
 * @tc.desc: Test the function StubGetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetPointerSpeed_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerSpeed(data, reply));
    EXPECT_NO_FATAL_FAILURE(stub->StubGetPointerSpeed(data, reply));
}

/**
 * @tc.name: StubGetPointerSpeed_003
 * @tc.desc: Test the function StubGetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetPointerSpeed_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    EXPECT_CALL(*messageParcelMock_, WriteInt32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerSpeed(data, reply));
    EXPECT_NO_FATAL_FAILURE(stub->StubGetPointerSpeed(data, reply));
}

/**
 * @tc.name: StubNotifyNapOnline_001
 * @tc.desc: Test the function StubNotifyNapOnline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubNotifyNapOnline_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubNotifyNapOnline(data, reply));
}

/**
 * @tc.name: StubRemoveInputEventObserver_001
 * @tc.desc: Test the function StubRemoveInputEventObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubRemoveInputEventObserver_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubRemoveInputEventObserver(data, reply));
}

/**
 * @tc.name: StubSetPointerStyle_001
 * @tc.desc: Test the function StubSetPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerStyle(data, reply));
}

/**
 * @tc.name: StubSetPointerStyle_002
 * @tc.desc: Test the function StubSetPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerStyle_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerStyle(data, reply));
}

/**
 * @tc.name: StubClearWindowPointerStyle_001
 * @tc.desc: Test the function StubClearWindowPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubClearWindowPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubClearWindowPointerStyle(data, reply));
}

/**
 * @tc.name: StubClearWindowPointerStyle_002
 * @tc.desc: Test the function StubClearWindowPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubClearWindowPointerStyle_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubClearWindowPointerStyle(data, reply));
}

/**
 * @tc.name: StubGetPointerStyle_001
 * @tc.desc: Test the function StubGetPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetPointerStyle(data, reply));
}

/**
 * @tc.name: StubGetPointerStyle_002
 * @tc.desc: Test the function StubGetPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetPointerStyle_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, WriteInt32(_))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetPointerStyle(data, reply));
}

/**
 * @tc.name: StubSupportKeys_001
 * @tc.desc: Test the function StubSupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSupportKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSupportKeys(data, reply));
}

/**
 * @tc.name: StubSupportKeys_002
 * @tc.desc: Test the function StubSupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSupportKeys_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>((ExtraData::MAX_BUFFER_SIZE + 1)), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSupportKeys(data, reply));
}

/**
 * @tc.name: StubSupportKeys_003
 * @tc.desc: Test the function StubSupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSupportKeys_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSupportKeys(data, reply));
}

/**
 * @tc.name: StubSupportKeys_004
 * @tc.desc: Test the function StubSupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSupportKeys_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)));
    EXPECT_CALL(*messageParcelMock_, WriteBoolVector(_)) .WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSupportKeys(data, reply));
}

/**
 * @tc.name: StubSupportKeys_005
 * @tc.desc: Test the function StubSupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSupportKeys_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)));
    EXPECT_CALL(*messageParcelMock_, WriteBoolVector(_)) .WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSupportKeys(data, reply));
}

/**
 * @tc.name: StubGetDeviceIds_001
 * @tc.desc: Test the function StubGetDeviceIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetDeviceIds_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->retIds_ = -1;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetDeviceIds(data, reply));
}

/**
 * @tc.name: StubGetDeviceIds_002
 * @tc.desc: Test the function StubGetDeviceIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetDeviceIds_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, WriteInt32Vector(_)) .WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->retIds_ = 0;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetDeviceIds(data, reply));
}

/**
 * @tc.name: StubGetDeviceIds_003
 * @tc.desc: Test the function StubGetDeviceIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetDeviceIds_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, WriteInt32Vector(_)) .WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->retIds_ = 0;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetDeviceIds(data, reply));
}

/**
 * @tc.name: StubGetDevice_001
 * @tc.desc: Test the function StubGetDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetDevice(data, reply));
}

/**
 * @tc.name: StubGetDevice_002
 * @tc.desc: Test the function StubGetDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    EXPECT_CALL(*messageParcelMock_, WriteInt32(_))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, WriteString(_))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, WriteUint64(_)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, WriteUint32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetDevice(data, reply));
}

/**
 * @tc.name: StubRegisterInputDeviceMonitor_001
 * @tc.desc: Test the function StubRegisterInputDeviceMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubRegisterInputDeviceMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubRegisterInputDeviceMonitor(data, reply));
}

/**
 * @tc.name: StubUnregisterInputDeviceMonitor_001
 * @tc.desc: Test the function StubUnregisterInputDeviceMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubUnregisterInputDeviceMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubUnregisterInputDeviceMonitor(data, reply));
}

/**
 * @tc.name: StubGetKeyboardType_001
 * @tc.desc: Test the function StubGetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetKeyboardType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetKeyboardType(data, reply));
}

/**
 * @tc.name: StubGetKeyboardType_002
 * @tc.desc: Test the function StubGetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetKeyboardType_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    EXPECT_CALL(*messageParcelMock_, WriteInt32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetKeyboardType(data, reply));
}

/**
 * @tc.name: StubAddInputHandler_001
 * @tc.desc: Test the function StubAddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubAddInputHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubAddInputHandler(data, reply));
}

/**
 * @tc.name: StubAddInputHandler_002
 * @tc.desc: Test the function StubAddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubAddInputHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubAddInputHandler(data, reply));
}

/**
 * @tc.name: StubAddInputHandler_003
 * @tc.desc: Test the function StubAddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubAddInputHandler_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(1), Return(true)));
    EXPECT_CALL(*messageParcelMock_, CheckInterceptor()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubAddInputHandler(data, reply));
}

/**
 * @tc.name: StubAddInputHandler_004
 * @tc.desc: Test the function StubAddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubAddInputHandler_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(1), Return(true)));
    EXPECT_CALL(*messageParcelMock_, CheckInterceptor()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint32(_)).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubAddInputHandler(data, reply));
}

/**
 * @tc.name: StubAddInputHandler_005
 * @tc.desc: Test the function StubAddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubAddInputHandler_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(2), Return(true)));
    EXPECT_CALL(*messageParcelMock_, CheckMonitor()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubAddInputHandler(data, reply));
}

/**
 * @tc.name: StubAddInputHandler_006
 * @tc.desc: Test the function StubAddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubAddInputHandler_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(2), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, CheckMonitor()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubAddInputHandler(data, reply));
}

/**
 * @tc.name: StubAddInputHandler_007
 * @tc.desc: Test the function StubAddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubAddInputHandler_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(2), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, CheckMonitor()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubAddInputHandler(data, reply));
}

/**
 * @tc.name: StubRemoveInputHandler_001
 * @tc.desc: Test the function StubRemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubRemoveInputHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubRemoveInputHandler(data, reply));
}

/**
 * @tc.name: StubRemoveInputHandler_002
 * @tc.desc: Test the function StubRemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubRemoveInputHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubRemoveInputHandler(data, reply));
}

/**
 * @tc.name: StubRemoveInputHandler_003
 * @tc.desc: Test the function StubRemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubRemoveInputHandler_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(1), Return(true)));
    EXPECT_CALL(*messageParcelMock_, CheckInterceptor()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubRemoveInputHandler(data, reply));
}

/**
 * @tc.name: StubRemoveInputHandler_004
 * @tc.desc: Test the function StubRemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubRemoveInputHandler_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(1), Return(true)));
    EXPECT_CALL(*messageParcelMock_, CheckInterceptor()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint32(_)).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubRemoveInputHandler(data, reply));
}

/**
 * @tc.name: StubRemoveInputHandler_005
 * @tc.desc: Test the function StubRemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubRemoveInputHandler_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(2), Return(true)));
    EXPECT_CALL(*messageParcelMock_, CheckMonitor()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubRemoveInputHandler(data, reply));
}

/**
 * @tc.name: StubRemoveInputHandler_006
 * @tc.desc: Test the function StubRemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubRemoveInputHandler_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(2), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, CheckMonitor()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubRemoveInputHandler(data, reply));
}

/**
 * @tc.name: StubRemoveInputHandler_007
 * @tc.desc: Test the function StubRemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubRemoveInputHandler_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(2), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, CheckMonitor()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubRemoveInputHandler(data, reply));
}

/**
 * @tc.name: StubMarkEventConsumed_001
 * @tc.desc: Test the function StubMarkEventConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubMarkEventConsumed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, CheckMonitor()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubMarkEventConsumed(data, reply));
}

/**
 * @tc.name: StubMarkEventConsumed_002
 * @tc.desc: Test the function StubMarkEventConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubMarkEventConsumed_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, CheckMonitor()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubMarkEventConsumed(data, reply));
}

/**
 * @tc.name: StubMarkEventConsumed_003
 * @tc.desc: Test the function StubMarkEventConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubMarkEventConsumed_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, CheckMonitor()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubMarkEventConsumed(data, reply));
}

/**
 * @tc.name: StubMarkEventConsumed_004
 * @tc.desc: Test the function StubMarkEventConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubMarkEventConsumed_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, CheckMonitor()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubMarkEventConsumed(data, reply));
}

/**
 * @tc.name: StubSubscribeKeyEvent_001
 * @tc.desc: Test the function StubSubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSubscribeKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSubscribeKeyEvent(data, reply));
}

/**
 * @tc.name: StubSubscribeKeyEvent_002
 * @tc.desc: Test the function StubSubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSubscribeKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSubscribeKeyEvent(data, reply));
}

/**
 * @tc.name: StubSubscribeKeyEvent_003
 * @tc.desc: Test the function StubSubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSubscribeKeyEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSubscribeKeyEvent(data, reply));
}

/**
 * @tc.name: StubSubscribeKeyEvent_004
 * @tc.desc: Test the function StubSubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSubscribeKeyEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSubscribeKeyEvent(data, reply));
}

/**
 * @tc.name: StubSubscribeKeyEvent_005
 * @tc.desc: Test the function StubSubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSubscribeKeyEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(1), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSubscribeKeyEvent(data, reply));
}

/**
 * @tc.name: StubUnsubscribeKeyEvent_001
 * @tc.desc: Test the function StubUnsubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubUnsubscribeKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubUnsubscribeKeyEvent(data, reply));
}

/**
 * @tc.name: StubUnsubscribeKeyEvent_002
 * @tc.desc: Test the function StubUnsubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubUnsubscribeKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubUnsubscribeKeyEvent(data, reply));
}

/**
 * @tc.name: StubUnsubscribeKeyEvent_003
 * @tc.desc: Test the function StubUnsubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubUnsubscribeKeyEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubUnsubscribeKeyEvent(data, reply));
}

/**
 * @tc.name: StubUnsubscribeKeyEvent_004
 * @tc.desc: Test the function StubUnsubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubUnsubscribeKeyEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubUnsubscribeKeyEvent(data, reply));
}

/**
 * @tc.name: StubSubscribeSwitchEvent_001
 * @tc.desc: Test the function StubSubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSubscribeSwitchEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSubscribeSwitchEvent(data, reply));
}

/**
 * @tc.name: StubSubscribeSwitchEvent_002
 * @tc.desc: Test the function StubSubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSubscribeSwitchEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSubscribeSwitchEvent(data, reply));
}

/**
 * @tc.name: StubSubscribeSwitchEvent_003
 * @tc.desc: Test the function StubSubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSubscribeSwitchEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSubscribeSwitchEvent(data, reply));
}

/**
 * @tc.name: StubSubscribeSwitchEvent_004
 * @tc.desc: Test the function StubSubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSubscribeSwitchEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSubscribeSwitchEvent(data, reply));
}

/**
 * @tc.name: StubUnsubscribeSwitchEvent_001
 * @tc.desc: Test the function StubUnsubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubUnsubscribeSwitchEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubUnsubscribeSwitchEvent(data, reply));
}

/**
 * @tc.name: StubUnsubscribeSwitchEvent_002
 * @tc.desc: Test the function StubUnsubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubUnsubscribeSwitchEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubUnsubscribeSwitchEvent(data, reply));
}

/**
 * @tc.name: StubUnsubscribeSwitchEvent_003
 * @tc.desc: Test the function StubUnsubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubUnsubscribeSwitchEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubUnsubscribeSwitchEvent(data, reply));
}

/**
 * @tc.name: StubUnsubscribeSwitchEvent_004
 * @tc.desc: Test the function StubUnsubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubUnsubscribeSwitchEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubUnsubscribeSwitchEvent(data, reply));
}

/**
 * @tc.name: StubMoveMouseEvent_001
 * @tc.desc: Test the function StubMoveMouseEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubMoveMouseEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubMoveMouseEvent(data, reply));
}

/**
 * @tc.name: StubMoveMouseEvent_002
 * @tc.desc: Test the function StubMoveMouseEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubMoveMouseEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubMoveMouseEvent(data, reply));
}

/**
 * @tc.name: StubMoveMouseEvent_003
 * @tc.desc: Test the function StubMoveMouseEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubMoveMouseEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubMoveMouseEvent(data, reply));
}

/**
 * @tc.name: StubMoveMouseEvent_004
 * @tc.desc: Test the function StubMoveMouseEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubMoveMouseEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubMoveMouseEvent(data, reply));
}

/**
 * @tc.name: StubInjectKeyEvent_001
 * @tc.desc: Test the function StubInjectKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubInjectKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubInjectKeyEvent(data, reply));
}

/**
 * @tc.name: StubInjectKeyEvent_002
 * @tc.desc: Test the function StubInjectKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubInjectKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubInjectKeyEvent(data, reply));
}

/**
 * @tc.name: StubInjectKeyEvent_003
 * @tc.desc: Test the function StubInjectKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubInjectKeyEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
#else
        .WillOnce(Return(true));
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    EXPECT_CALL(*messageParcelMock_, ReadInt64(_))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint64(_)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint32(_))
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(false), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadInt32()).WillOnce(Return(0));
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubInjectKeyEvent(data, reply));
}

/**
 * @tc.name: StubInjectKeyEvent_004
 * @tc.desc: Test the function StubInjectKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubInjectKeyEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
#else
        .WillOnce(Return(true));
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    EXPECT_CALL(*messageParcelMock_, ReadInt64(_))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint64(_)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint32(_))
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(false), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadInt32()).WillOnce(Return(0));
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubInjectKeyEvent(data, reply));
}

/**
 * @tc.name: StubInjectKeyEvent_005
 * @tc.desc: Test the function StubInjectKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubInjectKeyEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
#else
        .WillOnce(Return(true));
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    EXPECT_CALL(*messageParcelMock_, ReadInt64(_))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint64(_)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint32(_))
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadInt32()).WillOnce(Return(0));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubInjectKeyEvent(data, reply));
}

/**
 * @tc.name: StubInjectPointerEvent_001
 * @tc.desc: Test the function StubInjectPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubInjectPointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubInjectPointerEvent(data, reply));
}

/**
 * @tc.name: StubInjectPointerEvent_002
 * @tc.desc: Test the function StubInjectPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubInjectPointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubInjectPointerEvent(data, reply));
}

/**
 * @tc.name: StubInjectPointerEvent_003
 * @tc.desc: Test the function StubInjectPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubInjectPointerEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true)).WillOnce(Return(true))
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
#else
        .WillOnce(Return(true));
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    EXPECT_CALL(*messageParcelMock_, ReadInt64(_))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint64(_)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint32(_))
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_))
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(false), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadFloat(_)).WillOnce(Return(true));
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    EXPECT_CALL(*messageParcelMock_, ReadDouble(_))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
#else
    EXPECT_CALL(*messageParcelMock_, ReadDouble(_)).WillOnce(Return(true));
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubInjectPointerEvent(data, reply));
}

/**
 * @tc.name: StubInjectPointerEvent_004
 * @tc.desc: Test the function StubInjectPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubInjectPointerEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true)).WillOnce(Return(true))
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
#else
        .WillOnce(Return(true));
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    EXPECT_CALL(*messageParcelMock_, ReadInt64(_))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint64(_)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint32(_))
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_))
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(false), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadFloat(_)).WillOnce(Return(true));
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    EXPECT_CALL(*messageParcelMock_, ReadDouble(_))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
#else
    EXPECT_CALL(*messageParcelMock_, ReadDouble(_)).WillOnce(Return(true));
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubInjectPointerEvent(data, reply));
}

/**
 * @tc.name: StubInjectPointerEvent_005
 * @tc.desc: Test the function StubInjectPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubInjectPointerEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true)).WillOnce(Return(true))
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
#else
        .WillOnce(Return(true));
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    EXPECT_CALL(*messageParcelMock_, ReadInt64(_))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint64(_)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadUint32(_))
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_))
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadFloat(_)).WillOnce(Return(true));
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    EXPECT_CALL(*messageParcelMock_, ReadDouble(_))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
#else
    EXPECT_CALL(*messageParcelMock_, ReadDouble(_)).WillOnce(Return(true));
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubInjectPointerEvent(data, reply));
}

/**
 * @tc.name: StubSetAnrListener_001
 * @tc.desc: Test the function StubSetAnrListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetAnrListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetAnrListener(data, reply));
}

/**
 * @tc.name: StubSetAnrListener_002
 * @tc.desc: Test the function StubSetAnrListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetAnrListener_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetAnrListener(data, reply));
}

/**
 * @tc.name: StubSetAnrListener_003
 * @tc.desc: Test the function StubSetAnrListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetAnrListener_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    service->retObserver_ = -1;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetAnrListener(data, reply));
}

/**
 * @tc.name: StubSetAnrListener_004
 * @tc.desc: Test the function StubSetAnrListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetAnrListener_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    service->retObserver_ = 0;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetAnrListener(data, reply));
}

/**
 * @tc.name: StubGetDisplayBindInfo_001
 * @tc.desc: Test the function StubGetDisplayBindInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetDisplayBindInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetDisplayBindInfo(data, reply));
}

/**
 * @tc.name: StubGetDisplayBindInfo_002
 * @tc.desc: Test the function StubGetDisplayBindInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetDisplayBindInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetDisplayBindInfo(data, reply));
}

/**
 * @tc.name: StubGetDisplayBindInfo_003
 * @tc.desc: Test the function StubGetDisplayBindInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetDisplayBindInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    service->retBindInfo_ = -1;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetDisplayBindInfo(data, reply));
}

/**
 * @tc.name: StubGetDisplayBindInfo_004
 * @tc.desc: Test the function StubGetDisplayBindInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetDisplayBindInfo_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, WriteInt32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    service->retBindInfo_ = 0;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetDisplayBindInfo(data, reply));
}

/**
 * @tc.name: StubGetAllMmiSubscribedEvents_001
 * @tc.desc: Test the function StubGetAllMmiSubscribedEvents
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetAllMmiSubscribedEvents_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetAllMmiSubscribedEvents(data, reply));
}

/**
 * @tc.name: StubGetAllMmiSubscribedEvents_002
 * @tc.desc: Test the function StubGetAllMmiSubscribedEvents
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetAllMmiSubscribedEvents_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetAllMmiSubscribedEvents(data, reply));
}

/**
 * @tc.name: StubGetAllMmiSubscribedEvents_003
 * @tc.desc: Test the function StubGetAllMmiSubscribedEvents
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetAllMmiSubscribedEvents_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    service->retMmiSubscribedEvents_ = -1;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetAllMmiSubscribedEvents(data, reply));
}

/**
 * @tc.name: StubGetAllMmiSubscribedEvents_004
 * @tc.desc: Test the function StubGetAllMmiSubscribedEvents
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetAllMmiSubscribedEvents_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, WriteInt32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    service->retMmiSubscribedEvents_ = 0;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetAllMmiSubscribedEvents(data, reply));
}

/**
 * @tc.name: StubSetDisplayBind_001
 * @tc.desc: Test the function StubSetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetDisplayBind_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetDisplayBind(data, reply));
}

/**
 * @tc.name: StubSetDisplayBind_002
 * @tc.desc: Test the function StubSetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetDisplayBind_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetDisplayBind(data, reply));
}

/**
 * @tc.name: StubSetDisplayBind_003
 * @tc.desc: Test the function StubSetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetDisplayBind_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    EXPECT_CALL(*messageParcelMock_, WriteString(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetDisplayBind(data, reply));
}

/**
 * @tc.name: StubSetDisplayBind_004
 * @tc.desc: Test the function StubSetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetDisplayBind_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    EXPECT_CALL(*messageParcelMock_, WriteString(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetDisplayBind(data, reply));
}

/**
 * @tc.name: StubGetFunctionKeyState_001
 * @tc.desc: Test the function StubGetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetFunctionKeyState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetFunctionKeyState(data, reply));
}

/**
 * @tc.name: StubGetFunctionKeyState_002
 * @tc.desc: Test the function StubGetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetFunctionKeyState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetFunctionKeyState(data, reply));
}

/**
 * @tc.name: StubGetFunctionKeyState_003
 * @tc.desc: Test the function StubGetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetFunctionKeyState_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetFunctionKeyState(data, reply));
}

/**
 * @tc.name: StubGetFunctionKeyState_004
 * @tc.desc: Test the function StubGetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetFunctionKeyState_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    EXPECT_CALL(*messageParcelMock_, WriteBool(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetFunctionKeyState(data, reply));
}

/**
 * @tc.name: StubSetFunctionKeyState_001
 * @tc.desc: Test the function StubSetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetFunctionKeyState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetFunctionKeyState(data, reply));
}

/**
 * @tc.name: StubSetFunctionKeyState_002
 * @tc.desc: Test the function StubSetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetFunctionKeyState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetFunctionKeyState(data, reply));
}

/**
 * @tc.name: StubSetFunctionKeyState_003
 * @tc.desc: Test the function StubSetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetFunctionKeyState_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetFunctionKeyState(data, reply));
}

/**
 * @tc.name: StubSetFunctionKeyState_004
 * @tc.desc: Test the function StubSetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetFunctionKeyState_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetFunctionKeyState(data, reply));
}

/**
 * @tc.name: StubSetPointerLocation_001
 * @tc.desc: Test the function StubSetPointerLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerLocation_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerLocation(data, reply));
}

/**
 * @tc.name: StubSetPointerLocation_002
 * @tc.desc: Test the function StubSetPointerLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerLocation_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerLocation(data, reply));
}

/**
 * @tc.name: StubSetPointerLocation_003
 * @tc.desc: Test the function StubSetPointerLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerLocation_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetPointerLocation(data, reply));
}

/**
 * @tc.name: StubSetMouseCaptureMode_001
 * @tc.desc: Test the function StubSetMouseCaptureMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseCaptureMode_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMouseCaptureMode(data, reply));
}

/**
 * @tc.name: StubSetMouseCaptureMode_002
 * @tc.desc: Test the function StubSetMouseCaptureMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseCaptureMode_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetMouseCaptureMode(data, reply));
}

/**
 * @tc.name: StubGetWindowPid_001
 * @tc.desc: Test the function StubGetWindowPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetWindowPid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetWindowPid(data, reply));
}

/**
 * @tc.name: StubGetWindowPid_002
 * @tc.desc: Test the function StubGetWindowPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetWindowPid_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    EXPECT_CALL(*messageParcelMock_, WriteInt32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetWindowPid(data, reply));
}

/**
 * @tc.name: StubGetWindowPid_003
 * @tc.desc: Test the function StubGetWindowPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetWindowPid_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    EXPECT_CALL(*messageParcelMock_, WriteInt32(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetWindowPid(data, reply));
}

/**
 * @tc.name: StubAppendExtraData_001
 * @tc.desc: Test the function StubAppendExtraData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubAppendExtraData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubAppendExtraData(data, reply));
}

/**
 * @tc.name: StubAppendExtraData_002
 * @tc.desc: Test the function StubAppendExtraData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubAppendExtraData_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>((ExtraData::MAX_BUFFER_SIZE + 1)), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubAppendExtraData(data, reply));
}

/**
 * @tc.name: StubAppendExtraData_003
 * @tc.desc: Test the function StubAppendExtraData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubAppendExtraData_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubAppendExtraData(data, reply));
}

/**
 * @tc.name: StubAppendExtraData_004
 * @tc.desc: Test the function StubAppendExtraData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubAppendExtraData_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)))
        .WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubAppendExtraData(data, reply));
}

/**
 * @tc.name: StubEnableCombineKey_001
 * @tc.desc: Test the function StubEnableCombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubEnableCombineKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubEnableCombineKey(data, reply));
}

/**
 * @tc.name: StubEnableCombineKey_002
 * @tc.desc: Test the function StubEnableCombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubEnableCombineKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubEnableCombineKey(data, reply));
}

/**
 * @tc.name: StubEnableCombineKey_003
 * @tc.desc: Test the function StubEnableCombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubEnableCombineKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(false), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubEnableCombineKey(data, reply));
}

/**
 * @tc.name: StubEnableInputDevice_001
 * @tc.desc: Test the function StubEnableInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubEnableInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubEnableInputDevice(data, reply));
}

/**
 * @tc.name: StubEnableInputDevice_002
 * @tc.desc: Test the function StubEnableInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubEnableInputDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubEnableInputDevice(data, reply));
}

/**
 * @tc.name: StubEnableInputDevice_003
 * @tc.desc: Test the function StubEnableInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubEnableInputDevice_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(false), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubEnableInputDevice(data, reply));
}

/**
 * @tc.name: StubSetKeyDownDuration_001
 * @tc.desc: Test the function StubSetKeyDownDuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetKeyDownDuration_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetKeyDownDuration(data, reply));
}

/**
 * @tc.name: StubSetKeyDownDuration_002
 * @tc.desc: Test the function StubSetKeyDownDuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetKeyDownDuration_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetKeyDownDuration(data, reply));
}

/**
 * @tc.name: StubSetKeyDownDuration_003
 * @tc.desc: Test the function StubSetKeyDownDuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetKeyDownDuration_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadString(_)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(-1), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetKeyDownDuration(data, reply));
}

/**
 * @tc.name: StubSetKeyDownDuration_004
 * @tc.desc: Test the function StubSetKeyDownDuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetKeyDownDuration_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadString(_)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadInt32(_)).WillOnce(DoAll(SetArgReferee<0>(0), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetKeyDownDuration(data, reply));
}

/**
 * @tc.name: VerifyTouchPadSetting_001
 * @tc.desc: Test the function VerifyTouchPadSetting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, VerifyTouchPadSetting_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    EXPECT_NO_FATAL_FAILURE(stub->VerifyTouchPadSetting());
}

/**
 * @tc.name: VerifyTouchPadSetting_002
 * @tc.desc: Test the function VerifyTouchPadSetting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, VerifyTouchPadSetting_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(false));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    EXPECT_NO_FATAL_FAILURE(stub->VerifyTouchPadSetting());
}

/**
 * @tc.name: VerifyTouchPadSetting_003
 * @tc.desc: Test the function VerifyTouchPadSetting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, VerifyTouchPadSetting_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    EXPECT_NO_FATAL_FAILURE(stub->VerifyTouchPadSetting());
}

/**
 * @tc.name: StubSetTouchpadScrollSwitch_001
 * @tc.desc: Test the function StubSetTouchpadScrollSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetTouchpadScrollSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetTouchpadScrollSwitch(data, reply));
}

/**
 * @tc.name: StubSetTouchpadScrollSwitch_002
 * @tc.desc: Test the function StubSetTouchpadScrollSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetTouchpadScrollSwitch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetTouchpadScrollSwitch(data, reply));
}

/**
 * @tc.name: StubSetTouchpadScrollSwitch_003
 * @tc.desc: Test the function StubSetTouchpadScrollSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetTouchpadScrollSwitch_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(false), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetTouchpadScrollSwitch(data, reply));
}

/**
 * @tc.name: StubGetTouchpadScrollSwitch_001
 * @tc.desc: Test the function StubGetTouchpadScrollSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetTouchpadScrollSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubGetTouchpadScrollSwitch(data, reply));
}

/**
 * @tc.name: StubGetTouchpadScrollSwitch_002
 * @tc.desc: Test the function StubGetTouchpadScrollSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetTouchpadScrollSwitch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(true), Return(true)));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetTouchpadScrollSwitch(data, reply));
    EXPECT_NO_FATAL_FAILURE(stub->StubGetTouchpadScrollSwitch(data, reply));
}

/**
 * @tc.name: StubGetTouchpadScrollSwitch_003
 * @tc.desc: Test the function StubGetTouchpadScrollSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetTouchpadScrollSwitch_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, VerifySystemApp()).WillOnce(Return(true)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, ReadBool(_)).WillOnce(DoAll(SetArgReferee<0>(false), Return(true)));
    EXPECT_CALL(*messageParcelMock_, WriteBool(_)).WillOnce(Return(true));
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIServiceTest>();
    ASSERT_NE(stub, nullptr);
    std::shared_ptr<MMIServiceTest> service = std::static_pointer_cast<MMIServiceTest>(stub);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NO_FATAL_FAILURE(stub->StubSetTouchpadScrollSwitch(data, reply));
    EXPECT_NO_FATAL_FAILURE(stub->StubGetTouchpadScrollSwitch(data, reply));
}
} // namespace MMI
} // namespace OHOS