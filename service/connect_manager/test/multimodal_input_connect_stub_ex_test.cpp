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
    int32_t SetMousePrimaryButton(int32_t primaryButton) override { return primaryButton; }
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
    int32_t SetCurrentUser(int32_t userId) override { return userId; }
    int32_t AddVirtualInputDevice(std::shared_ptr<InputDevice> device, int32_t &deviceId) { return 0; }
    int32_t RemoveVirtualInputDevice(int32_t deviceId) { return 0; }
    int32_t EnableHardwareCursorStats(bool enable) override { return 0; }
    int32_t GetHardwareCursorStats(uint32_t &frameCount, uint32_t &vsyncCount) override { return 0; }

    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t rows_ = 0;
    int32_t size_ = 0;
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
} // namespace MMI
} // namespace OHOS