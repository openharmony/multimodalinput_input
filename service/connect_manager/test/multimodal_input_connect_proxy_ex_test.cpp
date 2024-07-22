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

#include "anco_channel_death_recipient.h"
#include "anco_channel_proxy.h"
#include "iremote_object.h"
#include "message_parcel_mock.h"
#include "mmi_log.h"
#include "multimodal_input_connect_proxy.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MultimodalInputConnectProxyTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;
constexpr uint32_t DEFAULT_ICON_COLOR { 0xFF };
constexpr int32_t MIDDLE_PIXEL_MAP_WIDTH { 400 };
constexpr int32_t MIDDLE_PIXEL_MAP_HEIGHT { 400 };
constexpr int32_t MAX_PIXEL_MAP_WIDTH { 600 };
constexpr int32_t MAX_PIXEL_MAP_HEIGHT { 600 };
constexpr int32_t INT32_BYTE { 4 };

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

class MultimodalInputConnectProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase();
    static std::shared_ptr<Media::PixelMap> CreatePixelMap(int32_t width, int32_t height);
    void SetUp() {}
    void TearDown() {}

    static inline std::shared_ptr<MessageParcelMock> messageParcelMock_ = nullptr;
};

void MultimodalInputConnectProxyTest::SetUpTestCase(void)
{
    messageParcelMock_ = std::make_shared<MessageParcelMock>();
    MessageParcelMock::messageParcel = messageParcelMock_;
}
void MultimodalInputConnectProxyTest::TearDownTestCase()
{
    MessageParcelMock::messageParcel = nullptr;
    messageParcelMock_ = nullptr;
}

std::shared_ptr<Media::PixelMap> MultimodalInputConnectProxyTest::CreatePixelMap(int32_t width, int32_t height)
{
    CALL_DEBUG_ENTER;
    if (width <= 0 || width > MAX_PIXEL_MAP_WIDTH || height <= 0 || height > MAX_PIXEL_MAP_HEIGHT) {
        return nullptr;
    }
    Media::InitializationOptions opts;
    opts.size.height = height;
    opts.size.width = width;
    opts.pixelFormat = Media::PixelFormat::BGRA_8888;
    opts.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.scaleMode = Media::ScaleMode::FIT_TARGET_SIZE;

    int32_t colorLen = width * height;
    uint32_t *pixelColors = new (std::nothrow) uint32_t[colorLen];
    CHKPP(pixelColors);
    int32_t colorByteCount = colorLen * INT32_BYTE;
    errno_t ret = memset_s(pixelColors, colorByteCount, DEFAULT_ICON_COLOR, colorByteCount);
    if (ret != EOK) {
        delete[] pixelColors;
        return nullptr;
    }
    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(pixelColors, colorLen, opts);
    if (pixelMap == nullptr) {
        delete[] pixelColors;
        return nullptr;
    }
    delete[] pixelColors;
    return pixelMap;
}

class MockPointerEvent : public PointerEvent {
public:
    int32_t eventType;
    explicit MockPointerEvent(int32_t eventType) : PointerEvent(eventType), eventType(eventType) {}
    MOCK_METHOD(bool, WriteToParcel, (Parcel& data));
};

class MockIRemoteObject : public IRemoteObject {
public:
    MockIRemoteObject() = default;
    ~MockIRemoteObject() override = default;
};

/**
 * @tc.name: MultimodalInputConnectProxyTest_SubscribeSwitchEvent_001
 * @tc.desc: Cover if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectProxyTest, MultimodalInputConnectProxyTest_SubscribeSwitchEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(false));
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    MultimodalInputConnectProxy proxy(remote);
    int32_t subscribeId = 10;
    int32_t switchType = 1;
    EXPECT_EQ(proxy.SubscribeSwitchEvent(subscribeId, switchType), ERR_INVALID_VALUE);
}

/**
 * @tc.name: MultimodalInputConnectProxyTest_SubscribeSwitchEvent_002
 * @tc.desc: Cover the else branch of if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor()))
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectProxyTest, MultimodalInputConnectProxyTest_SubscribeSwitchEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, WriteInt32(_)).WillRepeatedly(Return(true));
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    MultimodalInputConnectProxy proxy(remote);
    int32_t subscribeId = 10;
    int32_t switchType = 1;
    EXPECT_EQ(proxy.SubscribeSwitchEvent(subscribeId, switchType), RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectProxyTest_UnsubscribeSwitchEvent_001
 * @tc.desc: Cover if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectProxyTest, MultimodalInputConnectProxyTest_UnsubscribeSwitchEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(false));
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    MultimodalInputConnectProxy proxy(remote);
    int32_t subscribeId = 10;
    EXPECT_EQ(proxy.UnsubscribeSwitchEvent(subscribeId), ERR_INVALID_VALUE);
}

/**
 * @tc.name: MultimodalInputConnectProxyTest_UnsubscribeSwitchEvent_002
 * @tc.desc: Cover the else branch of if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor()))
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectProxyTest, MultimodalInputConnectProxyTest_UnsubscribeSwitchEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, WriteInt32(_)).WillRepeatedly(Return(true));
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    MultimodalInputConnectProxy proxy(remote);
    int32_t subscribeId = 10;
    EXPECT_EQ(proxy.UnsubscribeSwitchEvent(subscribeId), RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectProxyTest_SetMouseHotSpot_001
 * @tc.desc: Cover if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor())) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectProxyTest, MultimodalInputConnectProxyTest_SetMouseHotSpot_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(false));
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    MultimodalInputConnectProxy proxy(remote);
    int32_t pid = 1000;
    int32_t windowId = 50;
    int32_t hotSpotX = 300;
    int32_t hotSpotY = 300;
    EXPECT_EQ(proxy.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY), ERR_INVALID_VALUE);
}

/**
 * @tc.name: MultimodalInputConnectProxyTest_SetMouseHotSpot_002
 * @tc.desc: Cover the else branch of if (!data.WriteInterfaceToken(MultimodalInputConnectProxy::GetDescriptor()))
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectProxyTest, MultimodalInputConnectProxyTest_SetMouseHotSpot_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(true));
    EXPECT_CALL(*messageParcelMock_, WriteInt32(_)).WillRepeatedly(Return(true));
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    MultimodalInputConnectProxy proxy(remote);
    int32_t pid = 1000;
    int32_t windowId = 50;
    int32_t hotSpotX = 300;
    int32_t hotSpotY = 300;
    EXPECT_EQ(proxy.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY), RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectProxyTest_SyncInputEvent_001
 * @tc.desc: Test the function SyncInputEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectProxyTest, MultimodalInputConnectProxyTest_SyncInputEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteObject> remoteObject;
    OHOS::MMI::AncoChannelProxy ancoChannelProxy(remoteObject);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillRepeatedly(Return(false));
    int32_t ret = ancoChannelProxy.SyncInputEvent(pointerEvent);
    EXPECT_EQ(ret, RET_ERR);
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillRepeatedly(Return(true));
    ret = ancoChannelProxy.SyncInputEvent(pointerEvent);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MultimodalInputConnectProxyTest_SyncInputEvent_002
 * @tc.desc: Test the function SyncInputEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectProxyTest, MultimodalInputConnectProxyTest_SyncInputEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteObject> remoteObject;
    OHOS::MMI::AncoChannelProxy ancoChannelProxy(remoteObject);
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillRepeatedly(Return(true));
    int32_t eventType = 1;
    auto pointerEvent = std::make_shared<MockPointerEvent>(eventType);
    EXPECT_CALL(*pointerEvent, WriteToParcel(_)).WillRepeatedly(Return(true));
    int32_t ret = ancoChannelProxy.SyncInputEvent(pointerEvent);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MultimodalInputConnectProxyTest_SyncInputEvent_003
 * @tc.desc: Test the function SyncInputEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectProxyTest, MultimodalInputConnectProxyTest_SyncInputEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteObject> remoteObject;
    OHOS::MMI::AncoChannelProxy ancoChannelProxy(remoteObject);
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillRepeatedly(Return(false));
    int32_t ret = ancoChannelProxy.SyncInputEvent(keyEvent);
    EXPECT_EQ(ret, RET_ERR);
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillRepeatedly(Return(true));
    ret = ancoChannelProxy.SyncInputEvent(keyEvent);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MultimodalInputConnectProxyTest_SyncInputEvent_004
 * @tc.desc: Test the function SyncInputEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectProxyTest, MultimodalInputConnectProxyTest_SyncInputEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteObject> remoteObject;
    OHOS::MMI::AncoChannelProxy ancoChannelProxy(remoteObject);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_HOME);
    keyEvent->SetActionTime(100);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->ActionToString(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->KeyCodeToString(KeyEvent::KEYCODE_HOME);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_HOME);
    item.SetDownTime(100);
    item.SetPressed(true);
    keyEvent->AddKeyItem(item);
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillRepeatedly(Return(true));
    int32_t ret = ancoChannelProxy.SyncInputEvent(keyEvent);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MultimodalInputConnectProxyTest_UpdateWindowInfo_001
 * @tc.desc: Test the function UpdateWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectProxyTest, MultimodalInputConnectProxyTest_UpdateWindowInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteObject> remoteObject;
    OHOS::MMI::AncoChannelProxy ancoChannelProxy(remoteObject);
    auto windows = std::make_shared<AncoWindows>();
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillRepeatedly(Return(false));
    int32_t ret = ancoChannelProxy.UpdateWindowInfo(windows);
    EXPECT_EQ(ret, RET_ERR);
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillRepeatedly(Return(true));
    ret = ancoChannelProxy.UpdateWindowInfo(windows);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MultimodalInputConnectProxyTest_OnRemoteDied_001
 * @tc.desc: Test the function OnRemoteDied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectProxyTest, MultimodalInputConnectProxyTest_OnRemoteDied_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool callbackCalled = false;
    auto deathCallback = [&callbackCalled](const wptr<IRemoteObject>& object) {
        callbackCalled = true;
    };
    OHOS::MMI::AncoChannelDeathRecipient recipient(deathCallback);
    OHOS::sptr<OHOS::IRemoteObject> object;
    auto remoteObjectWptr = wptr<OHOS::IRemoteObject>(object);
    EXPECT_NO_FATAL_FAILURE(recipient.OnRemoteDied(remoteObjectWptr));
}

/**
 * @tc.name: MultimodalInputConnectProxyTest_OnRemoteDied_002
 * @tc.desc: Test the function OnRemoteDied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectProxyTest, MultimodalInputConnectProxyTest_OnRemoteDied_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OHOS::MMI::AncoChannelDeathRecipient recipient(nullptr);
    OHOS::sptr<OHOS::IRemoteObject> object;
    auto remoteObjectWptr = wptr<OHOS::IRemoteObject>(object);
    EXPECT_NO_FATAL_FAILURE(recipient.OnRemoteDied(remoteObjectWptr));
}

/**
 * @tc.name: MultimodalInputConnectProxyTest_GetPointerSnapshot
 * @tc.desc: Test the function GetPointerSnapshot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectProxyTest, MultimodalInputConnectProxyTest_GetPointerSnapshot, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillRepeatedly(Return(false));
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");
    MultimodalInputConnectProxy proxy(remote);
    std::shared_ptr<Media::PixelMap> pixelMapPtr = CreatePixelMap(MIDDLE_PIXEL_MAP_WIDTH, MIDDLE_PIXEL_MAP_HEIGHT);
    EXPECT_EQ(proxy.GetPointerSnapshot((void *)pixelMapPtr.get()), ERR_INVALID_VALUE);
}
} // namespace MMI
} // namespace OHOS