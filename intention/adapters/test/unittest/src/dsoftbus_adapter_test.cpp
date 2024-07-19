/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <memory>
#include <vector>

#include <unistd.h>

#include "accesstoken_kit.h"
#include "device_manager.h"
#include "dm_device_info.h"
#include <gtest/gtest.h>
#include "nativetoken_kit.h"
#include "securec.h"
#include "token_setproc.h"

#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "dsoftbus_adapter_impl.h"
#include "dsoftbus_adapter.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "DsoftbusAdapterTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
const std::string SYSTEM_CORE { "system_core" };
uint64_t g_tokenID { 0 };
#define SERVER_SESSION_NAME "ohos.msdp.device_status.intention.serversession"
#define DSTB_HARDWARE DistributedHardware::DeviceManager::GetInstance()
const std::string PKG_NAME_PREFIX { "DBinderBus_Dms_" };
const std::string CLIENT_SESSION_NAME { "ohos.msdp.device_status.intention.clientsession." };
constexpr size_t DEVICE_NAME_SIZE_MAX { 256 };
constexpr size_t PKG_NAME_SIZE_MAX { 65 };
constexpr int32_t SOCKET_SERVER { 0 };
constexpr int32_t SOCKET_CLIENT { 1 };
constexpr int32_t SOCKET { 1 };
const char* g_cores[] = { "ohos.permission.INPUT_MONITORING" };
} // namespace

class DsoftbusAdapterTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void SetPermission(const std::string &level, const char** perms, size_t permAmount);
    static void RemovePermission();
    static std::string GetLocalNetworkId();
};

void DsoftbusAdapterTest::SetPermission(const std::string &level, const char** perms, size_t permAmount)
{
    CALL_DEBUG_ENTER;
    if (perms == nullptr || permAmount == 0) {
        FI_HILOGE("The perms is empty");
        return;
    }

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permAmount,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "DsoftbusAdapterTest",
        .aplStr = level.c_str(),
    };
    g_tokenID = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(g_tokenID);
    OHOS::Security::AccessToken::AccessTokenKit::AccessTokenKit::ReloadNativeTokenInfo();
}

void DsoftbusAdapterTest::RemovePermission()
{
    CALL_DEBUG_ENTER;
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenID);
    if (ret != RET_OK) {
        FI_HILOGE("Failed to remove permission");
        return;
    }
}

void DsoftbusAdapterTest::SetUpTestCase() {}

void DsoftbusAdapterTest::SetUp() {}

void DsoftbusAdapterTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

class DSoftbusObserver final : public IDSoftbusObserver {
public:
    DSoftbusObserver() = default;
    ~DSoftbusObserver() = default;

    void OnBind(const std::string &networkId) {}
    void OnShutdown(const std::string &networkId) {}
    void OnConnected(const std::string &networkId) {}
    bool OnPacket(const std::string &networkId, NetPacket &packet)
    {
        return true;
    }
    bool OnRawData(const std::string &networkId, const void *data, uint32_t dataLen)
    {
        return true;
    }
};

std::string DsoftbusAdapterTest::GetLocalNetworkId()
{
    auto packageName = PKG_NAME_PREFIX + std::to_string(getpid());
    OHOS::DistributedHardware::DmDeviceInfo dmDeviceInfo;
    if (int32_t errCode = DSTB_HARDWARE.GetLocalDeviceInfo(packageName, dmDeviceInfo); errCode != RET_OK) {
        FI_HILOGE("GetLocalBasicInfo failed, errCode:%{public}d", errCode);
        return {};
    }
    FI_HILOGD("LocalNetworkId:%{public}s", Utility::Anonymize(dmDeviceInfo.networkId).c_str());
    return dmDeviceInfo.networkId;
}

/**
 * @tc.name: TestEnable
 * @tc.desc: Test Enable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, TestEnable, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DSoftbusAdapter dSoftbusAdapter;
    ASSERT_NO_FATAL_FAILURE(dSoftbusAdapter.Enable());
    RemovePermission();
}

/**
 * @tc.name: TestDisable
 * @tc.desc: Test Disable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, TestDisable, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DSoftbusAdapter dSoftbusAdapter;
    ASSERT_NO_FATAL_FAILURE(dSoftbusAdapter.Disable());
    RemovePermission();
}

/**
 * @tc.name: TestAddObserver
 * @tc.desc: Test AddObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, TestAddObserver, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DSoftbusAdapter dSoftbusAdapter;
    std::shared_ptr<IDSoftbusObserver> observer = std::make_shared<DSoftbusObserver>();
    ASSERT_NO_FATAL_FAILURE(dSoftbusAdapter.Enable());
    ASSERT_NO_FATAL_FAILURE(dSoftbusAdapter.AddObserver(observer));
    ASSERT_NO_FATAL_FAILURE(dSoftbusAdapter.Disable());
    RemovePermission();
}
/**
 * @tc.name: TestRemoveObserver
 * @tc.desc: Test RemoveObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, TestRemoveObserver, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DSoftbusAdapter dSoftbusAdapter;
    std::shared_ptr<IDSoftbusObserver> observer = std::make_shared<DSoftbusObserver>();
    ASSERT_NO_FATAL_FAILURE(dSoftbusAdapter.Enable());
    ASSERT_NO_FATAL_FAILURE(dSoftbusAdapter.AddObserver(observer));
    ASSERT_NO_FATAL_FAILURE(dSoftbusAdapter.RemoveObserver(observer));
    ASSERT_NO_FATAL_FAILURE(dSoftbusAdapter.Disable());
    RemovePermission();
}

/**
 * @tc.name: TestOpenSession
 * @tc.desc: Test OpenSession
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, TestOpenSession, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DSoftbusAdapter dSoftbusAdapter;
    std::string networkId("softbus");
    int32_t ret = dSoftbusAdapter.OpenSession(networkId);
    ASSERT_EQ(ret, RET_ERR);
    RemovePermission();
}

/**
 * @tc.name: TestCloseSession
 * @tc.desc: Test CloseSession
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, TestCloseSession, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DSoftbusAdapter dSoftbusAdapter;
    std::string networkId("softbus");
    int32_t ret = dSoftbusAdapter.OpenSession(networkId);
    ASSERT_EQ(ret, RET_ERR);
    ASSERT_NO_FATAL_FAILURE(dSoftbusAdapter.CloseSession(networkId));
    RemovePermission();
}

/**
 * @tc.name: TestSendPacket
 * @tc.desc: Test SendPacket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, SendPacket, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DSoftbusAdapter dSoftbusAdapter;
    std::string networkId("softbus");
    NetPacket packet(MessageId::DSOFTBUS_START_COOPERATE);
    ASSERT_NO_FATAL_FAILURE(dSoftbusAdapter.SendPacket(networkId, packet));
    RemovePermission();
}

/**
 * @tc.name: TestSendParcel
 * @tc.desc: Test SendParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, SendParcel, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DSoftbusAdapter dSoftbusAdapter;
    std::string networkId("softbus");
    Parcel parcel;
    ASSERT_NO_FATAL_FAILURE(dSoftbusAdapter.SendParcel(networkId, parcel));
    RemovePermission();
}

/**
 * @tc.name: TestSetupServer
 * @tc.desc: Test SetupServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, SetupServer, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DSoftbusAdapter dSoftbusAdapter;
    int32_t ret = DSoftbusAdapterImpl::GetInstance()->SetupServer();
    ASSERT_EQ(ret, RET_ERR);
    RemovePermission();
}

/**
 * @tc.name: TestConfigTcpAlive
 * @tc.desc: Test ConfigTcpAlive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, ConfigTcpAlive, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    ASSERT_NO_FATAL_FAILURE(DSoftbusAdapterImpl::GetInstance()->ConfigTcpAlive(SOCKET));
    RemovePermission();
}

/**
 * @tc.name: TestInitSocket
 * @tc.desc: Test InitSocket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, InitSocket, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DSoftbusAdapter dSoftbusAdapter;
    char name[DEVICE_NAME_SIZE_MAX] {};
    char peerName[DEVICE_NAME_SIZE_MAX] { SERVER_SESSION_NAME };
    char peerNetworkId[PKG_NAME_SIZE_MAX] {};
    char pkgName[PKG_NAME_SIZE_MAX] { FI_PKG_NAME };
    SocketInfo info {
        .name = name,
        .peerName = peerName,
        .peerNetworkId = peerNetworkId,
        .pkgName = pkgName,
        .dataType = DATA_TYPE_BYTES
    };
    int32_t socket = 1;
    int32_t ret = DSoftbusAdapterImpl::GetInstance()->InitSocket(info, SOCKET_CLIENT, socket);
    ASSERT_EQ(ret, RET_ERR);
    ret = DSoftbusAdapterImpl::GetInstance()->InitSocket(info, SOCKET_SERVER, socket);
    ASSERT_EQ(ret, RET_ERR);
    RemovePermission();
}

/**
 * @tc.name: TestOnBind
 * @tc.desc: Test OnBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, OnBind, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    PeerSocketInfo info;
    char deviceId[] = "softbus";
    info.networkId = deviceId;
    ASSERT_NO_FATAL_FAILURE(DSoftbusAdapterImpl::GetInstance()->OnBind(SOCKET, info));
    ASSERT_NO_FATAL_FAILURE(DSoftbusAdapterImpl::GetInstance()->OnShutdown(SOCKET, SHUTDOWN_REASON_UNKNOWN));
    RemovePermission();
}

/**
 * @tc.name: TestOnBytes
 * @tc.desc: Test OnBytes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, OnBytes, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    int32_t *data = new int32_t(SOCKET);
    ASSERT_NO_FATAL_FAILURE(DSoftbusAdapterImpl::GetInstance()->OnBytes(SOCKET, data, sizeof(data)));
    RemovePermission();
}

/**
 * @tc.name: TestHandleSessionData
 * @tc.desc: Test HandleSessionData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, HandleSessionData, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    std::string networkId("softbus");
    CircleStreamBuffer circleBuffer;
    ASSERT_NO_FATAL_FAILURE(DSoftbusAdapterImpl::GetInstance()->HandleSessionData(networkId, circleBuffer));
    RemovePermission();
}

/**
 * @tc.name: TestHandleRawData
 * @tc.desc: Test HandleRawData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, HandleRawData, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    std::string networkId("softbus");
    int32_t *data = new int32_t(SOCKET);
    ASSERT_NO_FATAL_FAILURE(DSoftbusAdapterImpl::GetInstance()->HandleRawData(networkId, data, sizeof(data)));
    RemovePermission();
}

/**
 * @tc.name: TestCloseAllSessions
 * @tc.desc: Test CloseAllSessions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, TestCloseAllSessions, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DSoftbusAdapter dSoftbusAdapter;
    ASSERT_NO_FATAL_FAILURE(dSoftbusAdapter.CloseAllSessions());
    RemovePermission();
}

/**
 * @tc.name: TestDestroyInstance
 * @tc.desc: Test Destroy Instance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, TestDestroyInstance, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DSoftbusAdapter dSoftbusAdapter;
    ASSERT_NO_FATAL_FAILURE(DSoftbusAdapterImpl::DestroyInstance());
    RemovePermission();
}

/**
 * @tc.name: TestDestroyInstance
 * @tc.desc: Test SendPacket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, DsoftbusAdapterTest01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    PeerSocketInfo info;
    char deviceId[] = "softbus";
    info.networkId = deviceId;
    DSoftbusAdapterImpl::GetInstance()->OnBind(SOCKET, info);
    std::string networkId("softbus");
    NetPacket packet(MessageId::DSOFTBUS_START_COOPERATE);
    ASSERT_NO_FATAL_FAILURE(DSoftbusAdapterImpl::GetInstance()->SendPacket(networkId, packet));
    RemovePermission();
}

/**
 * @tc.name: TestSendParcel
 * @tc.desc: Test SendParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, DsoftbusAdapterTest02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    PeerSocketInfo info;
    char deviceId[] = "softbus";
    info.networkId = deviceId;
    DSoftbusAdapterImpl::GetInstance()->OnBind(SOCKET, info);
    std::string networkId("softbus");
    Parcel parcel;
    ASSERT_NO_FATAL_FAILURE(DSoftbusAdapterImpl::GetInstance()->SendParcel(networkId, parcel));
    RemovePermission();
}

/**
 * @tc.name: TestSendParcel
 * @tc.desc: Test BroadcastPacket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, DsoftbusAdapterTest03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    NetPacket packet(MessageId::DSOFTBUS_START_COOPERATE);
    int32_t ret = DSoftbusAdapterImpl::GetInstance()->BroadcastPacket(packet);
    EXPECT_EQ(ret, RET_OK);
    PeerSocketInfo info;
    char deviceId[] = "softbus";
    info.networkId = deviceId;
    DSoftbusAdapterImpl::GetInstance()->OnBind(SOCKET, info);
    ret = DSoftbusAdapterImpl::GetInstance()->BroadcastPacket(packet);
    EXPECT_EQ(ret, RET_OK);
    RemovePermission();
}

/**
 * @tc.name: TestSendParcel
 * @tc.desc: Test InitSocket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, DsoftbusAdapterTest04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    char name[DEVICE_NAME_SIZE_MAX] { SERVER_SESSION_NAME };
    char pkgName[PKG_NAME_SIZE_MAX] { FI_PKG_NAME };
    SocketInfo info {
        .name = name,
        .pkgName = pkgName,
        .dataType = DATA_TYPE_BYTES
    };
    int32_t socket = 1;
    int32_t ret = DSoftbusAdapterImpl::GetInstance()->InitSocket(info, SOCKET_CLIENT, socket);
    ASSERT_EQ(ret, RET_ERR);
    ret = DSoftbusAdapterImpl::GetInstance()->InitSocket(info, SOCKET_SERVER, socket);
    ASSERT_EQ(ret, RET_ERR);
    RemovePermission();
}

/**
 * @tc.name: TestCheckDeviceOnline
 * @tc.desc: Test CheckDeviceOnline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, DsoftbusAdapterTest05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    bool ret = DSoftbusAdapterImpl::GetInstance()->CheckDeviceOnline("networkId");
    EXPECT_FALSE(ret);
    std::string NetworkId = GetLocalNetworkId();
    ret = DSoftbusAdapterImpl::GetInstance()->CheckDeviceOnline(NetworkId);
    EXPECT_FALSE(ret);
    RemovePermission();
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS