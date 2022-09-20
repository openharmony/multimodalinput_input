/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "device_cooperate_softbus_adapter.h"

#include <chrono>
#include <thread>

#include "softbus_bus_center.h"
#include "softbus_common.h"

#include "config_multimodal.h"
#include "input_device_cooperate_util.h"
#include "mmi_log.h"
#include "mmi_softbus_define.h"
#include "util.h"
#include "multimodal_input_connect_define.h"
#include "input_device_cooperate_sm.h"

namespace OHOS {
namespace MMI {
namespace {
std::shared_ptr<DeviceCooperateSoftbusAdapter> g_instance = nullptr;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "DeviceCooperateSoftbusAdapter"};
const int32_t DINPUT_LINK_TYPE_MAX = 4;
static SessionAttribute g_sessionAttr = {
    .dataType = SessionType::TYPE_BYTES,
    .linkTypeNum = DINPUT_LINK_TYPE_MAX,
    .linkType = {
        LINK_TYPE_WIFI_WLAN_2G,
        LINK_TYPE_WIFI_WLAN_5G,
        LINK_TYPE_WIFI_P2P,
        LINK_TYPE_BR
    }
};
} // namespace

static int32_t SessionOpened(int32_t sessionId, int32_t result)
{
    return DevCooperateSoftbusAdapter->OnSessionOpened(sessionId, result);
}

static void SessionClosed(int32_t sessionId)
{
    DevCooperateSoftbusAdapter->OnSessionClosed(sessionId);
}

static void BytesReceived(int32_t sessionId, const void *data, uint32_t dataLen)
{
    DevCooperateSoftbusAdapter->OnBytesReceived(sessionId, data, dataLen);
}

static void MessageReceived(int32_t sessionId, const void *data, uint32_t dataLen)
{
    (void)sessionId;
    (void)data;
    (void)dataLen;
}

static void StreamReceived(int32_t sessionId, const StreamData *data, const StreamData *ext,
    const StreamFrameInfo *param)
{
    (void)sessionId;
    (void)data;
    (void)ext;
    (void)param;
}

int32_t DeviceCooperateSoftbusAdapter::Init()
{
    CALL_INFO_TRACE;
    sessListener_ = {
        .OnSessionOpened = SessionOpened,
        .OnSessionClosed = SessionClosed,
        .OnBytesReceived = BytesReceived,
        .OnMessageReceived = MessageReceived,
        .OnStreamReceived = StreamReceived
    };

    std::string networkId;
    GetLocalDeviceId(networkId);
    if (networkId.empty()) {
        MMI_HILOGE("Local networkid is empty");
        return RET_ERR;
    }
    mySessionName_ = SESSION_NAME + networkId.substr(0, INTERCEPT_STRING_LENGTH);
    int32_t ret = CreateSessionServer(MMI_DSOFTBUS_PKG_NAME, mySessionName_.c_str(), &sessListener_);
    if (ret != RET_OK) {
        MMI_HILOGE("Init create session server failed, error code %{public}d.", ret);
        return RET_ERR;
    }
    return RET_OK;
}

void DeviceCooperateSoftbusAdapter::Release()
{
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    std::for_each(sessionDevMap_.begin(), sessionDevMap_.end(), [](auto item) { CloseSession(item.second); });
    (void)RemoveSessionServer(MMI_DSOFTBUS_PKG_NAME, mySessionName_.c_str());
    sessionDevMap_.clear();
    channelStatusMap_.clear();
}

int32_t DeviceCooperateSoftbusAdapter::CheckDeviceSessionState(const std::string &devId)
{
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    if (sessionDevMap_.count(devId) != 0) {
        return RET_OK;
    } else {
        MMI_HILOGE("Check session state error");
        return RET_ERR;
    }
}

int32_t DeviceCooperateSoftbusAdapter::OpenInputSoftbus(const std::string &remoteDevId)
{
    CALL_INFO_TRACE;
    int32_t ret = CheckDeviceSessionState(remoteDevId);
    if (ret == RET_OK) {
        MMI_HILOGD("Softbus session has already opened");
        return RET_OK;
    }

    ret = Init();
    if (ret != RET_OK) {
        MMI_HILOGE("CreateSessionServer failed.");
        return RET_ERR;
    }

    std::string peerSessionName = SESSION_NAME + remoteDevId.substr(0, INTERCEPT_STRING_LENGTH);
    MMI_HILOGI("OpenInputSoftbus peerSessionName:%{public}s", peerSessionName.c_str());

    int sessionId = OpenSession(mySessionName_.c_str(), peerSessionName.c_str(), remoteDevId.c_str(),
        GROUP_ID.c_str(), &g_sessionAttr);
    if (sessionId < 0) {
        MMI_HILOGE("OpenSession failed");
        return RET_ERR;
    }
    {
        std::unique_lock<std::mutex> sessionLock(operationMutex_);
        sessionDevMap_[remoteDevId] = sessionId;
    }

    MMI_HILOGI("Wait for channel session opened.");
    {
        std::unique_lock<std::mutex> waitLock(operationMutex_);
        auto status = openSessionWaitCond_.wait_for(waitLock, std::chrono::seconds(SESSION_WAIT_TIMEOUT_SECOND),
            [this, remoteDevId] () { return channelStatusMap_[remoteDevId]; });
        if (!status) {
            MMI_HILOGE("OpenSession timeout");
            return RET_ERR;
        }
    }
    channelStatusMap_[remoteDevId] = false;
    MMI_HILOGI("OpenSession finish");
    return RET_OK;
}

void DeviceCooperateSoftbusAdapter::CloseInputSoftbus(const std::string &remoteDevId)
{
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    if (sessionDevMap_.count(remoteDevId) == 0) {
        MMI_HILOGI("SessionDevIdMap Not find");
        return;
    }
    int32_t sessionId = sessionDevMap_[remoteDevId];

    CloseSession(sessionId);
    sessionDevMap_.erase(remoteDevId);
    channelStatusMap_.erase(remoteDevId);
}

std::shared_ptr<DeviceCooperateSoftbusAdapter> DeviceCooperateSoftbusAdapter::GetInstance()
{
    static std::once_flag flag;
    std::call_once(flag, [&]() {
        g_instance.reset(new (std::nothrow) DeviceCooperateSoftbusAdapter());
    });
    return g_instance;
}


int32_t DeviceCooperateSoftbusAdapter::StartRemoteCooperate(const std::string &localDeviceId,
    const std::string &remoteDeviceId)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    if (sessionDevMap_.count(remoteDeviceId) > 0) {
        int32_t sessionId = sessionDevMap_[remoteDeviceId];
        nlohmann::json jsonStr;
        jsonStr[MMI_SOFTBUS_KEY_CMD_TYPE] = REMOTE_COOPERATE_START;
        jsonStr[MMI_SOFTBUS_KEY_LOCAL_DEVICE_ID] = localDeviceId;
        jsonStr[MMI_SOFTBUS_KEY_SESSION_ID] = sessionId;
        std::string smsg = jsonStr.dump();
        int32_t ret = SendMsg(sessionId, smsg);
        if (ret != RET_OK) {
            MMI_HILOGE("Start remote cooperate send session msg failed");
            return RET_ERR;
        }
        return RET_OK;
    } else {
        MMI_HILOGE("Start remote cooperate error, not find this device.");
        return RET_ERR;
    }
}

int32_t DeviceCooperateSoftbusAdapter::StartRemoteCooperateResult(const std::string &remoteDeviceId, bool isSuccess,
    const std::string &startDhid, int32_t xPercent, int32_t yPercent)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    if (sessionDevMap_.count(remoteDeviceId) > 0) {
        int32_t sessionId = sessionDevMap_[remoteDeviceId];
        nlohmann::json jsonStr;
        jsonStr[MMI_SOFTBUS_KEY_CMD_TYPE] = REMOTE_COOPERATE_START_RES;
        jsonStr[MMI_SOFTBUS_KEY_RESULT] = isSuccess;
        jsonStr[MMI_SOFTBUS_KEY_START_DHID] = startDhid;
        jsonStr[MMI_SOFTBUS_KEY_POINTER_X] = xPercent;
        jsonStr[MMI_SOFTBUS_KEY_POINTER_Y] = yPercent;
        jsonStr[MMI_SOFTBUS_KEY_SESSION_ID] = sessionId;
        std::string smsg = jsonStr.dump();
        int32_t ret = SendMsg(sessionId, smsg);
        if (ret != RET_OK) {
            MMI_HILOGE("Start remote cooperate result send session msg failed");
            return RET_ERR;
        }
        return RET_OK;
    } else {
        MMI_HILOGE("Start remote cooperate result error, not find this device.");
        return RET_ERR;
    }
}

int32_t DeviceCooperateSoftbusAdapter::StopRemoteCooperate(const std::string &remoteDeviceId)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    if (sessionDevMap_.count(remoteDeviceId) > 0) {
        int32_t sessionId = sessionDevMap_[remoteDeviceId];
        nlohmann::json jsonStr;
        jsonStr[MMI_SOFTBUS_KEY_CMD_TYPE] = REMOTE_COOPERATE_STOP;
        jsonStr[MMI_SOFTBUS_KEY_SESSION_ID] = sessionId;
        std::string smsg = jsonStr.dump();
        int32_t ret = SendMsg(sessionId, smsg);
        if (ret != RET_OK) {
            MMI_HILOGE("Stop remote cooperate send session msg failed");
            return RET_ERR;
        }
        return RET_OK;
    } else {
        MMI_HILOGE("Stop remote cooperate error, not find this device.");
        return RET_ERR;
    }
}

int32_t DeviceCooperateSoftbusAdapter::StopRemoteCooperateResult(const std::string &remoteDeviceId, bool isSuccess)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    if (sessionDevMap_.count(remoteDeviceId) > 0) {
        int32_t sessionId = sessionDevMap_[remoteDeviceId];
        nlohmann::json jsonStr;
        jsonStr[MMI_SOFTBUS_KEY_CMD_TYPE] = REMOTE_COOPERATE_STOP_RES;
        jsonStr[MMI_SOFTBUS_KEY_RESULT] = isSuccess;
        jsonStr[MMI_SOFTBUS_KEY_SESSION_ID] = sessionId;
        std::string smsg = jsonStr.dump();
        int32_t ret = SendMsg(sessionId, smsg);
        if (ret != RET_OK) {
            MMI_HILOGE("Stop remote cooperate result send session msg failed");
            return RET_ERR;
        }
        return RET_OK;
    } else {
        MMI_HILOGE("Stop remote cooperate result error, not find this device.");
        return RET_ERR;
    }
}

int32_t DeviceCooperateSoftbusAdapter::StartCooperateOtherResult(const std::string &remoteDeviceId,
    const std::string &srcNetworkId)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    if (sessionDevMap_.count(remoteDeviceId) > 0) {
        int32_t sessionId = sessionDevMap_[remoteDeviceId];
        nlohmann::json jsonStr;
        jsonStr[MMI_SOFTBUS_KEY_CMD_TYPE] = REMOTE_COOPERATE_STOP_OTHER_RES;
        jsonStr[MMI_SOFTBUS_KEY_OTHER_DEVICE_ID] = srcNetworkId;
        jsonStr[MMI_SOFTBUS_KEY_SESSION_ID] = sessionId;
        std::string smsg = jsonStr.dump();
        int32_t ret = SendMsg(sessionId, smsg);
        if (ret != RET_OK) {
            MMI_HILOGE("Start cooperate other result send session msg failed");
            return RET_ERR;
        }
        return RET_OK;
    } else {
        MMI_HILOGE("Start cooperate other result error, not find this device.");
        return RET_ERR;
    }
}

void DeviceCooperateSoftbusAdapter::HandleSessionData(int32_t sessionId, const std::string& message)
{
    nlohmann::json recMsg = nlohmann::json::parse(message);
    if (recMsg.is_discarded()) {
        MMI_HILOGE("OnBytesReceived jsonStr error.");
        return;
    }

    if (recMsg.contains(MMI_SOFTBUS_KEY_CMD_TYPE) != true) {
        MMI_HILOGE("OnBytesReceived message:%{public}s is error, not contain cmdType.", message.c_str());
        return;
    }

    if (recMsg[MMI_SOFTBUS_KEY_CMD_TYPE].is_number() != true) {
        MMI_HILOGE("OnBytesReceived cmdType is not number type.");
        return;
    }

    int cmdType = recMsg[MMI_SOFTBUS_KEY_CMD_TYPE];
    switch (cmdType) {
        case REMOTE_COOPERATE_START: {
            NotifyResponseStartRemoteCooperate(sessionId, recMsg);
            break;
        }
        case REMOTE_COOPERATE_START_RES: {
            NotifyResponseStartRemoteCooperateResult(sessionId, recMsg);
            break;
        }
        case REMOTE_COOPERATE_STOP: {
            NotifyResponseStopRemoteCooperate(sessionId, recMsg);
            break;
        }
        case REMOTE_COOPERATE_STOP_RES: {
            NotifyResponseStopRemoteCooperateResult(sessionId, recMsg);
            break;
        }
        case REMOTE_COOPERATE_STOP_OTHER_RES: {
            NotifyResponseStartCooperateOtherResult(sessionId, recMsg);
            break;
        }
        default: {
            MMI_HILOGE("OnBytesReceived cmdType is undefined.");
            break;
        }
    }
}

void DeviceCooperateSoftbusAdapter::OnBytesReceived(int32_t sessionId, const void *data, uint32_t dataLen)
{
    MMI_HILOGD("OnBytesReceived, sessionId:%{public}d, dataLen:%{public}d", sessionId, dataLen);
    if (sessionId < 0 || data == nullptr || dataLen <= 0) {
        MMI_HILOGE("OnBytesReceived param check failed");
        return;
    }

    uint8_t *buf = (uint8_t *)calloc(dataLen + 1, sizeof(uint8_t));
    if (buf == nullptr) {
        MMI_HILOGE("OnBytesReceived: malloc memory failed");
        return;
    }

    if (memcpy_s(buf, dataLen + 1, (const uint8_t *)data, dataLen) != RET_OK) {
        MMI_HILOGE("OnBytesReceived: memcpy memory failed");
        free(buf);
        return;
    }

    std::string message(buf, buf + dataLen);
    MMI_HILOGD("OnBytesReceived message:%{public}s.", message.c_str());
    HandleSessionData(sessionId, message);

    free(buf);
    MMI_HILOGD("OnBytesReceived completed");
    return;
}

// send message by sessionId (channel opened)
int32_t DeviceCooperateSoftbusAdapter::SendMsg(int32_t sessionId, std::string &message)
{
    CALL_DEBUG_ENTER;
    if (message.size() > MSG_MAX_SIZE) {
        MMI_HILOGW("error: message.size() > MSG_MAX_SIZE");
        return RET_ERR;
    }
    uint8_t *buf = (uint8_t *)calloc((MSG_MAX_SIZE), sizeof(uint8_t));
    if (buf == nullptr) {
        MMI_HILOGE("malloc memory failed");
        return RET_ERR;
    }
    int32_t outLen = 0;
    if (memcpy_s(buf, MSG_MAX_SIZE, (const uint8_t *)message.c_str(), message.size()) != RET_OK) {
        MMI_HILOGE("memcpy memory failed");
        free(buf);
        return RET_ERR;
    }
    outLen = (int32_t)message.size();
    int32_t ret = SendBytes(sessionId, buf, outLen);
    free(buf);
    return ret;
}

std::string DeviceCooperateSoftbusAdapter::FindDeviceBySession(int32_t sessionId)
{
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    auto find_item = std::find_if(sessionDevMap_.begin(), sessionDevMap_.end(),
        [sessionId](const std::map<std::string, int>::value_type item) {
        return item.second == sessionId;
    });

    std::string devId = "";
    if (find_item != sessionDevMap_.end()) {
        devId = (*find_item).first;
    } else {
        MMI_HILOGE("findKeyByValue error.");
    }
    return devId;
}

int32_t DeviceCooperateSoftbusAdapter::OnSessionOpened(int32_t sessionId, int32_t result)
{
    CALL_INFO_TRACE;
    char peerDevId[DEVICE_ID_SIZE_MAX] = "";
    int32_t ret = GetPeerDeviceId(sessionId, peerDevId, sizeof(peerDevId));
    if (result != RET_OK) {
        std::string deviceId = FindDeviceBySession(sessionId);
        MMI_HILOGE("Session open failed result: %{public}d", result);
        std::unique_lock<std::mutex> sessionLock(operationMutex_);
        if (sessionDevMap_.count(deviceId) > 0) {
            sessionDevMap_.erase(deviceId);
        }
        channelStatusMap_[peerDevId] = true;
        openSessionWaitCond_.notify_all();
        return RET_OK;
    }

    int32_t sessionSide = GetSessionSide(sessionId);
    MMI_HILOGI("session open succeed, sessionId:%{public}d, sessionSide:%{public}d(1 is client side)",
        sessionId, sessionSide);
    // 0 is server
    if (sessionSide == SESSION_SIDE_SERVER){
        if (ret == RET_OK) {
            sessionDevMap_[peerDevId] = sessionId;
        }
    } else {
        std::lock_guard<std::mutex> notifyLock(operationMutex_);
        channelStatusMap_[peerDevId] = true;
        openSessionWaitCond_.notify_all();
    }
    return RET_OK;
}

void DeviceCooperateSoftbusAdapter::OnSessionClosed(int32_t sessionId)
{
    CALL_DEBUG_ENTER;
    std::string deviceId = FindDeviceBySession(sessionId);
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    if (sessionDevMap_.count(deviceId) > 0) {
        sessionDevMap_.erase(deviceId);
    }
    // 0 is server
    if (GetSessionSide(sessionId) != 0) {
        channelStatusMap_.erase(deviceId);
    }
}

void DeviceCooperateSoftbusAdapter::NotifyResponseStartRemoteCooperate(int32_t sessionId, const nlohmann::json &recMsg)
{
    CALL_DEBUG_ENTER;
    if (!recMsg[MMI_SOFTBUS_KEY_LOCAL_DEVICE_ID].is_string()) {
        MMI_HILOGE("OnBytesReceived cmdType is TRANS_SINK_MSG_ONPREPARE, data type is error.");
        return;
    }
    InputDevCooSM->StartRemoteCooperate(recMsg[MMI_SOFTBUS_KEY_LOCAL_DEVICE_ID]);
}

void DeviceCooperateSoftbusAdapter::NotifyResponseStartRemoteCooperateResult(int32_t sessionId, const nlohmann::json &recMsg)
{
    CALL_DEBUG_ENTER;
    if (!recMsg[MMI_SOFTBUS_KEY_RESULT].is_boolean() ||
        !recMsg[MMI_SOFTBUS_KEY_START_DHID].is_string() ||
        !recMsg[MMI_SOFTBUS_KEY_POINTER_X].is_number() ||
        !recMsg[MMI_SOFTBUS_KEY_POINTER_Y].is_number()) {
        MMI_HILOGE("OnBytesReceived cmdType is TRANS_SINK_MSG_ONPREPARE, data type is error.");
        return;
    }
    bool result = recMsg[MMI_SOFTBUS_KEY_RESULT];
    std::string dhid = recMsg[MMI_SOFTBUS_KEY_START_DHID];
    int32_t x = recMsg[MMI_SOFTBUS_KEY_POINTER_X];
    int32_t y = recMsg[MMI_SOFTBUS_KEY_POINTER_Y];
    InputDevCooSM->StartRemoteCooperateResult(result, dhid, x, y);
}

void DeviceCooperateSoftbusAdapter::NotifyResponseStopRemoteCooperate(int32_t sessionId, const nlohmann::json &recMsg)
{
    InputDevCooSM->StopRemoteCooperate();
}

void DeviceCooperateSoftbusAdapter::NotifyResponseStopRemoteCooperateResult(int32_t sessionId, const nlohmann::json &recMsg)
{
    CALL_DEBUG_ENTER;
    if (!recMsg[MMI_SOFTBUS_KEY_RESULT].is_boolean()) {
        MMI_HILOGE("OnBytesReceived cmdType is TRANS_SINK_MSG_ONPREPARE, data type is error.");
        return;
    }
    InputDevCooSM->StopRemoteCooperateResult(recMsg[MMI_SOFTBUS_KEY_RESULT]);
}

void DeviceCooperateSoftbusAdapter::NotifyResponseStartCooperateOtherResult(int32_t sessionId, const nlohmann::json &recMsg)
{
    CALL_DEBUG_ENTER;
    if (!recMsg[MMI_SOFTBUS_KEY_OTHER_DEVICE_ID].is_string()) {
        MMI_HILOGE("OnBytesReceived cmdType is TRANS_SINK_MSG_ONPREPARE, data type is error.");
        return;
    }
    InputDevCooSM->StartCooperateOtherResult(recMsg[MMI_SOFTBUS_KEY_OTHER_DEVICE_ID]);
}
} // namespace MMI
} // namespace OHOS
