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
#include "device_cooperate_softbus_define.h"
#include "input_device_cooperate_sm.h"
#include "input_device_cooperate_util.h"
#include "mmi_log.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
std::shared_ptr<DeviceCooperateSoftbusAdapter> g_instance = nullptr;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "DeviceCooperateSoftbusAdapter" };
constexpr int32_t DINPUT_LINK_TYPE_MAX = 4;
const SessionAttribute g_sessionAttr = {
    .dataType = SessionType::TYPE_BYTES,
    .linkTypeNum = DINPUT_LINK_TYPE_MAX,
    .linkType = {
        LINK_TYPE_WIFI_WLAN_2G,
        LINK_TYPE_WIFI_WLAN_5G,
        LINK_TYPE_WIFI_P2P,
        LINK_TYPE_BR
    }
};

void ResponseStartRemoteCooperate(int32_t sessionId, const JsonParser& parser)
{
    CALL_DEBUG_ENTER;
    cJSON* deviceId = cJSON_GetObjectItemCaseSensitive(parser.json_, MMI_SOFTBUS_KEY_LOCAL_DEVICE_ID);
    if (!cJSON_IsString(deviceId)) {
        MMI_HILOGE("OnBytesReceived cmdType is TRANS_SINK_MSG_ONPREPARE, data type is error");
        return;
    }
    InputDevCooSM->StartRemoteCooperate(deviceId->valuestring);
}

void ResponseStartRemoteCooperateResult(int32_t sessionId, const JsonParser& parser)
{
    CALL_DEBUG_ENTER;
    cJSON* result = cJSON_GetObjectItemCaseSensitive(parser.json_, MMI_SOFTBUS_KEY_RESULT);
    cJSON* dhid = cJSON_GetObjectItemCaseSensitive(parser.json_, MMI_SOFTBUS_KEY_START_DHID);
    cJSON* x = cJSON_GetObjectItemCaseSensitive(parser.json_, MMI_SOFTBUS_KEY_POINTER_X);
    cJSON* y = cJSON_GetObjectItemCaseSensitive(parser.json_, MMI_SOFTBUS_KEY_POINTER_Y);
    if (!cJSON_IsBool(result) || !cJSON_IsString(dhid) || !cJSON_IsNumber(x) || !cJSON_IsNumber(y)) {
        MMI_HILOGE("OnBytesReceived cmdType is TRANS_SINK_MSG_ONPREPARE, data type is error");
        return;
    }
    InputDevCooSM->StartRemoteCooperateResult(cJSON_IsTrue(result), dhid->valuestring, x->valueint, y->valueint);
}

void ResponseStopRemoteCooperate(int32_t sessionId, const JsonParser& parser)
{
    InputDevCooSM->StopRemoteCooperate();
}

void ResponseStopRemoteCooperateResult(int32_t sessionId, const JsonParser& parser)
{
    CALL_DEBUG_ENTER;
    cJSON* result = cJSON_GetObjectItemCaseSensitive(parser.json_, MMI_SOFTBUS_KEY_RESULT);

    if (!cJSON_IsBool(result)) {
        MMI_HILOGE("OnBytesReceived cmdType is TRANS_SINK_MSG_ONPREPARE, data type is error");
        return;
    }
    InputDevCooSM->StopRemoteCooperateResult(cJSON_IsTrue(result));
}

void ResponseStartCooperateOtherResult(int32_t sessionId, const JsonParser& parser)
{
    CALL_DEBUG_ENTER;
    cJSON* deviceId = cJSON_GetObjectItemCaseSensitive(parser.json_, MMI_SOFTBUS_KEY_OTHER_DEVICE_ID);

    if (!cJSON_IsString(deviceId)) {
        MMI_HILOGE("OnBytesReceived cmdType is TRANS_SINK_MSG_ONPREPARE, data type is error");
        return;
    }
    InputDevCooSM->StartCooperateOtherResult(deviceId->valuestring);
}
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
    std::string networkId = GetLocalDeviceId();
    if (networkId.empty()) {
        MMI_HILOGE("Local networkid is empty");
        return RET_ERR;
    }
    localSessionName_ = SESSION_NAME + networkId.substr(0, INTERCEPT_STRING_LENGTH);
    int32_t ret = CreateSessionServer(MMI_DINPUT_PKG_NAME, localSessionName_.c_str(), &sessListener_);
    if (ret != RET_OK) {
        MMI_HILOGE("Create session server failed, error code:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

DeviceCooperateSoftbusAdapter::~DeviceCooperateSoftbusAdapter()
{
    Release();
}

void DeviceCooperateSoftbusAdapter::Release()
{
    CALL_INFO_TRACE;
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    std::for_each(sessionDevMap_.begin(), sessionDevMap_.end(), [](auto item) {
        CloseSession(item.second);
        MMI_HILOGD("Close session success");
    });
    int32_t ret = RemoveSessionServer(MMI_DINPUT_PKG_NAME, localSessionName_.c_str());
    MMI_HILOGD("RemoveSessionServer ret:%{public}d", ret);
    sessionDevMap_.clear();
    channelStatusMap_.clear();
}

bool DeviceCooperateSoftbusAdapter::CheckDeviceSessionState(const std::string &devId)
{
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    if (sessionDevMap_.find(devId) == sessionDevMap_.end()) {
        MMI_HILOGE("Check session state error");
        return false;
    }
    return true;
}

int32_t DeviceCooperateSoftbusAdapter::OpenInputSoftbus(const std::string &remoteDevId)
{
    CALL_INFO_TRACE;
    if (CheckDeviceSessionState(remoteDevId)) {
        MMI_HILOGD("Softbus session has already  opened");
        return RET_OK;
    }

    int32_t ret = Init();
    if (ret != RET_OK) {
        MMI_HILOGE("Init failed");
        return RET_ERR;
    }

    std::string peerSessionName = SESSION_NAME + remoteDevId.substr(0, INTERCEPT_STRING_LENGTH);
    int32_t sessionId = OpenSession(localSessionName_.c_str(), peerSessionName.c_str(), remoteDevId.c_str(),
        GROUP_ID.c_str(), &g_sessionAttr);
    if (sessionId < 0) {
        MMI_HILOGE("OpenSession failed");
        return RET_ERR;
    }
    return WaitSessionOpend(remoteDevId, sessionId);
}

int32_t DeviceCooperateSoftbusAdapter::WaitSessionOpend(const std::string &remoteDevId, int32_t sessionId)
{
    CALL_INFO_TRACE;
    std::unique_lock<std::mutex> waitLock(operationMutex_);
    sessionDevMap_[remoteDevId] = sessionId;
    auto status = openSessionWaitCond_.wait_for(waitLock, std::chrono::seconds(SESSION_WAIT_TIMEOUT_SECOND),
        [this, remoteDevId] () { return channelStatusMap_[remoteDevId]; });
    if (!status) {
        MMI_HILOGE("OpenSession timeout");
        return RET_ERR;
    }
    channelStatusMap_[remoteDevId] = false;
    return RET_OK;
}

void DeviceCooperateSoftbusAdapter::CloseInputSoftbus(const std::string &remoteDevId)
{
    CALL_INFO_TRACE;
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    if (sessionDevMap_.find(remoteDevId) == sessionDevMap_.end()) {
        MMI_HILOGI("SessionDevIdMap not find");
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
    if (sessionDevMap_.find(remoteDeviceId) == sessionDevMap_.end()) {
        MMI_HILOGE("Start remote cooperate error, not find this device");
        return RET_ERR;
    }
    int32_t sessionId = sessionDevMap_[remoteDeviceId];
    cJSON *jsonStr = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonStr, MMI_SOFTBUS_KEY_CMD_TYPE, cJSON_CreateNumber(REMOTE_COOPERATE_START));
    cJSON_AddItemToObject(jsonStr, MMI_SOFTBUS_KEY_LOCAL_DEVICE_ID, cJSON_CreateString(localDeviceId.c_str()));
    cJSON_AddItemToObject(jsonStr, MMI_SOFTBUS_KEY_SESSION_ID, cJSON_CreateNumber(sessionId));
    char *smsg = cJSON_Print(jsonStr);
    cJSON_Delete(jsonStr);
    int32_t ret = SendMsg(sessionId, smsg);
    cJSON_free(smsg);
    if (ret != RET_OK) {
        MMI_HILOGE("Start remote cooperate send session msg failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t DeviceCooperateSoftbusAdapter::StartRemoteCooperateResult(const std::string &remoteDeviceId, bool isSuccess,
    const std::string &startDhid, int32_t xPercent, int32_t yPercent)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    if (sessionDevMap_.find(remoteDeviceId) == sessionDevMap_.end()) {
        MMI_HILOGE("Stop remote cooperate error, not find this device");
        return RET_ERR;
    }
    int32_t sessionId = sessionDevMap_[remoteDeviceId];
    cJSON *jsonStr = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonStr, MMI_SOFTBUS_KEY_CMD_TYPE, cJSON_CreateNumber(REMOTE_COOPERATE_START_RES));
    cJSON_AddItemToObject(jsonStr, MMI_SOFTBUS_KEY_RESULT, cJSON_CreateBool(isSuccess));
    cJSON_AddItemToObject(jsonStr, MMI_SOFTBUS_KEY_START_DHID, cJSON_CreateString(startDhid.c_str()));
    cJSON_AddItemToObject(jsonStr, MMI_SOFTBUS_KEY_POINTER_X, cJSON_CreateNumber(xPercent));
    cJSON_AddItemToObject(jsonStr, MMI_SOFTBUS_KEY_POINTER_Y, cJSON_CreateNumber(yPercent));
    cJSON_AddItemToObject(jsonStr, MMI_SOFTBUS_KEY_SESSION_ID, cJSON_CreateNumber(sessionId));
    char *smsg = cJSON_Print(jsonStr);
    cJSON_Delete(jsonStr);
    int32_t ret = SendMsg(sessionId, smsg);
    cJSON_free(smsg);
    if (ret != RET_OK) {
        MMI_HILOGE("Start remote cooperate result send session msg failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t DeviceCooperateSoftbusAdapter::StopRemoteCooperate(const std::string &remoteDeviceId)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    if (sessionDevMap_.find(remoteDeviceId) == sessionDevMap_.end()) {
        MMI_HILOGE("Stop remote cooperate error, not find this device");
        return RET_ERR;
    }
    int32_t sessionId = sessionDevMap_[remoteDeviceId];
    cJSON *jsonStr = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonStr, MMI_SOFTBUS_KEY_CMD_TYPE, cJSON_CreateNumber(REMOTE_COOPERATE_STOP));
    cJSON_AddItemToObject(jsonStr, MMI_SOFTBUS_KEY_SESSION_ID, cJSON_CreateNumber(sessionId));
    char *smsg = cJSON_Print(jsonStr);
    cJSON_Delete(jsonStr);
    int32_t ret = SendMsg(sessionId, smsg);
    cJSON_free(smsg);
    if (ret != RET_OK) {
        MMI_HILOGE("Stop remote cooperate send session msg failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t DeviceCooperateSoftbusAdapter::StopRemoteCooperateResult(const std::string &remoteDeviceId, bool isSuccess)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    if (sessionDevMap_.find(remoteDeviceId) == sessionDevMap_.end()) {
        MMI_HILOGE("Stop remote cooperate result error, not find this device");
        return RET_ERR;
    }
    int32_t sessionId = sessionDevMap_[remoteDeviceId];
    cJSON *jsonStr = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonStr, MMI_SOFTBUS_KEY_CMD_TYPE, cJSON_CreateNumber(REMOTE_COOPERATE_STOP_RES));
    cJSON_AddItemToObject(jsonStr, MMI_SOFTBUS_KEY_RESULT, cJSON_CreateBool(isSuccess));
    cJSON_AddItemToObject(jsonStr, MMI_SOFTBUS_KEY_SESSION_ID, cJSON_CreateNumber(sessionId));
    char *smsg = cJSON_Print(jsonStr);
    cJSON_Delete(jsonStr);
    int32_t ret = SendMsg(sessionId, smsg);
    cJSON_free(smsg);
    if (ret != RET_OK) {
        MMI_HILOGE("Stop remote cooperate result send session msg failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t DeviceCooperateSoftbusAdapter::StartCooperateOtherResult(const std::string &remoteDeviceId,
    const std::string &srcNetworkId)
{
    CALL_DEBUG_ENTER;
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    if (sessionDevMap_.find(remoteDeviceId) == sessionDevMap_.end()) {
        MMI_HILOGE("Start cooperate other result error, not find this device");
        return RET_ERR;
    }
    int32_t sessionId = sessionDevMap_[remoteDeviceId];
    cJSON *jsonStr = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonStr, MMI_SOFTBUS_KEY_CMD_TYPE, cJSON_CreateNumber(REMOTE_COOPERATE_STOP_OTHER_RES));
    cJSON_AddItemToObject(jsonStr, MMI_SOFTBUS_KEY_OTHER_DEVICE_ID, cJSON_CreateString(srcNetworkId.c_str()));
    cJSON_AddItemToObject(jsonStr, MMI_SOFTBUS_KEY_SESSION_ID, cJSON_CreateNumber(sessionId));
    char *smsg = cJSON_Print(jsonStr);
    cJSON_Delete(jsonStr);
    int32_t ret = SendMsg(sessionId, smsg);
    cJSON_free(smsg);
    if (ret != RET_OK) {
        MMI_HILOGE("Start cooperate other result send session msg failed");
        return RET_ERR;
    }
    return RET_OK;
}

void DeviceCooperateSoftbusAdapter::HandleSessionData(int32_t sessionId, const std::string& message)
{
    JsonParser parser;
    parser.json_ = cJSON_Parse(message.c_str());
    if (!cJSON_IsObject(parser.json_)) {
        MMI_HILOGE("Parser.json_ is not object");
        return;
    }
    cJSON* comType = cJSON_GetObjectItemCaseSensitive(parser.json_, MMI_SOFTBUS_KEY_CMD_TYPE);
    if (!cJSON_IsNumber(comType)) {
        MMI_HILOGE("OnBytesReceived cmdType is not number type");
        return;
    }
    MMI_HILOGD("valueint: %{public}d", comType->valueint);
    switch (comType->valueint) {
        case REMOTE_COOPERATE_START: {
            ResponseStartRemoteCooperate(sessionId, parser);
            break;
        }
        case REMOTE_COOPERATE_START_RES: {
            ResponseStartRemoteCooperateResult(sessionId, parser);
            break;
        }
        case REMOTE_COOPERATE_STOP: {
            ResponseStopRemoteCooperate(sessionId, parser);
            break;
        }
        case REMOTE_COOPERATE_STOP_RES: {
            ResponseStopRemoteCooperateResult(sessionId, parser);
            break;
        }
        case REMOTE_COOPERATE_STOP_OTHER_RES: {
            ResponseStartCooperateOtherResult(sessionId, parser);
            break;
        }
        default: {
            MMI_HILOGE("OnBytesReceived cmdType is undefined");
            break;
        }
    }
}

void DeviceCooperateSoftbusAdapter::OnBytesReceived(int32_t sessionId, const void *data, uint32_t dataLen)
{
    MMI_HILOGD("dataLen:%{public}d", dataLen);
    if (sessionId < 0 || data == nullptr || dataLen <= 0) {
        MMI_HILOGE("Param check failed");
        return;
    }
    std::string message = std::string(static_cast<const char *>(data), dataLen);
    HandleSessionData(sessionId, message);
}

int32_t DeviceCooperateSoftbusAdapter::SendMsg(int32_t sessionId, const std::string &message)
{
    CALL_DEBUG_ENTER;
    if (message.size() > MSG_MAX_SIZE) {
        MMI_HILOGW("error:message.size() > MSG_MAX_SIZE msessage size:%{public}zu", message.size());
        return RET_ERR;
    }
    return SendBytes(sessionId, message.c_str(), strlen(message.c_str()));
}

std::string DeviceCooperateSoftbusAdapter::FindDevice(int32_t sessionId)
{
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    auto find_item = std::find_if(sessionDevMap_.begin(), sessionDevMap_.end(),
        [sessionId](const std::map<std::string, int>::value_type item) {
        return item.second == sessionId;
    });
    if (find_item == sessionDevMap_.end()) {
        MMI_HILOGE("FindDevice error");
        return {};
    }
    return find_item->first;
}

int32_t DeviceCooperateSoftbusAdapter::OnSessionOpened(int32_t sessionId, int32_t result)
{
    CALL_INFO_TRACE;
    char peerDevId[DEVICE_ID_SIZE_MAX] = {};
    int32_t getPeerDeviceIdResult = GetPeerDeviceId(sessionId, peerDevId, sizeof(peerDevId));
    MMI_HILOGD("Get peer device id ret:%{public}d", getPeerDeviceIdResult);
    if (result != RET_OK) {
        std::string deviceId = FindDevice(sessionId);
        MMI_HILOGE("Session open failed result:%{public}d", result);
        std::unique_lock<std::mutex> sessionLock(operationMutex_);
        if (sessionDevMap_.find(deviceId) != sessionDevMap_.end()) {
            sessionDevMap_.erase(deviceId);
        }
        if (getPeerDeviceIdResult == RET_OK) {
            channelStatusMap_[peerDevId] = true;
        }
        openSessionWaitCond_.notify_all();
        return RET_OK;
    }

    int32_t sessionSide = GetSessionSide(sessionId);
    MMI_HILOGI("session open succeed, sessionId:%{public}d, sessionSide:%{public}d(1 is client side)",
        sessionId, sessionSide);
    std::lock_guard<std::mutex> notifyLock(operationMutex_);
    if (sessionSide == SESSION_SIDE_SERVER) {
        if (getPeerDeviceIdResult == RET_OK) {
            sessionDevMap_[peerDevId] = sessionId;
        }
    } else {
        if (getPeerDeviceIdResult == RET_OK) {
            channelStatusMap_[peerDevId] = true;
        }
        openSessionWaitCond_.notify_all();
    }
    return RET_OK;
}

void DeviceCooperateSoftbusAdapter::OnSessionClosed(int32_t sessionId)
{
    CALL_DEBUG_ENTER;
    std::string deviceId = FindDevice(sessionId);
    std::unique_lock<std::mutex> sessionLock(operationMutex_);
    if (sessionDevMap_.find(deviceId) != sessionDevMap_.end()) {
        sessionDevMap_.erase(deviceId);
    }
    if (GetSessionSide(sessionId) != 0) {
        channelStatusMap_.erase(deviceId);
    }
    InputDevCooSM->Reset(deviceId);
}
} // namespace MMI
} // namespace OHOS
