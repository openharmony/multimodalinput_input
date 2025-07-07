/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "multimodal_event_handler.h"

#include <fstream>
#include <config_policy_utils.h>
#include <json/reader.h>
#include <json/value.h>

#include "event_log_helper.h"
#include "input_manager_impl.h"
#include "mmi_client.h"
#include "multimodal_input_connect_manager.h"
#include "proto.h"
#include "tablet_event_input_subscribe_manager.h"
#include "pre_monitor_manager.h"
#include "util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MultimodalEventHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MIN_MULTI_TOUCH_POINT_NUM { 0 };
constexpr int32_t MAX_MULTI_TOUCH_POINT_NUM { 10 };
constexpr int32_t UNKNOWN_MULTI_TOUCH_POINT_NUM { -1 };
constexpr size_t DEFAULT_BUFFER_SIZE { 255 };
}

void OnConnected(const IfMMIClient& client)
{
    CALL_DEBUG_ENTER;
    InputMgrImpl.OnConnected();
    INPUT_DEVICE_IMPL.OnConnected();
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    KeyEventInputSubscribeMgr.OnConnected();
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_SWITCH
    SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.OnConnected();
#endif // OHOS_BUILD_ENABLE_SWITCH
    TABLET_EVENT_INPUT_SUBSCRIBE_MGR.OnConnected();
#ifdef OHOS_BUILD_ENABLE_MONITOR
    IMonitorMgr.OnConnected();
    PRE_MONITOR_MGR.OnConnected();
#endif // OHOS_BUILD_ENABLE_MONITOR
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    InputInterMgr->OnConnected();
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    INPUT_ACTIVE_SUBSCRIBE_MGR.OnConnected();
    DEVICE_CONSUMER.OnConnected();
}

void OnDisconnected(const IfMMIClient &client)
{
    CALL_DEBUG_ENTER;
    InputMgrImpl.OnDisconnected();
    INPUT_DEVICE_IMPL.OnDisconnected();
#ifdef OHOS_BUILD_ENABLE_MONITOR
    IMonitorMgr.OnDisconnected();
#endif // OHOS_BUILD_ENABLE_MONITOR
}

MultimodalEventHandler::MultimodalEventHandler() {}
MultimodalEventHandler::~MultimodalEventHandler() {}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t MultimodalEventHandler::SubscribeKeyEvent(
    const KeyEventInputSubscribeManager::SubscribeKeyEventInfo &subscribeInfo)
{
    CALL_DEBUG_ENTER;
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    return MULTIMODAL_INPUT_CONNECT_MGR->SubscribeKeyEvent(subscribeInfo.GetSubscribeId(),
        subscribeInfo.GetKeyOption());
}

int32_t MultimodalEventHandler::UnsubscribeKeyEvent(int32_t subscribeId)
{
    CALL_DEBUG_ENTER;
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    return MULTIMODAL_INPUT_CONNECT_MGR->UnsubscribeKeyEvent(subscribeId);
}

int32_t MultimodalEventHandler::SubscribeHotkey(
    const KeyEventInputSubscribeManager::SubscribeKeyEventInfo &subscribeInfo)
{
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    return MULTIMODAL_INPUT_CONNECT_MGR->SubscribeHotkey(
        subscribeInfo.GetSubscribeId(), subscribeInfo.GetKeyOption());
}

int32_t MultimodalEventHandler::UnsubscribeHotkey(int32_t subscribeId)
{
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    return MULTIMODAL_INPUT_CONNECT_MGR->UnsubscribeHotkey(subscribeId);
}

int32_t MultimodalEventHandler::InjectEvent(const std::shared_ptr<KeyEvent> keyEvent, bool isNativeInject)
{
    CALL_DEBUG_ENTER;
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    EndLogTraceId(keyEvent->GetId());
    keyEvent->UpdateId();
    LogTracer lt(keyEvent->GetId(), keyEvent->GetEventType(), keyEvent->GetKeyAction());
    if (keyEvent->GetKeyCode() < 0) {
        if (EventLogHelper::IsBetaVersion()) {
            MMI_HILOGE("KeyCode is invalid:%{private}u", keyEvent->GetKeyCode());
        }
        return RET_ERR;
    }
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->InjectKeyEvent(keyEvent, isNativeInject);
    if (ret != 0) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER
int32_t MultimodalEventHandler::SubscribeKeyMonitor(const KeyMonitorOption &keyOption)
{
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    return MULTIMODAL_INPUT_CONNECT_MGR->SubscribeKeyMonitor(keyOption);
}

int32_t MultimodalEventHandler::UnsubscribeKeyMonitor(const KeyMonitorOption &keyOption)
{
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    return MULTIMODAL_INPUT_CONNECT_MGR->UnsubscribeKeyMonitor(keyOption);
}
#endif // OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER

#ifdef OHOS_BUILD_ENABLE_SWITCH
int32_t MultimodalEventHandler::SubscribeSwitchEvent(int32_t subscribeId, int32_t switchType)
{
    CALL_DEBUG_ENTER;
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    return MULTIMODAL_INPUT_CONNECT_MGR->SubscribeSwitchEvent(subscribeId, switchType);
}

int32_t MultimodalEventHandler::UnsubscribeSwitchEvent(int32_t subscribeId)
{
    CALL_DEBUG_ENTER;
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    return MULTIMODAL_INPUT_CONNECT_MGR->UnsubscribeSwitchEvent(subscribeId);
}
#endif // OHOS_BUILD_ENABLE_SWITCH

int32_t MultimodalEventHandler::SubscribeTabletProximity(int32_t subscribeId)
{
    CALL_DEBUG_ENTER;
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    return MULTIMODAL_INPUT_CONNECT_MGR->SubscribeTabletProximity(subscribeId);
}

int32_t MultimodalEventHandler::UnsubscribetabletProximity(int32_t subscribeId)
{
    CALL_DEBUG_ENTER;
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    return MULTIMODAL_INPUT_CONNECT_MGR->UnsubscribetabletProximity(subscribeId);
}

int32_t MultimodalEventHandler::SubscribeLongPressEvent(int32_t subscribeId,
    const LongPressRequest &longPressRequest)
{
    CALL_DEBUG_ENTER;
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    return MULTIMODAL_INPUT_CONNECT_MGR->SubscribeLongPressEvent(subscribeId, longPressRequest);
}
 
int32_t MultimodalEventHandler::UnsubscribeLongPressEvent(int32_t subscribeId)
{
    CALL_DEBUG_ENTER;
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    return MULTIMODAL_INPUT_CONNECT_MGR->UnsubscribeLongPressEvent(subscribeId);
}

bool MultimodalEventHandler::InitClient(EventHandlerPtr eventHandler)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (client_ != nullptr) {
        if (eventHandler != nullptr) {
            client_->MarkIsEventHandlerChanged(eventHandler);
        }
        return true;
    }
    client_ = std::make_shared<MMIClient>();
    client_->SetEventHandler(eventHandler);
    client_->RegisterConnectedFunction(&OnConnected);
    client_->RegisterDisconnectedFunction(&OnDisconnected);
    if (!client_->Start()) {
        client_ = nullptr;
        MMI_HILOGE("The client fails to start");
        return false;
    }
    EventHandlerPtr eventHandlerPtr = client_->GetEventHandler();
    CHKPF(eventHandlerPtr);
    if (!eventHandlerPtr->PostTask([this] { SetClientInfo(GetPid(), GetThisThreadId()); })) {
        MMI_HILOGE("Send reconnect event failed");
        return false;
    }
    return true;
}

MMIClientPtr MultimodalEventHandler::GetMMIClient()
{
    std::lock_guard<std::mutex> guard(mtx_);
    CHKPP(client_);
    return client_->GetSharedPtr();
}

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
int32_t MultimodalEventHandler::InjectPointerEvent(std::shared_ptr<PointerEvent> pointerEvent, bool isNativeInject,
    int32_t useCoordinate)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->InjectPointerEvent(pointerEvent, isNativeInject, useCoordinate);
    if (ret != 0) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
int32_t MultimodalEventHandler::InjectTouchPadEvent(std::shared_ptr<PointerEvent> pointerEvent,
    const TouchpadCDG &touchpadCDG, bool isNativeInject)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    EventLogHelper::PrintEventData(pointerEvent, MMI_LOG_HEADER);
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->InjectTouchPadEvent(pointerEvent, touchpadCDG, isNativeInject);
    if (ret != 0) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
int32_t MultimodalEventHandler::MoveMouseEvent(int32_t offsetX, int32_t offsetY)
{
    CALL_DEBUG_ENTER;
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->MoveMouseEvent(offsetX, offsetY);
    if (ret != 0) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING

int32_t MultimodalEventHandler::Authorize(bool isAuthorize)
{
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->Authorize(isAuthorize);
    if (ret != RET_OK) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MultimodalEventHandler::CancelInjection()
{
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->CancelInjection();
    if (ret != RET_OK) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MultimodalEventHandler::SetClientInfo(int32_t pid, uint64_t readThreadId)
{
    CALL_DEBUG_ENTER;
    CHKPR(MULTIMODAL_INPUT_CONNECT_MGR, RET_ERR);
    return MULTIMODAL_INPUT_CONNECT_MGR->SetClientInfo(pid, readThreadId);
}

static std::unique_ptr<char[]> ReadMaxTouchPointsConfig(std::ifstream &ifs, Json::Value &jsonMaxTouchPoints)
{
    auto rdbuf = ifs.rdbuf();
    CHKPP(rdbuf);
    rdbuf->pubseekpos(jsonMaxTouchPoints.getOffsetStart());

    size_t sIndexChars = 0;
    size_t indexChars = 0;
    size_t countChars = jsonMaxTouchPoints.getOffsetLimit();
    if (countChars > DEFAULT_BUFFER_SIZE) {
        MMI_HILOGE("Config of touchscreen.MaxTouchPoints is too long to be integer");
        return nullptr;
    }
    std::unique_ptr<char[]> buffer { new char[countChars + 1] };
    ifs.read(buffer.get(), countChars);

    while ((indexChars < countChars) && std::isspace(buffer[indexChars])) {
        ++indexChars;
    }
    if (buffer[indexChars] == '-') {
        buffer[sIndexChars++] = buffer[indexChars++];
    }
    while ((indexChars < countChars) && (std::isdigit(buffer[indexChars]) || (buffer[indexChars] == '.'))) {
        buffer[sIndexChars++] = buffer[indexChars++];
    }
    buffer[sIndexChars] = '\0';
    MMI_HILOGI("Config of touchscreen.MaxTouchPoints: %{public}s", buffer.get());
    return buffer;
}

static void ReadMaxMultiTouchPointNum(std::ifstream &ifs, int32_t &maxMultiTouchPointNum)
{
    Json::Reader reader;
    Json::Value root;

    if (!reader.parse(ifs, root)) {
        MMI_HILOGE("Failed to parse config");
        return;
    }
    Json::Value jsonTouchscreen = root.get("touchscreen", Json::Value());
    if (jsonTouchscreen.isNull()) {
        MMI_HILOGE("Expect 'touchscreen'");
        return;
    }
    Json::Value jsonMaxTouchPoints = jsonTouchscreen.get("MaxTouchPoints", Json::Value());
    if (jsonMaxTouchPoints.isNull()) {
        MMI_HILOGE("Expect 'touchscreen.MaxTouchPoints'");
        return;
    }
    if (!jsonMaxTouchPoints.isInt()) {
        MMI_HILOGE("Expect integer for 'touchscreen.MaxTouchPoints'");
        return;
    }
    auto sMaxTouchPoints = ReadMaxTouchPointsConfig(ifs, jsonMaxTouchPoints);
    if (!IsInteger(sMaxTouchPoints.get())) {
        MMI_HILOGE("Config of touchscreen.MaxTouchPoints is not integer");
        return;
    }
    auto num = jsonMaxTouchPoints.asInt();
    if ((num < MIN_MULTI_TOUCH_POINT_NUM) || (num > MAX_MULTI_TOUCH_POINT_NUM)) {
        MMI_HILOGW("Invalid config: MaxTouchPoints(%{public}d) is out of range[%{public}d, %{public}d]",
            num, MIN_MULTI_TOUCH_POINT_NUM, MAX_MULTI_TOUCH_POINT_NUM);
        return;
    }
    maxMultiTouchPointNum = num;
    MMI_HILOGI("touchscreen.MaxTouchPoints:%{public}d", maxMultiTouchPointNum);
}

static void ReadMaxMultiTouchPointNum(const char *cfgPath, int32_t &maxMultiTouchPointNum)
{
    std::ifstream ifs(cfgPath);
    if (!ifs.is_open()) {
        MMI_HILOGE("Can not open config");
        return;
    }
    ReadMaxMultiTouchPointNum(ifs, maxMultiTouchPointNum);
    ifs.close();
}

static void ReadMaxMultiTouchPointNum(int32_t &maxMultiTouchPointNum)
{
    maxMultiTouchPointNum = -1;
    char cfgName[] { "etc/input/input_product_config.json" };
    char buf[MAX_PATH_LEN] {};
    char *cfgPath = ::GetOneCfgFile(cfgName, buf, sizeof(buf));
    if (cfgPath == nullptr) {
        MMI_HILOGE("No input product config was found");
        return;
    }
    auto realPath = std::unique_ptr<char, std::function<void(char *)>>(
        ::realpath(cfgPath, nullptr),
        [](auto arr) {
            if (arr != nullptr) {
                ::free(arr);
            }
        });
    if (realPath == nullptr) {
        MMI_HILOGI("No input product config");
        return;
    }
    ReadMaxMultiTouchPointNum(realPath.get(), maxMultiTouchPointNum);
}

int32_t MultimodalEventHandler::GetMaxMultiTouchPointNum(int32_t &pointNum)
{
    static int32_t maxMultiTouchPointNum { UNKNOWN_MULTI_TOUCH_POINT_NUM };
    static std::once_flag flag;

    std::call_once(flag, []() {
        ReadMaxMultiTouchPointNum(maxMultiTouchPointNum);
    });
    if (maxMultiTouchPointNum < 0) {
        pointNum = UNKNOWN_MULTI_TOUCH_POINT_NUM;
        return MMI_ERR_NO_PRODUCT_CONFIG;
    }
    pointNum = maxMultiTouchPointNum;
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
