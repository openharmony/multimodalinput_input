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

#include "input_manager_impl.h"

#include <cinttypes>

#include <unistd.h>

#ifdef OHOS_BUILD_ENABLE_ANCO
#include "anco_channel.h"
#endif // OHOS_BUILD_ENABLE_ANCO
#include "anr_handler.h"
#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "event_filter_service.h"
#include "event_log_helper.h"
#include "input_scene_board_judgement.h"
#include "mmi_client.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"
#include "pixel_map.h"
#include "switch_event_input_subscribe_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputManagerImpl"

namespace OHOS {
namespace MMI {
namespace {
constexpr size_t MAX_FILTER_NUM { 4 };
constexpr int32_t MAX_DELAY { 4000 };
constexpr int32_t MIN_DELAY { 0 };
constexpr int32_t SIMULATE_EVENT_START_ID { 10000 };
constexpr int32_t EVENT_TYPE { 0 };
constexpr uint8_t LOOP_COND { 2 };
constexpr int32_t MAX_PKT_SIZE { 8 * 1024 };
constexpr int32_t WINDOWINFO_RECT_COUNT { 2 };
constexpr int32_t DISPLAY_STRINGS_MAX_SIZE { 27 * 2 };
} // namespace

struct MonitorEventConsumer : public IInputEventConsumer {
    explicit MonitorEventConsumer(const std::function<void(std::shared_ptr<PointerEvent>)> &monitor)
        : monitor_ (monitor) {}

    explicit MonitorEventConsumer(const std::function<void(std::shared_ptr<KeyEvent>)> &monitor)
        : keyMonitor_ (monitor) {}

    void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const
    {
        CHKPV(keyEvent);
        CHKPV(keyMonitor_);
        keyMonitor_(keyEvent);
    }

    void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
    {
        CHKPV(pointerEvent);
        CHKPV(monitor_);
        monitor_(pointerEvent);
    }

    void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const
    {
        CHKPV(axisEvent);
        CHKPV(axisMonitor_);
        axisMonitor_(axisEvent);
    }

private:
    std::function<void(std::shared_ptr<PointerEvent>)> monitor_;
    std::function<void(std::shared_ptr<KeyEvent>)> keyMonitor_;
    std::function<void(std::shared_ptr<AxisEvent>)> axisMonitor_;
};

InputManagerImpl::InputManagerImpl() {}
InputManagerImpl::~InputManagerImpl() {}

int32_t InputManagerImpl::GetDisplayBindInfo(DisplayBindInfos &infos)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetDisplayBindInfo(infos);
    if (ret != RET_OK) {
        MMI_HILOGE("GetDisplayBindInfo failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputManagerImpl::GetAllMmiSubscribedEvents(std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> &datas)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetAllMmiSubscribedEvents(datas);
    if (ret != RET_OK) {
        MMI_HILOGE("GetDisplayBindInfo failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t InputManagerImpl::SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetDisplayBind(deviceId, displayId, msg);
    if (ret != RET_OK) {
        MMI_HILOGE("SetDisplayBind failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputManagerImpl::GetWindowPid(int32_t windowId)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    return MULTIMODAL_INPUT_CONNECT_MGR->GetWindowPid(windowId);
}

int32_t InputManagerImpl::UpdateDisplayInfo(const DisplayGroupInfo &displayGroupInfo)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Failed to initialize MMI client");
        return RET_ERR;
    }
    displayGroupInfo_ = displayGroupInfo;
    int32_t ret = SendDisplayInfo();
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to send display information to service");
        return ret;
    }
    PrintDisplayInfo();
    return RET_OK;
}

int32_t InputManagerImpl::UpdateWindowInfo(const WindowGroupInfo &windowGroupInfo)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Failed to initialize MMI client");
        return RET_ERR;
    }
    if (!IsValiadWindowAreas(windowGroupInfo.windowsInfo)) {
        MMI_HILOGE("Invalid window information");
        return PARAM_INPUT_INVALID;
    }
    windowGroupInfo_ = windowGroupInfo;
    int32_t ret = SendWindowInfo();
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to send window information to service");
        return ret;
    }
    PrintWindowGroupInfo();
    return RET_OK;
}

bool InputManagerImpl::IsValiadWindowAreas(const std::vector<WindowInfo> &windows)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_ANCO
    if (IsValidAncoWindow(windows)) {
        return true;
    }
#endif // OHOS_BUILD_ENABLE_ANCO
    for (const auto &window : windows) {
        if (window.action == WINDOW_UPDATE_ACTION::DEL) {
            continue;
        }
        if (window.defaultHotAreas.empty() || window.pointerHotAreas.empty() ||
            (!window.pointerChangeAreas.empty() &&
            window.pointerChangeAreas.size() != WindowInfo::POINTER_CHANGEAREA_COUNT) ||
            (!window.transform.empty() && window.transform.size() != WindowInfo::WINDOW_TRANSFORM_SIZE)) {
            MMI_HILOGE("Hot areas check failed! defaultHotAreas:size:%{public}zu,"
                "pointerHotAreas:size:%{public}zu, pointerChangeAreas:size:%{public}zu,"
                "transform:size:%{public}zu", window.defaultHotAreas.size(),
                window.pointerHotAreas.size(), window.pointerChangeAreas.size(),
                window.transform.size());
            return false;
        }
    }
    return true;
}

int32_t InputManagerImpl::GetDisplayMaxSize()
{
    return sizeof(DisplayInfo) + DISPLAY_STRINGS_MAX_SIZE;
}

int32_t InputManagerImpl::GetWindowMaxSize(int32_t maxAreasCount)
{
    return sizeof(WindowInfo) + sizeof(Rect) * maxAreasCount * WINDOWINFO_RECT_COUNT
           + sizeof(int32_t) * WindowInfo::POINTER_CHANGEAREA_COUNT
           + sizeof(float) * WindowInfo::WINDOW_TRANSFORM_SIZE;
}

#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
void InputManagerImpl::SetEnhanceConfig(uint8_t *cfg, uint32_t cfgLen)
{
    CALL_INFO_TRACE;
    if (cfg == nullptr || cfgLen == 0) {
        MMI_HILOGE("SecCompEnhance cfg info is empty");
        return;
    }
    enhanceCfg_ = new (std::nothrow) uint8_t[cfgLen];
    CHKPV(enhanceCfg_);
    errno_t ret = memcpy_s(enhanceCfg_, cfgLen, cfg, cfgLen);
    if (ret != EOK) {
        MMI_HILOGE("cfg memcpy failed");
        return;
    }
    enhanceCfgLen_ = cfgLen;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Get mmi client is nullptr");
        return;
    }
    SendEnhanceConfig();
    PrintEnhanceConfig();
}
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT

int32_t InputManagerImpl::AddInputEventFilter(std::shared_ptr<IInputEventFilter> filter, int32_t priority,
    uint32_t deviceTags)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    CHKPR(filter, RET_ERR);
    if (eventFilterServices_.size() >= MAX_FILTER_NUM) {
        MMI_HILOGE("Too many filters, size:%{public}zu", eventFilterServices_.size());
        return RET_ERR;
    }
    sptr<IEventFilter> service = new (std::nothrow) EventFilterService(filter);
    CHKPR(service, RET_ERR);
    const int32_t filterId = EventFilterService::GetNextId();
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->AddInputEventFilter(service, filterId, priority, deviceTags);
    if (ret != RET_OK) {
        MMI_HILOGE("AddInputEventFilter has send to server failed, priority:%{public}d, ret:%{public}d", priority, ret);
        service = nullptr;
        return RET_ERR;
    }
    auto it = eventFilterServices_.emplace(filterId, std::make_tuple(service, priority, deviceTags));
    if (!it.second) {
        MMI_HILOGW("filterId duplicate");
    }
    return filterId;
}

int32_t InputManagerImpl::AddInputEventObserver(std::shared_ptr<MMIEventObserver> observer)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    CHKPR(observer, RET_ERR);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Get mmi client is nullptr");
        return RET_ERR;
    }
    eventObserver_ = observer;
    NotifyNapOnline();
    return RET_OK;
}

int32_t InputManagerImpl::RemoveInputEventObserver(std::shared_ptr<MMIEventObserver> observer)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    eventObserver_ = nullptr;
    return MULTIMODAL_INPUT_CONNECT_MGR->RemoveInputEventObserver();
}

int32_t InputManagerImpl::NotifyNapOnline()
{
    CALL_DEBUG_ENTER;
    return MULTIMODAL_INPUT_CONNECT_MGR->NotifyNapOnline();
}

int32_t InputManagerImpl::RemoveInputEventFilter(int32_t filterId)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (eventFilterServices_.empty()) {
        MMI_HILOGE("Filters is empty, size:%{public}zu", eventFilterServices_.size());
        return RET_OK;
    }
    std::map<int32_t, std::tuple<sptr<IEventFilter>, int32_t, uint32_t>>::iterator it;
    if (filterId != -1) {
        it = eventFilterServices_.find(filterId);
        if (it == eventFilterServices_.end()) {
            MMI_HILOGE("Filter not found");
            return RET_OK;
        }
    }
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->RemoveInputEventFilter(filterId);
    if (ret != RET_OK) {
        MMI_HILOGE("Remove filter failed, filter id:%{public}d, ret:%{public}d", filterId, ret);
        return RET_ERR;
    }
    if (filterId != -1) {
        eventFilterServices_.erase(it);
    } else {
        eventFilterServices_.clear();
    }
    MMI_HILOGI("Filter remove success");
    return RET_OK;
}

void InputManagerImpl::SetWindowInputEventConsumer(std::shared_ptr<IInputEventConsumer> inputEventConsumer,
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler)
{
    CALL_INFO_TRACE;
    CHK_PID_AND_TID();
    CHKPV(inputEventConsumer);
    CHKPV(eventHandler);
    {
        std::lock_guard<std::mutex> guard(mtx_);
        if (!MMIEventHdl.InitClient(eventHandler)) {
            MMI_HILOGE("Client init failed");
            return;
        }
    }
    std::lock_guard<std::mutex> guard(resourceMtx_);
    consumer_ = inputEventConsumer;
    eventHandler_ = eventHandler;
}

int32_t InputManagerImpl::SubscribeKeyEvent(std::shared_ptr<KeyOption> keyOption,
    std::function<void(std::shared_ptr<KeyEvent>)> callback)
{
    CALL_INFO_TRACE;
    CHK_PID_AND_TID();
    std::lock_guard<std::mutex> guard(mtx_);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    CHKPR(keyOption, RET_ERR);
    CHKPR(callback, RET_ERR);
    return KeyEventInputSubscribeMgr.SubscribeKeyEvent(keyOption, callback);
#else
    MMI_HILOGW("Keyboard device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

void InputManagerImpl::UnsubscribeKeyEvent(int32_t subscriberId)
{
    CALL_INFO_TRACE;
    CHK_PID_AND_TID();
    std::lock_guard<std::mutex> guard(mtx_);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    KeyEventInputSubscribeMgr.UnsubscribeKeyEvent(subscriberId);
#else
    MMI_HILOGW("Keyboard device does not support");
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

int32_t InputManagerImpl::SubscribeSwitchEvent(int32_t switchType,
    std::function<void(std::shared_ptr<SwitchEvent>)> callback)
{
    CALL_INFO_TRACE;
    CHK_PID_AND_TID();
#ifdef OHOS_BUILD_ENABLE_SWITCH
    CHKPR(callback, RET_ERR);
    if (switchType < SwitchEvent::SwitchType::SWITCH_DEFAULT) {
        MMI_HILOGE("switch type error, switchType:%{public}d", switchType);
        return RET_ERR;
    }
    return SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.SubscribeSwitchEvent(switchType, callback);
#else
    MMI_HILOGW("Switch device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_SWITCH
}

void InputManagerImpl::UnsubscribeSwitchEvent(int32_t subscriberId)
{
    CALL_INFO_TRACE;
    CHK_PID_AND_TID();
#ifdef OHOS_BUILD_ENABLE_SWITCH
    SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.UnsubscribeSwitchEvent(subscriberId);
#else
    MMI_HILOGW("Switch device does not support");
#endif // OHOS_BUILD_ENABLE_SWITCH
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void InputManagerImpl::OnKeyEventTask(std::shared_ptr<IInputEventConsumer> consumer,
    std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_INFO_TRACE;
    LogTracer lt(keyEvent->GetId(), keyEvent->GetEventType(), keyEvent->GetKeyAction());
    CHK_PID_AND_TID();
    CHKPV(consumer);
    BytraceAdapter::StartConsumer(keyEvent);
    consumer->OnInputEvent(keyEvent);
    BytraceAdapter::StopConsumer();
    MMI_HILOGD("Key event callback keyCode:%{public}d", keyEvent->GetKeyCode());
}

void InputManagerImpl::OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_INFO_TRACE;
    CHK_PID_AND_TID();
    CHKPV(keyEvent);
    CHKPV(eventHandler_);
    CHKPV(consumer_);
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler = nullptr;
    std::shared_ptr<IInputEventConsumer> inputConsumer = nullptr;
    {
        std::lock_guard<std::mutex> guard(resourceMtx_);
        eventHandler = eventHandler_;
        inputConsumer = consumer_;
    }
    MMI_HILOG_DISPATCHI("id:%{public}d recv", keyEvent->GetId());
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::KEY_DISPATCH_EVENT);
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPV(client);
    if (client->IsEventHandlerChanged()) {
        BytraceAdapter::StartPostTaskEvent(keyEvent);
        if (!eventHandler->PostTask([this, inputConsumer, keyEvent] {
                return this->OnKeyEventTask(inputConsumer, keyEvent);
            },
            std::string("MMI::OnKeyEvent"), 0, AppExecFwk::EventHandler::Priority::VIP)) {
            MMI_HILOG_DISPATCHE("Post task failed");
            BytraceAdapter::StopPostTaskEvent();
            return;
        }
        BytraceAdapter::StopPostTaskEvent();
    } else {
        BytraceAdapter::StartConsumer(keyEvent);
        inputConsumer->OnInputEvent(keyEvent);
        BytraceAdapter::StopConsumer();
        MMI_HILOG_DISPATCHD("Key event report keyCode:%{public}d", keyEvent->GetKeyCode());
    }
    MMI_HILOG_DISPATCHD("Key event keyCode:%{public}d", keyEvent->GetKeyCode());
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
void InputManagerImpl::OnPointerEventTask(std::shared_ptr<IInputEventConsumer> consumer,
    std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
    CHK_PID_AND_TID();
    CHKPV(consumer);
    CHKPV(pointerEvent);
    BytraceAdapter::StartConsumer(pointerEvent);
    consumer->OnInputEvent(pointerEvent);
    BytraceAdapter::StopConsumer();
    MMI_HILOG_DISPATCHD("Pointer event callback pointerId:%{public}d",
        pointerEvent->GetPointerId());
}

void InputManagerImpl::OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHK_PID_AND_TID();
    CHKPV(pointerEvent);
    CHKPV(eventHandler_);
    CHKPV(consumer_);
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler = nullptr;
    std::shared_ptr<IInputEventConsumer> inputConsumer = nullptr;
    {
        std::lock_guard<std::mutex> guard(resourceMtx_);
        eventHandler = eventHandler_;
        inputConsumer = consumer_;
        lastPointerEvent_ = std::make_shared<PointerEvent>(*pointerEvent);
    }
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::POINT_DISPATCH_EVENT);
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPV(client);
    if (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_MOVE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_AXIS_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_ROTATE_UPDATE) {
        MMI_HILOG_FREEZEI("id:%{public}d recv", pointerEvent->GetId());
    }
    if (client->IsEventHandlerChanged()) {
        BytraceAdapter::StartPostTaskEvent(pointerEvent);
        if (!eventHandler->PostTask([this, inputConsumer, pointerEvent] {
                return this->OnPointerEventTask(inputConsumer, pointerEvent);
            },
            std::string("MMI::OnPointerEvent"), 0, AppExecFwk::EventHandler::Priority::VIP)) {
            MMI_HILOG_DISPATCHE("Post task failed");
            BytraceAdapter::StopPostTaskEvent();
            return;
        }
        BytraceAdapter::StopPostTaskEvent();
    } else {
        BytraceAdapter::StartConsumer(pointerEvent);
        inputConsumer->OnInputEvent(pointerEvent);
        BytraceAdapter::StopConsumer();
    }
    MMI_HILOG_DISPATCHD("Pointer event pointerId:%{public}d",
        pointerEvent->GetPointerId());
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

int32_t InputManagerImpl::PackDisplayData(NetPacket &pkt)
{
    CALL_DEBUG_ENTER;
    pkt << displayGroupInfo_.width << displayGroupInfo_.height
        << displayGroupInfo_.focusWindowId << displayGroupInfo_.currentUserId;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write logical data failed");
        return RET_ERR;
    }
    if (PackWindowInfo(pkt) != RET_OK) {
        MMI_HILOGE("Packet write windows info failed");
        return RET_ERR;
    }
    return PackDisplayInfo(pkt);
}

int32_t InputManagerImpl::PackWindowGroupInfo(NetPacket &pkt)
{
    CALL_DEBUG_ENTER;
    pkt << windowGroupInfo_.focusWindowId << windowGroupInfo_.displayId;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write windowGroupInfo data failed");
        return RET_ERR;
    }
    uint32_t num = static_cast<uint32_t>(windowGroupInfo_.windowsInfo.size());
    pkt << num;
    for (const auto &item : windowGroupInfo_.windowsInfo) {
        pkt << item.id << item.pid << item.uid << item.area
            << item.defaultHotAreas << item.pointerHotAreas
            << item.agentWindowId << item.flags << item.action
            << item.displayId << item.zOrder << item.pointerChangeAreas
            << item.transform << item.windowInputType << item.privacyMode << item.windowType;
        uint32_t uiExtentionWindowInfoNum = static_cast<uint32_t>(item.uiExtentionWindowInfo.size());
        pkt << uiExtentionWindowInfoNum;
        MMI_HILOGD("uiExtentionWindowInfoNum:%{public}u", uiExtentionWindowInfoNum);
        if (!item.uiExtentionWindowInfo.empty()) {
            PackUiExtentionWindowInfo(item.uiExtentionWindowInfo, pkt);
            PrintWindowInfo(item.uiExtentionWindowInfo);
        }
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write windows data failed");
        return RET_ERR;
    }
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
int32_t InputManagerImpl::PackEnhanceConfig(NetPacket &pkt)
{
    CALL_INFO_TRACE;
    CHKPR(enhanceCfg_, RET_ERR);
    pkt << enhanceCfgLen_;
    for (uint32_t i = 0; i < enhanceCfgLen_; i++) {
        pkt << enhanceCfg_[i];
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write security info config failed");
        return RET_ERR;
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT

int32_t InputManagerImpl::PackUiExtentionWindowInfo(const std::vector<WindowInfo>& windowsInfo, NetPacket &pkt)
{
    CALL_DEBUG_ENTER;
    for (const auto &item : windowsInfo) {
        pkt << item.id << item.pid << item.uid << item.area
            << item.defaultHotAreas << item.pointerHotAreas
            << item.agentWindowId << item.flags << item.action
            << item.displayId << item.zOrder << item.pointerChangeAreas
            << item.transform << item.windowInputType << item.privacyMode << item.windowType << item.privacyUIFlag;
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write windows data failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputManagerImpl::PackWindowInfo(NetPacket &pkt)
{
    CALL_DEBUG_ENTER;
    uint32_t num = static_cast<uint32_t>(displayGroupInfo_.windowsInfo.size());
    pkt << num;
    for (const auto &item : displayGroupInfo_.windowsInfo) {
        int32_t byteCount = 0;
        pkt << item.id << item.pid << item.uid << item.area << item.defaultHotAreas
            << item.pointerHotAreas << item.agentWindowId << item.flags << item.action
            << item.displayId << item.zOrder << item.pointerChangeAreas << item.transform
            << item.windowInputType << item.privacyMode << item.windowType;

        if (item.pixelMap == nullptr) {
            pkt << byteCount;
            uint32_t uiExtentionWindowInfoNum = static_cast<uint32_t>(item.uiExtentionWindowInfo.size());
            pkt << uiExtentionWindowInfoNum;
            MMI_HILOGD("uiExtentionWindowInfoNum:%{public}u", uiExtentionWindowInfoNum);
            if (!item.uiExtentionWindowInfo.empty()) {
                PackUiExtentionWindowInfo(item.uiExtentionWindowInfo, pkt);
                PrintWindowInfo(item.uiExtentionWindowInfo);
            }
            continue;
        }
        OHOS::Media::PixelMap* pixelMapPtr = static_cast<OHOS::Media::PixelMap*>(item.pixelMap);
        byteCount = pixelMapPtr->GetByteCount();
        int32_t ret = SetPixelMapData(item.id, item.pixelMap);
        if (ret != RET_OK) {
            byteCount = 0;
            MMI_HILOGE("Failed to set pixel map");
        }
        pkt << byteCount;
        uint32_t uiExtentionWindowInfoNum = static_cast<uint32_t>(item.uiExtentionWindowInfo.size());
        pkt << uiExtentionWindowInfoNum;
        MMI_HILOGD("uiExtentionWindowInfoNum:%{public}u", uiExtentionWindowInfoNum);
        if (!item.uiExtentionWindowInfo.empty()) {
            PackUiExtentionWindowInfo(item.uiExtentionWindowInfo, pkt);
            PrintWindowInfo(item.uiExtentionWindowInfo);
        }
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write windows data failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputManagerImpl::PackDisplayInfo(NetPacket &pkt)
{
    CALL_DEBUG_ENTER;
    uint32_t num = static_cast<uint32_t>(displayGroupInfo_.displaysInfo.size());
    pkt << num;
    for (const auto &item : displayGroupInfo_.displaysInfo) {
        pkt << item.id << item.x << item.y << item.width
            << item.height << item.dpi << item.name << item.uniq << item.direction
            << item.displayDirection << item.displayMode << item.transform;
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write display data failed");
        return RET_ERR;
    }
    return RET_OK;
}

void InputManagerImpl::PrintWindowInfo(const std::vector<WindowInfo> &windowsInfo)
{
    if (!HiLogIsLoggable(MMI_LOG_DOMAIN, MMI_LOG_TAG, LOG_DEBUG)) {
        return;
    }
    for (const auto &item : windowsInfo) {
        MMI_HILOGD("windowsInfos,id:%{public}d,pid:%{public}d,uid:%{public}d,"
            "area.x:%{public}d,area.y:%{public}d,area.width:%{public}d,area.height:%{public}d,"
            "defaultHotAreas.size:%{public}zu,pointerHotAreas.size:%{public}zu,"
            "agentWindowId:%{public}d,flags:%{public}d,action:%{public}d,displayId:%{public}d,"
            "zOrder:%{public}f,privacyMode:%{public}d",
            item.id, item.pid, item.uid, item.area.x, item.area.y, item.area.width,
            item.area.height, item.defaultHotAreas.size(), item.pointerHotAreas.size(),
            item.agentWindowId, item.flags, item.action, item.displayId, item.zOrder, item.privacyMode);
        for (const auto &win : item.defaultHotAreas) {
            MMI_HILOGD("defaultHotAreas:x:%{public}d,y:%{public}d,width:%{public}d,height:%{public}d",
                win.x, win.y, win.width, win.height);
        }
        for (const auto &pointer : item.pointerHotAreas) {
            MMI_HILOGD("pointerHotAreas:x:%{public}d,y:%{public}d,width:%{public}d,height:%{public}d",
                pointer.x, pointer.y, pointer.width, pointer.height);
        }

        std::string dump;
        dump += StringPrintf("pointChangeAreas:[");
        for (auto it : item.pointerChangeAreas) {
            dump += StringPrintf("%d,", it);
        }
        dump += StringPrintf("] transform:[");
        for (auto it : item.transform) {
            dump += StringPrintf("%f,", it);
        }
        dump += StringPrintf("]\n");
        std::istringstream stream(dump);
        std::string line;
        while (std::getline(stream, line, '\n')) {
            MMI_HILOGD("%{public}s", line.c_str());
        }
    }
}

void InputManagerImpl::PrintForemostThreeWindowInfo(const std::vector<WindowInfo> &windowsInfo)
{
    uint8_t times = 0;
    for (const auto &item : windowsInfo) {
        if (times > LOOP_COND) {
            return;
        }
        MMI_HILOGD("WindowInfo[%{public}d,%{public}d,%{public}d,%{public}d,%{public}d,%{public}d,%{public}f]",
            item.id, item.pid, item.area.x, item.area.y, item.area.width, item.area.height, item.zOrder);
        for (const auto &pointer : item.pointerHotAreas) {
            MMI_HILOGD("pointerHotAreas:x:%{public}d,y:%{public}d,width:%{public}d,height:%{public}d",
                pointer.x, pointer.y, pointer.width, pointer.height);
        }
        times++;
    }
}

void InputManagerImpl::PrintDisplayInfo()
{
    MMI_HILOGD("windowsInfos,num:%{public}zu,focusWindowId:%{public}d", displayGroupInfo_.windowsInfo.size(),
        displayGroupInfo_.focusWindowId);
    PrintForemostThreeWindowInfo(displayGroupInfo_.windowsInfo);
    if (!HiLogIsLoggable(MMI_LOG_DOMAIN, MMI_LOG_TAG, LOG_DEBUG)) {
        return;
    }
    MMI_HILOGD("logicalInfo,width:%{public}d,height:%{public}d,focusWindowId:%{public}d",
        displayGroupInfo_.width, displayGroupInfo_.height, displayGroupInfo_.focusWindowId);
    PrintWindowInfo(displayGroupInfo_.windowsInfo);

    MMI_HILOGD("displayInfos,num:%{public}zu", displayGroupInfo_.displaysInfo.size());
    for (const auto &item : displayGroupInfo_.displaysInfo) {
        MMI_HILOGD("displayInfos,id:%{public}d,x:%{public}d,y:%{public}d,"
            "width:%{public}d,height:%{public}d,dpi:%{public}d,name:%{public}s,"
            "uniq:%{public}s,direction:%{public}d,displayDirection:%{public}d,displayMode:%{public}d",
            item.id, item.x, item.y, item.width, item.height, item.dpi, item.name.c_str(),
            item.uniq.c_str(), item.direction, item.displayDirection, item.displayMode);
    }
}

void InputManagerImpl::PrintWindowGroupInfo()
{
    if (!HiLogIsLoggable(MMI_LOG_DOMAIN, MMI_LOG_TAG, LOG_DEBUG)) {
        return;
    }
    MMI_HILOGD("windowsGroupInfo,focusWindowId:%{public}d,displayId:%{public}d",
        windowGroupInfo_.focusWindowId, windowGroupInfo_.displayId);
    PrintWindowInfo(windowGroupInfo_.windowsInfo);
}

#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
void InputManagerImpl::PrintEnhanceConfig()
{
    CHKPV(enhanceCfg_);
    MMI_HILOGD("securityConfigInfo, cfg len:%{public}d", enhanceCfgLen_);
}
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT

int32_t InputManagerImpl::AddMonitor(std::function<void(std::shared_ptr<KeyEvent>)> monitor)
{
    CALL_DEBUG_ENTER;
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_MONITOR)
    CHKPR(monitor, INVALID_HANDLER_ID);
    auto consumer = std::make_shared<MonitorEventConsumer>(monitor);
    return AddMonitor(consumer, HANDLE_EVENT_TYPE_KEY);
#else
    MMI_HILOGW("Keyboard device or monitor function does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_KEYBOARD || OHOS_BUILD_ENABLE_MONITOR
}

int32_t InputManagerImpl::AddMonitor(std::function<void(std::shared_ptr<PointerEvent>)> monitor)
{
    CALL_DEBUG_ENTER;
#if (defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)) && defined(OHOS_BUILD_ENABLE_MONITOR)
    CHKPR(monitor, INVALID_HANDLER_ID);
    auto consumer = std::make_shared<MonitorEventConsumer>(monitor);
    return AddMonitor(consumer, HANDLE_EVENT_TYPE_POINTER);
#else
    MMI_HILOGW("Pointer/touchscreen device or monitor function does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_MONITOR ||  OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
}

int32_t InputManagerImpl::AddMonitor(std::shared_ptr<IInputEventConsumer> consumer, HandleEventType eventType)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_MONITOR
    CHKPR(consumer, INVALID_HANDLER_ID);
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return IMonitorMgr->AddMonitor(consumer, eventType);
#else
    MMI_HILOGI("Monitor function does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_MONITOR
}

void InputManagerImpl::RemoveMonitor(int32_t monitorId)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_MONITOR
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return;
    }
    IMonitorMgr->RemoveMonitor(monitorId);
#else
    MMI_HILOGI("Monitor function does not support");
#endif // OHOS_BUILD_ENABLE_MONITOR
}

void InputManagerImpl::MarkConsumed(int32_t monitorId, int32_t eventId)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_MONITOR
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return;
    }
    IMonitorMgr->MarkConsumed(monitorId, eventId);
#else
    MMI_HILOGI("Monitor function does not support");
#endif // OHOS_BUILD_ENABLE_MONITOR
}

void InputManagerImpl::MoveMouse(int32_t offsetX, int32_t offsetY)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    std::lock_guard<std::mutex> guard(mtx_);
    if (MMIEventHdl.MoveMouseEvent(offsetX, offsetY) != RET_OK) {
        MMI_HILOGE("Failed to inject move mouse offset event");
    }
#else
    MMI_HILOGW("Pointer device or pointer drawing module does not support");
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
}

int32_t InputManagerImpl::AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptor,
    int32_t priority, uint32_t deviceTags)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    CHKPR(interceptor, INVALID_HANDLER_ID);
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputInterMgr->AddInterceptor(interceptor, HANDLE_EVENT_TYPE_ALL, priority, deviceTags);
#else
    MMI_HILOGW("Interceptor function does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
}

int32_t InputManagerImpl::AddInterceptor(std::function<void(std::shared_ptr<KeyEvent>)> interceptor,
    int32_t priority, uint32_t deviceTags)
{
    CALL_DEBUG_ENTER;
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_INTERCEPTOR)
    CHKPR(interceptor, INVALID_HANDLER_ID);
    std::lock_guard<std::mutex> guard(mtx_);
    auto consumer = std::make_shared<MonitorEventConsumer>(interceptor);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputInterMgr->AddInterceptor(consumer, HANDLE_EVENT_TYPE_KEY, priority, deviceTags);
#else
    MMI_HILOGW("Keyboard device or interceptor function does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_INTERCEPTOR
}

void InputManagerImpl::RemoveInterceptor(int32_t interceptorId)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return;
    }
    InputInterMgr->RemoveInterceptor(interceptorId);
#else
    MMI_HILOGW("Interceptor function does not support");
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
}

void InputManagerImpl::SimulateInputEvent(std::shared_ptr<KeyEvent> keyEvent, bool isNativeInject)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    CHKPV(keyEvent);
    if (!EventLogHelper::IsBetaVersion()) {
        MMI_HILOGI("action:%{public}d", keyEvent->GetKeyAction());
    } else {
        MMI_HILOGI("KeyCode:%{public}d, action:%{public}d", keyEvent->GetKeyCode(), keyEvent->GetKeyAction());
    }
    if (MMIEventHdl.InjectEvent(keyEvent, isNativeInject) != RET_OK) {
        MMI_HILOGE("Failed to inject keyEvent");
    }
#else
    MMI_HILOGW("Keyboard device does not support");
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

void InputManagerImpl::HandleSimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    int maxPointerId = SIMULATE_EVENT_START_ID;
    std::list<PointerEvent::PointerItem> pointerItems = pointerEvent->GetAllPointerItems();
    for (auto &pointerItem : pointerItems) {
        int32_t pointerId = pointerItem.GetPointerId();
        if (pointerId != -1) {
            maxPointerId = (maxPointerId > pointerId) ? maxPointerId : pointerId;
            continue;
        }
        maxPointerId += 1;
        pointerItem.SetPointerId(maxPointerId);
    }
    for (auto &pointerItem : pointerItems) {
        int32_t pointerId = pointerItem.GetPointerId();
        if (pointerId < SIMULATE_EVENT_START_ID) {
            pointerItem.SetOriginPointerId(pointerId);
            pointerItem.SetPointerId(pointerId + SIMULATE_EVENT_START_ID);
        }
    }
    pointerEvent->RemoveAllPointerItems();
    for (auto &pointerItem : pointerItems) {
        pointerEvent->AddPointerItem(pointerItem);
    }
    if ((pointerEvent->GetPointerId() < 0) && !pointerItems.empty()) {
        pointerEvent->SetPointerId(pointerItems.front().GetPointerId());
        MMI_HILOGD("Simulate pointer event id:%{public}d", pointerEvent->GetPointerId());
    }
    if (pointerEvent->GetPointerId() < SIMULATE_EVENT_START_ID) {
        pointerEvent->SetPointerId(pointerEvent->GetPointerId() + SIMULATE_EVENT_START_ID);
    }
}

void InputManagerImpl::SimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent, bool isNativeInject)
{
    CALL_DEBUG_ENTER;
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    CHKPV(pointerEvent);
    if (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_MOVE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_PULL_MOVE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_HOVER_MOVE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_AXIS_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_ROTATE_UPDATE &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE) {
        MMI_HILOGI("Pointer event action:%{public}d", pointerEvent->GetPointerAction());
    }
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE ||
        pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHPAD) {
#ifndef OHOS_BUILD_ENABLE_POINTER
        MMI_HILOGW("Pointer device does not support");
        return;
#endif // OHOS_BUILD_ENABLE_POINTER
    }
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
#ifndef OHOS_BUILD_ENABLE_TOUCH
        MMI_HILOGW("Touchscreen device does not support");
        return;
#endif // OHOS_BUILD_ENABLE_TOUCH
    }
#ifndef OHOS_BUILD_ENABLE_JOYSTICK
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_JOYSTICK) {
        MMI_HILOGW("Joystick device does not support");
        return;
    }
#endif // OHOS_BUILD_ENABLE_JOYSTICK
    HandleSimulateInputEvent(pointerEvent);
    if (MMIEventHdl.InjectPointerEvent(pointerEvent, isNativeInject) != RET_OK) {
        MMI_HILOGE("Failed to inject pointer event");
    }
#else
    MMI_HILOGW("Pointer and touchscreen device does not support");
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
}

int32_t InputManagerImpl::SetMouseScrollRows(int32_t rows)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetMouseScrollRows(rows);
    if (ret != RET_OK) {
        MMI_HILOGE("Set the number of mouse scrolling rows failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetCustomCursor(int32_t windowId, int32_t focusX, int32_t focusY, void* pixelMap)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t winPid = GetWindowPid(windowId);
    if (winPid == -1) {
        MMI_HILOGE("winPid is invalid");
        return RET_ERR;
    }
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetCustomCursor(winPid, windowId, focusX, focusY, pixelMap);
    if (ret != RET_OK) {
        MMI_HILOGE("Set custom cursor failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetMouseIcon(int32_t windowId, void* pixelMap)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetMouseIcon(windowId, pixelMap);
    if (ret != RET_OK) {
        MMI_HILOGE("Set the number of mouse scrolling rows failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetMouseHotSpot(int32_t windowId, int32_t hotSpotX, int32_t hotSpotY)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t winPid = GetWindowPid(windowId);
    if (winPid == -1) {
        MMI_HILOGE("winPid is invalid return -1");
        return RET_ERR;
    }
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetMouseHotSpot(winPid, windowId, hotSpotX, hotSpotY);
    if (ret != RET_OK) {
        MMI_HILOGE("Set mouse hot spot failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::GetMouseScrollRows(int32_t &rows)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetMouseScrollRows(rows);
    if (ret != RET_OK) {
        MMI_HILOGE("Get the number of mouse scrolling rows failed");
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetPointerSize(int32_t size)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetPointerSize(size);
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer size failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::GetPointerSize(int32_t &size)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetPointerSize(size);
    if (ret != RET_OK) {
        MMI_HILOGE("Get pointer size failed");
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetMousePrimaryButton(int32_t primaryButton)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    if (primaryButton != LEFT_BUTTON && primaryButton != RIGHT_BUTTON) {
        MMI_HILOGE("primaryButton is invalid");
        return RET_ERR;
    }
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetMousePrimaryButton(primaryButton);
    if (ret != RET_OK) {
        MMI_HILOGE("Set mouse primary button failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::GetMousePrimaryButton(int32_t &primaryButton)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetMousePrimaryButton(primaryButton);
    if (ret != RET_OK) {
        MMI_HILOGE("Get mouse primary button failed");
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetHoverScrollState(bool state)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetHoverScrollState(state);
    if (ret != RET_OK) {
        MMI_HILOGE("Set mouse hover scroll state failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::GetHoverScrollState(bool &state)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetHoverScrollState(state);
    if (ret != RET_OK) {
        MMI_HILOGE("Get mouse hover scroll state failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetPointerVisible(bool visible, int32_t priority)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetPointerVisible(visible, priority);
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer visible failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device or pointer drawing module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
}

bool InputManagerImpl::IsPointerVisible()
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    std::lock_guard<std::mutex> guard(mtx_);
    bool visible;
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->IsPointerVisible(visible);
    if (ret != 0) {
        MMI_HILOGE("Get pointer visible failed, ret:%{public}d", ret);
    }
    return visible;
#else
    MMI_HILOGW("Pointer device or pointer drawing module does not support");
    return false;
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
}

int32_t InputManagerImpl::SetPointerColor(int32_t color)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetPointerColor(color);
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer color failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::GetPointerColor(int32_t &color)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetPointerColor(color);
    if (ret != RET_OK) {
        MMI_HILOGE("Get pointer color failed");
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::EnableCombineKey(bool enable)
{
    CALL_INFO_TRACE;
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->EnableCombineKey(enable);
    if (ret != RET_OK) {
        MMI_HILOGE("Enable combine key failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t InputManagerImpl::SetPointerSpeed(int32_t speed)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetPointerSpeed(speed);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to set pointer speed");
        return RET_ERR;
    }
    return RET_OK;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::GetPointerSpeed(int32_t &speed)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetPointerSpeed(speed);
    if (ret != RET_OK) {
        MMI_HILOGE("Get pointer speed failed");
        return RET_ERR;
    }
    return RET_OK;
#else
    return ERROR_UNSUPPORT;
    MMI_HILOGW("Pointer device does not support");
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetPointerStyle(int32_t windowId, const PointerStyle& pointerStyle, bool isUiExtension)
{
    CALL_INFO_TRACE;
    if (pointerStyle.id < 0) {
        MMI_HILOGE("The param is invalid");
        return RET_ERR;
    }

    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetPointerStyle(windowId, pointerStyle, isUiExtension);
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer style failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t InputManagerImpl::GetPointerStyle(int32_t windowId, PointerStyle &pointerStyle, bool isUiExtension)
{
    CALL_DEBUG_ENTER;
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetPointerStyle(windowId, pointerStyle, isUiExtension);
    if (ret != RET_OK) {
        MMI_HILOGE("Get pointer style failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

void InputManagerImpl::OnConnected()
{
    CALL_INFO_TRACE;
    ReAddInputEventFilter();
    if (displayGroupInfo_.windowsInfo.empty() || displayGroupInfo_.displaysInfo.empty()) {
        MMI_HILOGD("The windows info or display info is empty");
        return;
    }
    SendDisplayInfo();
    SendWindowInfo();
    PrintDisplayInfo();
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    SendEnhanceConfig();
    PrintEnhanceConfig();
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    if (anrObservers_.empty()) {
        return;
    }
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetAnrObserver();
    if (ret != RET_OK) {
        MMI_HILOGE("Set anr observer failed, ret:%{public}d", ret);
    }
}

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
template<typename T>
bool InputManagerImpl::RecoverPointerEvent(std::initializer_list<T> pointerActionEvents, T pointerActionEvent)
{
    CALL_INFO_TRACE;
    CHKPF(lastPointerEvent_);
    int32_t pointerAction = lastPointerEvent_->GetPointerAction();
    for (const auto &it : pointerActionEvents) {
        if (pointerAction == it) {
            PointerEvent::PointerItem item;
            int32_t pointerId = lastPointerEvent_->GetPointerId();
            if (!lastPointerEvent_->GetPointerItem(pointerId, item)) {
                MMI_HILOG_DISPATCHD("Get pointer item failed. pointer:%{public}d",
                    pointerId);
                return false;
            }
            item.SetPressed(false);
            lastPointerEvent_->UpdatePointerItem(pointerId, item);
            lastPointerEvent_->SetPointerAction(pointerActionEvent);
            OnPointerEvent(lastPointerEvent_);
            return true;
        }
    }
    return false;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

void InputManagerImpl::OnDisconnected()
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    std::initializer_list<int32_t> pointerActionEvents { PointerEvent::POINTER_ACTION_MOVE,
        PointerEvent::POINTER_ACTION_DOWN };
    std::initializer_list<int32_t> pointerActionPullEvents { PointerEvent::POINTER_ACTION_PULL_MOVE,
        PointerEvent::POINTER_ACTION_PULL_DOWN };
    if (RecoverPointerEvent(pointerActionEvents, PointerEvent::POINTER_ACTION_UP)) {
        MMI_HILOGE("Up event for service exception re-sending");
        return;
    }

    if (RecoverPointerEvent(pointerActionPullEvents, PointerEvent::POINTER_ACTION_PULL_UP)) {
        MMI_HILOGE("Pull up event for service exception re-sending");
        return;
    }
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
}

int32_t InputManagerImpl::SendDisplayInfo()
{
    CALL_DEBUG_ENTER;
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPR(client, RET_ERR);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    int32_t ret = PackDisplayData(pkt);
    if (ret != RET_OK) {
        MMI_HILOGE("Pack display info failed");
        return ret;
    }
    if (!client->SendMessage(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

int32_t InputManagerImpl::SendWindowInfo()
{
    CALL_DEBUG_ENTER;
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPR(client, RET_ERR);
    NetPacket pkt(MmiMessageId::WINDOW_INFO);
    int32_t ret = PackWindowGroupInfo(pkt);
    if (ret != RET_OK) {
        MMI_HILOGE("Pack window group info failed");
        return ret;
    }
    if (!client->SendMessage(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
void InputManagerImpl::SendEnhanceConfig()
{
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPV(client);
    NetPacket pkt(MmiMessageId::SCINFO_CONFIG);
    if (PackEnhanceConfig(pkt) == RET_ERR) {
        return;
    }
    if (!client->SendMessage(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
    }
}
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT

void InputManagerImpl::ReAddInputEventFilter()
{
    CALL_INFO_TRACE;
    if (eventFilterServices_.size() > MAX_FILTER_NUM) {
        MMI_HILOGE("Too many filters, size:%{public}zu", eventFilterServices_.size());
        return;
    }
    for (const auto &[filterId, t] : eventFilterServices_) {
        const auto &[service, priority, deviceTags] = t;
        int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->AddInputEventFilter(service, filterId, priority, deviceTags);
        if (ret != RET_OK) {
            MMI_HILOGE("AddInputEventFilter has send to server failed, filterId:%{public}d, priority:%{public}d,"
                "deviceTags:%{public}u, ret:%{public}d", filterId, priority, deviceTags, ret);
        }
    }
}

int32_t InputManagerImpl::RegisterDevListener(std::string type, std::shared_ptr<IInputDeviceListener> listener)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return INPUT_DEVICE_IMPL.RegisterDevListener(type, listener);
}

int32_t InputManagerImpl::UnregisterDevListener(std::string type,
    std::shared_ptr<IInputDeviceListener> listener)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return INPUT_DEVICE_IMPL.UnregisterDevListener(type, listener);
}

int32_t InputManagerImpl::GetDeviceIds(std::function<void(std::vector<int32_t>&)> callback)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return INPUT_DEVICE_IMPL.GetInputDeviceIds(callback);
}

int32_t InputManagerImpl::GetDevice(int32_t deviceId,
    std::function<void(std::shared_ptr<InputDevice>)> callback)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return INPUT_DEVICE_IMPL.GetInputDevice(deviceId, callback);
}

int32_t InputManagerImpl::SupportKeys(int32_t deviceId, std::vector<int32_t> &keyCodes,
    std::function<void(std::vector<bool>&)> callback)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return INPUT_DEVICE_IMPL.SupportKeys(deviceId, keyCodes, callback);
}

int32_t InputManagerImpl::GetKeyboardType(int32_t deviceId, std::function<void(int32_t)> callback)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return INPUT_DEVICE_IMPL.GetKeyboardType(deviceId, callback);
}

int32_t InputManagerImpl::SetKeyboardRepeatDelay(int32_t delay)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return INPUT_DEVICE_IMPL.SetKeyboardRepeatDelay(delay);
}

int32_t InputManagerImpl::SetKeyboardRepeatRate(int32_t rate)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return INPUT_DEVICE_IMPL.SetKeyboardRepeatRate(rate);
}

int32_t InputManagerImpl::GetKeyboardRepeatDelay(std::function<void(int32_t)> callback)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return INPUT_DEVICE_IMPL.GetKeyboardRepeatDelay(callback);
}

int32_t InputManagerImpl::GetKeyboardRepeatRate(std::function<void(int32_t)> callback)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return INPUT_DEVICE_IMPL.GetKeyboardRepeatRate(callback);
}

void InputManagerImpl::SetAnrObserver(std::shared_ptr<IAnrObserver> observer)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOG_ANRDETECTE("Client init failed");
        return;
    }
    for (auto iter = anrObservers_.begin(); iter != anrObservers_.end(); ++iter) {
        if (*iter == observer) {
            MMI_HILOG_ANRDETECTE("Observer already exist");
            return;
        }
    }
    anrObservers_.push_back(observer);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetAnrObserver();
    if (ret != RET_OK) {
        MMI_HILOG_ANRDETECTE("Set anr observer failed, ret:%{public}d", ret);
    }
}

void InputManagerImpl::OnAnr(int32_t pid, int32_t eventId)
{
    CALL_DEBUG_ENTER;
    CHK_PID_AND_TID();
    {
        std::lock_guard<std::mutex> guard(mtx_);
        for (const auto &observer : anrObservers_) {
            CHKPC(observer);
            observer->OnAnr(pid, eventId);
        }
    }
    MMI_HILOG_ANRDETECTI("ANR noticed pid:%{public}d eventId:%{public}d", pid, eventId);
}

bool InputManagerImpl::GetFunctionKeyState(int32_t funcKey)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    bool state { false };
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetFunctionKeyState(funcKey, state);
    if (ret != RET_OK) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
    }
    return state;
#else
    MMI_HILOGW("Keyboard device does not support");
    return false;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

int32_t InputManagerImpl::SetFunctionKeyState(int32_t funcKey, bool enable)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetFunctionKeyState(funcKey, enable);
    if (ret != RET_OK) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
#else
    MMI_HILOGW("Keyboard device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

int32_t InputManagerImpl::SetPointerLocation(int32_t x, int32_t y)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetPointerLocation(x, y);
    if (ret != RET_OK) {
        MMI_HILOGE("Set Pointer Location failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device or pointer drawing module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
}

int32_t InputManagerImpl::EnterCaptureMode(int32_t windowId)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER)
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetMouseCaptureMode(windowId, true);
    if (ret != RET_OK) {
        MMI_HILOGE("Enter captrue mode failed");
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::LeaveCaptureMode(int32_t windowId)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER)
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetMouseCaptureMode(windowId, false);
    if (ret != RET_OK) {
        MMI_HILOGE("Leave captrue mode failed");
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

void InputManagerImpl::AppendExtraData(const ExtraData& extraData)
{
    CALL_INFO_TRACE;
    if (extraData.buffer.size() > ExtraData::MAX_BUFFER_SIZE) {
        MMI_HILOGE("Append extra data failed, buffer is oversize:%{public}zu", extraData.buffer.size());
        return;
    }
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->AppendExtraData(extraData);
    if (ret != RET_OK) {
        MMI_HILOGE("Append extra data failed:%{public}d", ret);
    }
}

int32_t InputManagerImpl::EnableInputDevice(bool enable)
{
    CALL_INFO_TRACE;
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->EnableInputDevice(enable);
    if (ret != RET_OK) {
        MMI_HILOGE("Enable input device failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t InputManagerImpl::SetKeyDownDuration(const std::string &businessId, int32_t delay)
{
    CALL_INFO_TRACE;
    if (delay < MIN_DELAY || delay > MAX_DELAY) {
        MMI_HILOGE("The param is invalid");
        return RET_ERR;
    }
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetKeyDownDuration(businessId, delay);
    if (ret != RET_OK) {
        MMI_HILOGE("Set Key down duration failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t InputManagerImpl::SetTouchpadScrollSwitch(bool switchFlag)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetTouchpadScrollSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Set the touchpad scroll switch failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::GetTouchpadScrollSwitch(bool &switchFlag)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetTouchpadScrollSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Get the touchpad scroll switch failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetTouchpadScrollDirection(bool state)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetTouchpadScrollDirection(state);
    if (ret != RET_OK) {
        MMI_HILOGE("Set the touchpad scroll direction switch failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::GetTouchpadScrollDirection(bool &state)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetTouchpadScrollDirection(state);
    if (ret != RET_OK) {
        MMI_HILOGE("Get the touchpad scroll direction switch failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetTouchpadTapSwitch(bool switchFlag)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetTouchpadTapSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Set the touchpad tap switch failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::GetTouchpadTapSwitch(bool &switchFlag)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetTouchpadTapSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Get the touchpad tap switch failed");
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetTouchpadPointerSpeed(int32_t speed)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetTouchpadPointerSpeed(speed);
    if (ret != RET_OK) {
        MMI_HILOGE("Set the touchpad pointer speed failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::GetTouchpadPointerSpeed(int32_t &speed)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetTouchpadPointerSpeed(speed);
    if (ret != RET_OK) {
        MMI_HILOGE("Get the touchpad pointer speed failed");
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetTouchpadPinchSwitch(bool switchFlag)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetTouchpadPinchSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Set the touchpad pinch switch failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::GetTouchpadPinchSwitch(bool &switchFlag)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetTouchpadPinchSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Get the touchpad pinch switch failed");
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetTouchpadSwipeSwitch(bool switchFlag)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetTouchpadSwipeSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Set the touchpad swipe switch failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::GetTouchpadSwipeSwitch(bool &switchFlag)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetTouchpadSwipeSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Get the touchpad swipe switch failed");
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetTouchpadRightClickType(int32_t type)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetTouchpadRightClickType(type);
    if (ret != RET_OK) {
        MMI_HILOGE("Set the touchpad right click type failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::GetTouchpadRightClickType(int32_t &type)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetTouchpadRightClickType(type);
    if (ret != RET_OK) {
        MMI_HILOGE("Get the touchpad right click failed");
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetTouchpadRotateSwitch(bool rotateSwitch)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetTouchpadRotateSwitch(rotateSwitch);
    if (ret != RET_OK) {
        MMI_HILOGE("Set touchpad rotate switch failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::GetTouchpadRotateSwitch(bool &rotateSwitch)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetTouchpadRotateSwitch(rotateSwitch);
    if (ret != RET_OK) {
        MMI_HILOGE("Get touchpad rotate switch failed");
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::EnableHardwareCursorStats(bool enable)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->EnableHardwareCursorStats(enable);
    if (ret != RET_OK) {
        MMI_HILOGE("Enable hardware cursor stats failed");
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::GetHardwareCursorStats(uint32_t &frameCount, uint32_t &vsyncCount)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetHardwareCursorStats(frameCount, vsyncCount);
    if (ret != RET_OK) {
        MMI_HILOGE("Get hardware cursor stats failed");
    }
    MMI_HILOGD("GetHardwareCursorStats, frameCount:%{public}d, vsyncCount:%{public}d", frameCount, vsyncCount);
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::GetPointerSnapshot(void *pixelMapPtr)
{
    CALL_DEBUG_ENTER;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetPointerSnapshot(pixelMapPtr);
    if (ret != RET_OK) {
        MMI_HILOGE("Get the pointer snapshot failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetTouchpadScrollRows(int32_t rows)
{
    CALL_INFO_TRACE;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetTouchpadScrollRows(rows);
    if (ret != RET_OK) {
        MMI_HILOGE("Set the number of touchpad scrolling rows failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device module does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::GetTouchpadScrollRows(int32_t &rows)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetTouchpadScrollRows(rows);
    if (ret != RET_OK) {
        MMI_HILOGE("Get the number of touchpad scrolling rows failed");
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetNapStatus(int32_t pid, int32_t uid, const std::string &bundleName, int32_t napStatus)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetNapStatus(pid, uid, bundleName, napStatus);
    if (ret != RET_OK) {
        MMI_HILOGE("Set napStatus failed, ret:%{public}d", ret);
    }
    return ret;
}

void InputManagerImpl::NotifyBundleName(int32_t pid, int32_t uid, const std::string &bundleName, int32_t syncStatus)
{
    CALL_INFO_TRACE;
    CHKPV(eventObserver_);
    eventObserver_->SyncBundleName(pid, uid, bundleName, syncStatus);
}

void InputManagerImpl::SetWindowPointerStyle(WindowArea area, int32_t pid, int32_t windowId)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Get mmi client is nullptr");
        return;
    }
    SendWindowAreaInfo(area, pid, windowId);
#else
    MMI_HILOGW("Pointer device or pointer drawing module does not support");
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
}

void InputManagerImpl::SendWindowAreaInfo(WindowArea area, int32_t pid, int32_t windowId)
{
    CALL_INFO_TRACE;
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPV(client);
    NetPacket pkt(MmiMessageId::WINDOW_AREA_INFO);
    pkt << area << pid << windowId;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write logical data failed");
        return;
    }
    if (!client->SendMessage(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
    }
}

void InputManagerImpl::ClearWindowPointerStyle(int32_t pid, int32_t windowId)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Get mmi client is nullptr");
        return;
    }
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->ClearWindowPointerStyle(pid, windowId);
    if (ret != RET_OK) {
        MMI_HILOGE("ClearWindowPointerStyle failed, ret:%{public}d", ret);
        return;
    }
}

int32_t InputManagerImpl::SetShieldStatus(int32_t shieldMode, bool isShield)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetShieldStatus(shieldMode, isShield);
    if (ret != RET_OK) {
        MMI_HILOGE("Set shield event interception status failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Keyboard device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

int32_t InputManagerImpl::GetShieldStatus(int32_t shieldMode, bool &isShield)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetShieldStatus(shieldMode, isShield);
    if (ret != RET_OK) {
        MMI_HILOGE("Get shield event interception status failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Keyboard device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

void InputManagerImpl::AddServiceWatcher(std::shared_ptr<IInputServiceWatcher> watcher)
{
    CALL_INFO_TRACE;
    MULTIMODAL_INPUT_CONNECT_MGR->AddServiceWatcher(watcher);
}

void InputManagerImpl::RemoveServiceWatcher(std::shared_ptr<IInputServiceWatcher> watcher)
{
    CALL_INFO_TRACE;
    MULTIMODAL_INPUT_CONNECT_MGR->RemoveServiceWatcher(watcher);
}

int32_t InputManagerImpl::MarkProcessed(int32_t eventId, int64_t actionTime)
{
    CALL_DEBUG_ENTER;
    ANRHDL->SetLastProcessedEventId(EVENT_TYPE, eventId, actionTime);
    return RET_OK;
}

int32_t InputManagerImpl::GetKeyState(std::vector<int32_t> &pressedKeys, std::map<int32_t, int32_t> &specialKeysState)
{
    CALL_INFO_TRACE;
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetKeyState(pressedKeys, specialKeysState);
    if (ret != RET_OK) {
        MMI_HILOGE("Get key state failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

void InputManagerImpl::Authorize(bool isAuthorize)
{
    if (MMIEventHdl.Authorize(isAuthorize) != RET_OK) {
        MMI_HILOGE("Failed to authorize");
    }
}

int32_t InputManagerImpl::CancelInjection()
{
    if (MMIEventHdl.CancelInjection() != RET_OK) {
        MMI_HILOGE("CancelInjection failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputManagerImpl::HasIrEmitter(bool &hasIrEmitter)
{
    CALL_INFO_TRACE;
    return MULTIMODAL_INPUT_CONNECT_MGR->HasIrEmitter(hasIrEmitter);
}

int32_t InputManagerImpl::GetInfraredFrequencies(std::vector<InfraredFrequency>& requencys)
{
    CALL_INFO_TRACE;
    return MULTIMODAL_INPUT_CONNECT_MGR->GetInfraredFrequencies(requencys);
}

int32_t InputManagerImpl::TransmitInfrared(int64_t number, std::vector<int64_t>& pattern)
{
    CALL_INFO_TRACE;
    return MULTIMODAL_INPUT_CONNECT_MGR->TransmitInfrared(number, pattern);
}

int32_t InputManagerImpl::SetPixelMapData(int32_t infoId, void* pixelMap)
{
    CALL_DEBUG_ENTER;
    if (infoId < 0 || pixelMap == nullptr) {
        MMI_HILOGE("Invalid infoId or pixelMap");
        return RET_ERR;
    }
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetPixelMapData(infoId, pixelMap);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to set pixel map, ret:%{public}d", ret);
    }
    return ret;
}

int32_t InputManagerImpl::SetCurrentUser(int32_t userId)
{
    CALL_DEBUG_ENTER;
    if (userId < 0) {
        MMI_HILOGE("Invalid userId");
        return RET_ERR;
    }
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetCurrentUser(userId);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to set userId, ret:%{public}d", ret);
    }
    return ret;
}

int32_t InputManagerImpl::SetMoveEventFilters(bool flag)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetMoveEventFilters(flag);
    if (ret != RET_OK) {
        MMI_HILOGE("Set move event filters failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Set move event filters does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
}

int32_t InputManagerImpl::SetTouchpadThreeFingersTapSwitch(bool switchFlag)
{
    CALL_DEBUG_ENTER;
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->SetTouchpadThreeFingersTapSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to SetTouchpadThreeFingersTapSwitch, ret:%{public}d", ret);
    }
    return ret;
}

int32_t InputManagerImpl::GetTouchpadThreeFingersTapSwitch(bool &switchFlag)
{
    CALL_DEBUG_ENTER;
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->GetTouchpadThreeFingersTapSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to GetTouchpadThreeFingersTapSwitch, ret:%{public}d", ret);
    }
    return ret;
}

int32_t InputManagerImpl::GetWinSyncBatchSize(int32_t maxAreasCount, int32_t displayCount)
{
    return (MAX_PKT_SIZE - GetDisplayMaxSize() * displayCount) / GetWindowMaxSize(maxAreasCount);
}

int32_t InputManagerImpl::AddVirtualInputDevice(std::shared_ptr<InputDevice> device, int32_t &deviceId)
{
    return MULTIMODAL_INPUT_CONNECT_MGR->AddVirtualInputDevice(device, deviceId);
}

int32_t InputManagerImpl::RemoveVirtualInputDevice(int32_t deviceId)
{
    return MULTIMODAL_INPUT_CONNECT_MGR->RemoveVirtualInputDevice(deviceId);
}

int32_t InputManagerImpl::AncoAddChannel(std::shared_ptr<IAncoConsumer> consumer)
{
#ifdef OHOS_BUILD_ENABLE_ANCO
    std::lock_guard<std::mutex> guard(mtx_);
    if (ancoChannels_.find(consumer) != ancoChannels_.end()) {
        return RET_OK;
    }
    sptr<IAncoChannel> tChannel = sptr<AncoChannel>::MakeSptr(consumer);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->AncoAddChannel(tChannel);
    if (ret != RET_OK) {
        MMI_HILOGE("AncoAddChannel fail, error:%{public}d", ret);
        return ret;
    }
    ancoChannels_.emplace(consumer, tChannel);
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_ANCO
    MMI_HILOGI("AncoAddChannel function does not support");
    return ERROR_UNSUPPORT;
}

int32_t InputManagerImpl::AncoRemoveChannel(std::shared_ptr<IAncoConsumer> consumer)
{
#ifdef OHOS_BUILD_ENABLE_ANCO
    std::lock_guard<std::mutex> guard(mtx_);
    auto iter = ancoChannels_.find(consumer);
    if (iter == ancoChannels_.end()) {
        MMI_HILOGI("Not associated with any channel");
        return RET_OK;
    }
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->AncoRemoveChannel(iter->second);
    if (ret != RET_OK) {
        MMI_HILOGE("AncoRemoveChannel fail, error:%{public}d", ret);
        return ret;
    }
    ancoChannels_.erase(iter);
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_ANCO
    MMI_HILOGI("AncoRemoveChannel function does not support");
    return ERROR_UNSUPPORT;
}
} // namespace MMI
} // namespace OHOS