/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "define_multimodal.h"
#include "error_multimodal.h"

#include "bytrace_adapter.h"
#include "event_filter_service.h"
#include "mmi_client.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"
#include "input_scene_board_judgement.h"
#include "switch_event_input_subscribe_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputManagerImpl" };
constexpr size_t MAX_FILTER_NUM = 4;
constexpr int32_t MAX_DELAY = 4000;
constexpr int32_t MIN_DELAY = 0;
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
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->GetDisplayBindInfo(infos);
    if (ret != RET_OK) {
        MMI_HILOGE("GetDisplayBindInfo failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputManagerImpl::GetAllMmiSubscribedEvents(std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> &datas)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->GetAllMmiSubscribedEvents(datas);
    if (ret != RET_OK) {
        MMI_HILOGE("GetDisplayBindInfo failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputManagerImpl::SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg)
{
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->SetDisplayBind(deviceId, displayId, msg);
    if (ret != RET_OK) {
        MMI_HILOGE("SetDisplayBind failed, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputManagerImpl::GetWindowPid(int32_t windowId)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    return MultimodalInputConnMgr->GetWindowPid(windowId);
}

void InputManagerImpl::UpdateDisplayInfo(const DisplayGroupInfo &displayGroupInfo)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Get mmi client is nullptr");
        return;
    }
    if (displayGroupInfo.windowsInfo.empty() || displayGroupInfo.displaysInfo.empty()) {
        MMI_HILOGE("The windows info or display info is empty!");
        return;
    }
    if (!IsValiadWindowAreas(displayGroupInfo.windowsInfo)) {
        return;
    }
    displayGroupInfo_ = displayGroupInfo;
    SendDisplayInfo();
    PrintDisplayInfo();
}

void InputManagerImpl::UpdateWindowInfo(const WindowGroupInfo &windowGroupInfo)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Get mmi client is nullptr");
        return;
    }
    if (!IsValiadWindowAreas(windowGroupInfo.windowsInfo)) {
        return;
    }
    windowGroupInfo_ = windowGroupInfo;
    SendWindowInfo();
    PrintWindowGroupInfo();
}

bool InputManagerImpl::IsValiadWindowAreas(const std::vector<WindowInfo> &windows)
{
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
            (window.defaultHotAreas.size() > WindowInfo::MAX_HOTAREA_COUNT) ||
            (window.pointerHotAreas.size() > WindowInfo::MAX_HOTAREA_COUNT) ||
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

#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
void InputManagerImpl::SetEnhanceConfig(uint8_t *cfg, uint32_t cfgLen)
{
    CALL_DEBUG_ENTER;
    if (cfg == nullptr || cfgLen == 0) {
        MMI_HILOGE("SecCompEnhance cfg info is empty!");
        return;
    }
    enhanceCfg_ = new (std::nothrow) uint8_t[cfgLen];
    if (memcpy_s(enhanceCfg_, cfgLen, cfg, cfgLen)) {
        MMI_HILOGE("cfg memcpy failed!");
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
    int32_t ret = MultimodalInputConnMgr->AddInputEventFilter(service, filterId, priority, deviceTags);
    if (ret != RET_OK) {
        MMI_HILOGE("AddInputEventFilter has send to server failed, priority:%{public}d, ret:%{public}d", priority, ret);
        service = nullptr;
        return RET_ERR;
    }
    auto it = eventFilterServices_.emplace(filterId, std::make_tuple(service, priority, deviceTags));
    if (!it.second) {
        MMI_HILOGW("Filter id duplicate");
    }
    return filterId;
}

int32_t InputManagerImpl::AddInputEventObserver(std::shared_ptr<MMIEventObserver> observer)
{
    CALL_DEBUG_ENTER;
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
    CALL_DEBUG_ENTER;
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mtx_);
    eventObserver_ = nullptr;
    int32_t ret = MultimodalInputConnMgr->RemoveInputEventObserver();
    return ret;
}

int32_t InputManagerImpl::NotifyNapOnline()
{
    CALL_DEBUG_ENTER;
    int32_t ret = MultimodalInputConnMgr->NotifyNapOnline();
    return ret;
}

int32_t InputManagerImpl::RemoveInputEventFilter(int32_t filterId)
{
    CALL_INFO_TRACE;
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
    int32_t ret = MultimodalInputConnMgr->RemoveInputEventFilter(filterId);
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

EventHandlerPtr InputManagerImpl::GetEventHandler() const
{
    if (eventHandler_ == nullptr) {
        MMI_HILOGD("eventHandler_ is nullptr");
        auto MMIClient = MMIEventHdl.GetMMIClient();
        if (MMIClient == nullptr) {
            MMI_HILOGE("Get MMIClient is failed");
            return nullptr;
        }
        return MMIClient->GetEventHandler();
    }
    return eventHandler_;
}

void InputManagerImpl::SetWindowInputEventConsumer(std::shared_ptr<IInputEventConsumer> inputEventConsumer,
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler)
{
    CALL_DEBUG_ENTER;
    CHK_PID_AND_TID();
    CHKPV(inputEventConsumer);
    CHKPV(eventHandler);
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient(eventHandler)) {
        MMI_HILOGE("Client init failed");
        return;
    }
    consumer_ = inputEventConsumer;
    eventHandler_ = eventHandler;
}

int32_t InputManagerImpl::SubscribeKeyEvent(std::shared_ptr<KeyOption> keyOption,
    std::function<void(std::shared_ptr<KeyEvent>)> callback)
{
    CALL_DEBUG_ENTER;
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

int32_t InputManagerImpl::SubscribeSwitchEvent(std::function<void(std::shared_ptr<SwitchEvent>)> callback)
{
    CALL_INFO_TRACE;
    CHK_PID_AND_TID();
#ifdef OHOS_BUILD_ENABLE_SWITCH
    CHKPR(callback, RET_ERR);
    return SWITCH_EVENT_INPUT_SUBSCRIBE_MGR.SubscribeSwitchEvent(callback);
#else
    MMI_HILOGW("switch device does not support");
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
    MMI_HILOGW("switch device does not support");
#endif // OHOS_BUILD_ENABLE_SWITCH
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void InputManagerImpl::OnKeyEventTask(std::shared_ptr<IInputEventConsumer> consumer,
    std::shared_ptr<KeyEvent> keyEvent)
{
    CHK_PID_AND_TID();
    CHKPV(consumer);
    consumer->OnInputEvent(keyEvent);
    MMI_HILOGD("Key event callback keyCode:%{public}d", keyEvent->GetKeyCode());
}

void InputManagerImpl::OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHK_PID_AND_TID();
    CHKPV(keyEvent);
    CHKPV(eventHandler_);
    CHKPV(consumer_);
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler = nullptr;
    std::shared_ptr<IInputEventConsumer> inputConsumer = nullptr;
    {
        std::lock_guard<std::mutex> guard(mtx_);
        eventHandler = eventHandler_;
        inputConsumer = consumer_;
    }
    MMI_HILOGI("InputTracking id:%{public}d Key Event", keyEvent->GetId());
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::KEY_DISPATCH_EVENT);
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPV(client);
    if (client->IsEventHandlerChanged()) {
        if (!eventHandler->PostHighPriorityTask(std::bind(&InputManagerImpl::OnKeyEventTask,
            this, inputConsumer, keyEvent))) {
            MMI_HILOGE("Post task failed");
            return;
        }
    } else {
        inputConsumer->OnInputEvent(keyEvent);
        MMI_HILOGD("Key event report keyCode:%{public}d", keyEvent->GetKeyCode());
    }
    MMI_HILOGD("Key event keyCode:%{public}d", keyEvent->GetKeyCode());
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
void InputManagerImpl::OnPointerEventTask(std::shared_ptr<IInputEventConsumer> consumer,
    std::shared_ptr<PointerEvent> pointerEvent)
{
    CHK_PID_AND_TID();
    CHKPV(consumer);
    CHKPV(pointerEvent);
    consumer->OnInputEvent(pointerEvent);
    MMI_HILOGD("Pointer event callback pointerId:%{public}d", pointerEvent->GetPointerId());
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
        std::lock_guard<std::mutex> guard(mtx_);
        eventHandler = eventHandler_;
        inputConsumer = consumer_;
    }
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::POINT_DISPATCH_EVENT);
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPV(client);
    if (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_MOVE) {
        MMI_HILOGI("InputTracking id:%{public}d Pointer Event", pointerEvent->GetId());
    }
    if (client->IsEventHandlerChanged()) {
        if (!eventHandler->PostHighPriorityTask(std::bind(&InputManagerImpl::OnPointerEventTask,
            this, inputConsumer, pointerEvent))) {
            MMI_HILOGE("Post task failed");
            return;
        }
    } else {
        inputConsumer->OnInputEvent(pointerEvent);
    }
    MMI_HILOGD("Pointer event pointerId:%{public}d", pointerEvent->GetPointerId());
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

int32_t InputManagerImpl::PackDisplayData(NetPacket &pkt)
{
    pkt << displayGroupInfo_.width << displayGroupInfo_.height << displayGroupInfo_.focusWindowId;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write logical data failed");
        return RET_ERR;
    }
    if (PackWindowInfo(pkt) == RET_ERR) {
        MMI_HILOGE("Packet write windows info failed");
        return RET_ERR;
    }
    return PackDisplayInfo(pkt);
}

int32_t InputManagerImpl::PackWindowGroupInfo(NetPacket &pkt)
{
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
            << item.transform;
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
    if (enhanceCfg_ == nullptr) {
        MMI_HILOGE("security info config failed");
        return RET_ERR;
    }
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

int32_t InputManagerImpl::PackWindowInfo(NetPacket &pkt)
{
    uint32_t num = static_cast<uint32_t>(displayGroupInfo_.windowsInfo.size());
    pkt << num;
    for (const auto &item : displayGroupInfo_.windowsInfo) {
        pkt << item.id << item.pid << item.uid << item.area
            << item.defaultHotAreas << item.pointerHotAreas
            << item.agentWindowId << item.flags << item.action
            << item.displayId << item.zOrder << item.pointerChangeAreas
            << item.transform;
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write windows data failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputManagerImpl::PackDisplayInfo(NetPacket &pkt)
{
    uint32_t num = static_cast<uint32_t>(displayGroupInfo_.displaysInfo.size());
    pkt << num;
    for (const auto &item : displayGroupInfo_.displaysInfo) {
        pkt << item.id << item.x << item.y << item.width
            << item.height << item.dpi << item.name << item.uniq << item.direction
            << item.displayMode;
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write display data failed");
        return RET_ERR;
    }
    return RET_OK;
}

void InputManagerImpl::PrintWindowInfo(const std::vector<WindowInfo> &windowsInfo)
{
    for (const auto &item : windowsInfo) {
        MMI_HILOGD("windowsInfos,id:%{public}d,pid:%{public}d,uid:%{public}d,"
            "area.x:%{public}d,area.y:%{public}d,area.width:%{public}d,area.height:%{public}d,"
            "defaultHotAreas.size:%{public}zu,pointerHotAreas.size:%{public}zu,"
            "agentWindowId:%{public}d,flags:%{public}d,action:%{public}d,displayId:%{public}d,"
            "zOrder:%{public}f",
            item.id, item.pid, item.uid, item.area.x, item.area.y, item.area.width,
            item.area.height, item.defaultHotAreas.size(), item.pointerHotAreas.size(),
            item.agentWindowId, item.flags, item.action, item.displayId, item.zOrder);
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

void InputManagerImpl::PrintDisplayInfo()
{
    MMI_HILOGD("logicalInfo,width:%{public}d,height:%{public}d,focusWindowId:%{public}d",
        displayGroupInfo_.width, displayGroupInfo_.height, displayGroupInfo_.focusWindowId);
    MMI_HILOGD("windowsInfos,num:%{public}zu", displayGroupInfo_.windowsInfo.size());

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
    MMI_HILOGD("windowsGroupInfo,focusWindowId:%{public}d,displayId:%{public}d",
        windowGroupInfo_.focusWindowId, windowGroupInfo_.displayId);
    PrintWindowInfo(windowGroupInfo_.windowsInfo);
}

#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
void InputManagerImpl::PrintEnhanceConfig()
{
    if (enhanceCfg_ == nullptr) {
        MMI_HILOGE("SecCompEnhanceCfg is null");
        return;
    }
    MMI_HILOGD("securityConfigInfo, cfg len:%{public}d", enhanceCfgLen_);
}
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT

int32_t InputManagerImpl::AddMonitor(std::function<void(std::shared_ptr<KeyEvent>)> monitor)
{
    CALL_INFO_TRACE;
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_MONITOR)
    CHKPR(monitor, INVALID_HANDLER_ID);
    auto consumer = std::make_shared<MonitorEventConsumer>(monitor);
    return AddMonitor(consumer);
#else
    MMI_HILOGW("Keyboard device or monitor function does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_KEYBOARD || OHOS_BUILD_ENABLE_MONITOR
}

int32_t InputManagerImpl::AddMonitor(std::function<void(std::shared_ptr<PointerEvent>)> monitor)
{
    CALL_INFO_TRACE;
#if (defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)) && defined(OHOS_BUILD_ENABLE_MONITOR)
    CHKPR(monitor, INVALID_HANDLER_ID);
    auto consumer = std::make_shared<MonitorEventConsumer>(monitor);
    return AddMonitor(consumer);
#else
    MMI_HILOGW("Pointer/touchscreen device or monitor function does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_MONITOR ||  OHOS_BUILD_ENABLE_TOUCH && OHOS_BUILD_ENABLE_MONITOR
}

int32_t InputManagerImpl::AddMonitor(std::shared_ptr<IInputEventConsumer> consumer)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_MONITOR
    CHKPR(consumer, INVALID_HANDLER_ID);
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return IMonitorMgr->AddMonitor(consumer);
#else
    MMI_HILOGI("Monitor function does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_MONITOR
}

void InputManagerImpl::RemoveMonitor(int32_t monitorId)
{
    CALL_INFO_TRACE;
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
    CALL_DEBUG_ENTER;
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
    CALL_INFO_TRACE;
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
    CALL_INFO_TRACE;
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
    CALL_INFO_TRACE;
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

void InputManagerImpl::SimulateInputEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    CHKPV(keyEvent);
    if (MMIEventHdl.InjectEvent(keyEvent) != RET_OK) {
        MMI_HILOGE("Failed to inject keyEvent");
    }
#else
    MMI_HILOGW("Keyboard device does not support");
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

void InputManagerImpl::SimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    CHKPV(pointerEvent);
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE ||
        pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHPAD) {
#ifndef OHOS_BUILD_ENABLE_POINTER
        MMI_HILOGW("Pointer device does not support");
        return;
#endif
    }
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
#ifndef OHOS_BUILD_ENABLE_TOUCH
        MMI_HILOGW("Touchscreen device does not support");
        return;
#endif
    }
#ifndef OHOS_BUILD_ENABLE_JOYSTICK
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_JOYSTICK) {
        MMI_HILOGW("Joystick device does not support");
        return;
    }
#endif
    if (MMIEventHdl.InjectPointerEvent(pointerEvent) != RET_OK) {
        MMI_HILOGE("Failed to inject pointer event");
    }
#else
    MMI_HILOGW("Pointer and touchscreen device does not support");
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
}

int32_t InputManagerImpl::SetMouseScrollRows(int32_t rows)
{
    CALL_DEBUG_ENTER;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->SetMouseScrollRows(rows);
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
    CALL_DEBUG_ENTER;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t winPid = GetWindowPid(windowId);
    if (winPid == -1) {
        MMI_HILOGE("winPid is invalid");
        return RET_ERR;
    }
    int32_t ret = MultimodalInputConnMgr->SetCustomCursor(winPid, windowId, focusX, focusY, pixelMap);
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
    CALL_DEBUG_ENTER;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t winPid = GetWindowPid(windowId);
    if (winPid == -1) {
        MMI_HILOGE("winPid is invalid return -1");
        return RET_ERR;
    }
    int32_t ret = MultimodalInputConnMgr->SetMouseIcon(winPid, windowId, pixelMap);
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
    CALL_DEBUG_ENTER;
#if defined OHOS_BUILD_ENABLE_POINTER
    int32_t winPid = GetWindowPid(windowId);
    if (winPid == -1) {
        MMI_HILOGE("winPid is invalid return -1");
        return RET_ERR;
    }
    int32_t ret = MultimodalInputConnMgr->SetMouseHotSpot(winPid, windowId, hotSpotX, hotSpotY);
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
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->GetMouseScrollRows(rows);
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
    CALL_DEBUG_ENTER;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->SetPointerSize(size);
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
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->GetPointerSize(size);
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
    CALL_DEBUG_ENTER;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    if (primaryButton != LEFT_BUTTON && primaryButton != RIGHT_BUTTON) {
        MMI_HILOGE("primaryButton is invalid");
        return RET_ERR;
    }
    int32_t ret = MultimodalInputConnMgr->SetMousePrimaryButton(primaryButton);
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
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->GetMousePrimaryButton(primaryButton);
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
    CALL_DEBUG_ENTER;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->SetHoverScrollState(state);
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
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->GetHoverScrollState(state);
    if (ret != RET_OK) {
        MMI_HILOGE("Get mouse hover scroll state failed, ret:%{public}d", ret);
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetPointerVisible(bool visible)
{
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->SetPointerVisible(visible);
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
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    bool visible;
    int32_t ret = MultimodalInputConnMgr->IsPointerVisible(visible);
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
    CALL_DEBUG_ENTER;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->SetPointerColor(color);
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
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->GetPointerColor(color);
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
    CALL_DEBUG_ENTER;
    int32_t ret = MultimodalInputConnMgr->EnableCombineKey(enable);
    if (ret != RET_OK) {
        MMI_HILOGE("Enable combine key failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t InputManagerImpl::SetPointerSpeed(int32_t speed)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = MultimodalInputConnMgr->SetPointerSpeed(speed);
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
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ret = MultimodalInputConnMgr->GetPointerSpeed(speed);
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

int32_t InputManagerImpl::SetPointerStyle(int32_t windowId, const PointerStyle& pointerStyle)
{
    CALL_DEBUG_ENTER;
    if (pointerStyle.id < 0) {
        MMI_HILOGE("The param is invalid");
        return RET_ERR;
    }

    int32_t ret = MultimodalInputConnMgr->SetPointerStyle(windowId, pointerStyle);
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer style failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t InputManagerImpl::GetPointerStyle(int32_t windowId, PointerStyle &pointerStyle)
{
    CALL_DEBUG_ENTER;
    int32_t ret = MultimodalInputConnMgr->GetPointerStyle(windowId, pointerStyle);
    if (ret != RET_OK) {
        MMI_HILOGE("Get pointer style failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

void InputManagerImpl::OnConnected()
{
    CALL_DEBUG_ENTER;
    ReAddInputEventFilter();
    if (displayGroupInfo_.windowsInfo.empty() || displayGroupInfo_.displaysInfo.empty()) {
        MMI_HILOGD("The windows info or display info is empty");
        return;
    }
    SendDisplayInfo();
    PrintDisplayInfo();
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    SendEnhanceConfig();
    PrintEnhanceConfig();
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    if (anrObservers_.empty()) {
        return;
    }
    int32_t ret = MultimodalInputConnMgr->SetAnrObserver();
    if (ret != RET_OK) {
        MMI_HILOGE("Set anr observer failed, ret:%{public}d", ret);
    }
}

void InputManagerImpl::SendDisplayInfo()
{
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPV(client);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    if (PackDisplayData(pkt) == RET_ERR) {
        MMI_HILOGE("Pack display info failed");
        return;
    }
    if (!client->SendMessage(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
    }
}

void InputManagerImpl::SendWindowInfo()
{
    CALL_DEBUG_ENTER;
    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    CHKPV(client);
    NetPacket pkt(MmiMessageId::WINDOW_INFO);
    if (PackWindowGroupInfo(pkt) == RET_ERR) {
        MMI_HILOGE("Pack window group info failed");
        return;
    }
    if (!client->SendMessage(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
    }
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
    CALL_DEBUG_ENTER;
    if (eventFilterServices_.size() > MAX_FILTER_NUM) {
        MMI_HILOGE("Too many filters, size:%{public}zu", eventFilterServices_.size());
        return;
    }
    for (const auto &[filterId, t] : eventFilterServices_) {
        const auto &[service, priority, deviceTags] = t;
        int32_t ret = MultimodalInputConnMgr->AddInputEventFilter(service, filterId, priority, deviceTags);
        if (ret != RET_OK) {
            MMI_HILOGE("AddInputEventFilter has send to server failed, filterId:%{public}d, priority:%{public}d,"
                "deviceTags:%{public}u, ret:%{public}d", filterId, priority, deviceTags, ret);
        }
    }
}

int32_t InputManagerImpl::RegisterDevListener(std::string type, std::shared_ptr<IInputDeviceListener> listener)
{
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputDevImpl.RegisterDevListener(type, listener);
}

int32_t InputManagerImpl::UnregisterDevListener(std::string type,
    std::shared_ptr<IInputDeviceListener> listener)
{
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputDevImpl.UnregisterDevListener(type, listener);
}

int32_t InputManagerImpl::GetDeviceIds(std::function<void(std::vector<int32_t>&)> callback)
{
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputDevImpl.GetInputDeviceIds(callback);
}

int32_t InputManagerImpl::GetDevice(int32_t deviceId,
    std::function<void(std::shared_ptr<InputDevice>)> callback)
{
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputDevImpl.GetInputDevice(deviceId, callback);
}

int32_t InputManagerImpl::SupportKeys(int32_t deviceId, std::vector<int32_t> &keyCodes,
    std::function<void(std::vector<bool>&)> callback)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputDevImpl.SupportKeys(deviceId, keyCodes, callback);
}

int32_t InputManagerImpl::GetKeyboardType(int32_t deviceId, std::function<void(int32_t)> callback)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputDevImpl.GetKeyboardType(deviceId, callback);
}

int32_t InputManagerImpl::SetKeyboardRepeatDelay(int32_t delay)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputDevImpl.SetKeyboardRepeatDelay(delay);
}

int32_t InputManagerImpl::SetKeyboardRepeatRate(int32_t rate)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputDevImpl.SetKeyboardRepeatRate(rate);
}

int32_t InputManagerImpl::GetKeyboardRepeatDelay(std::function<void(int32_t)> callback)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputDevImpl.GetKeyboardRepeatDelay(callback);
}

int32_t InputManagerImpl::GetKeyboardRepeatRate(std::function<void(int32_t)> callback)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return RET_ERR;
    }
    return InputDevImpl.GetKeyboardRepeatRate(callback);
}

void InputManagerImpl::SetAnrObserver(std::shared_ptr<IAnrObserver> observer)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return;
    }
    for (auto iter = anrObservers_.begin(); iter != anrObservers_.end(); ++iter) {
        if (*iter == observer) {
            MMI_HILOGE("Observer already exist");
            return;
        }
    }
    anrObservers_.push_back(observer);
    int32_t ret = MultimodalInputConnMgr->SetAnrObserver();
    if (ret != RET_OK) {
        MMI_HILOGE("Set anr observer failed, ret:%{public}d", ret);
    }
}

void InputManagerImpl::OnAnr(int32_t pid)
{
    CALL_DEBUG_ENTER;
    CHK_PID_AND_TID();
    {
        std::lock_guard<std::mutex> guard(mtx_);
        for (const auto &observer : anrObservers_) {
            CHKPC(observer);
            observer->OnAnr(pid);
        }
    }
    MMI_HILOGI("ANR noticed pid:%{public}d", pid);
}

bool InputManagerImpl::GetFunctionKeyState(int32_t funcKey)
{
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    CALL_DEBUG_ENTER;
    bool state { false };
    int32_t ret = MultimodalInputConnMgr->GetFunctionKeyState(funcKey, state);
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
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    CALL_DEBUG_ENTER;
    int32_t ret = MultimodalInputConnMgr->SetFunctionKeyState(funcKey, enable);
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
    CALL_DEBUG_ENTER;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t ret = MultimodalInputConnMgr->SetPointerLocation(x, y);
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
#if defined(OHOS_BUILD_ENABLE_POINTER)
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->SetMouseCaptureMode(windowId, true);
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
#if defined(OHOS_BUILD_ENABLE_POINTER)
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->SetMouseCaptureMode(windowId, false);
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
    CALL_DEBUG_ENTER;
    if (extraData.buffer.size() > ExtraData::MAX_BUFFER_SIZE) {
        MMI_HILOGE("Append extra data failed, buffer is oversize:%{public}zu", extraData.buffer.size());
        return;
    }
    int32_t ret = MultimodalInputConnMgr->AppendExtraData(extraData);
    if (ret != RET_OK) {
        MMI_HILOGE("Append extra data failed:%{public}d", ret);
    }
}

int32_t InputManagerImpl::EnableInputDevice(bool enable)
{
    CALL_DEBUG_ENTER;
    int32_t ret = MultimodalInputConnMgr->EnableInputDevice(enable);
    if (ret != RET_OK) {
        MMI_HILOGE("Enable input device failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t InputManagerImpl::SetKeyDownDuration(const std::string &businessId, int32_t delay)
{
    CALL_DEBUG_ENTER;
    if (delay < MIN_DELAY || delay > MAX_DELAY) {
        MMI_HILOGE("The param is invalid");
        return RET_ERR;
    }
    int32_t ret = MultimodalInputConnMgr->SetKeyDownDuration(businessId, delay);
    if (ret != RET_OK) {
        MMI_HILOGE("Set Key down duration failed, ret:%{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t InputManagerImpl::SetTouchpadScrollSwitch(bool switchFlag)
{
    CALL_DEBUG_ENTER;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->SetTouchpadScrollSwitch(switchFlag);
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
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->GetTouchpadScrollSwitch(switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("Get the touchpad scroll switch failed");
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetTouchpadScrollDirection(bool state)
{
    CALL_DEBUG_ENTER;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->SetTouchpadScrollDirection(state);
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
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->GetTouchpadScrollDirection(state);
    if (ret != RET_OK) {
        MMI_HILOGE("Get the touchpad scroll direction switch failed");
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}

int32_t InputManagerImpl::SetTouchpadTapSwitch(bool switchFlag)
{
    CALL_DEBUG_ENTER;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->SetTouchpadTapSwitch(switchFlag);
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
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->GetTouchpadTapSwitch(switchFlag);
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
    CALL_DEBUG_ENTER;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->SetTouchpadPointerSpeed(speed);
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
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->GetTouchpadPointerSpeed(speed);
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
    CALL_DEBUG_ENTER;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->SetTouchpadPinchSwitch(switchFlag);
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
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->GetTouchpadPinchSwitch(switchFlag);
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
    CALL_DEBUG_ENTER;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->SetTouchpadSwipeSwitch(switchFlag);
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
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->GetTouchpadSwipeSwitch(switchFlag);
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
    CALL_DEBUG_ENTER;
#if defined OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->SetTouchpadRightClickType(type);
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
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->GetTouchpadRightClickType(type);
    if (ret != RET_OK) {
        MMI_HILOGE("Get the touchpad right click failed");
    }
    return ret;
#else
    MMI_HILOGW("Pointer device does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_POINTER
}
void InputManagerImpl::SetWindowCheckerHandler(std::shared_ptr<IWindowChecker> windowChecker)
{
    #if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
        CALL_DEBUG_ENTER;
        CHKPV(windowChecker);
        MMI_HILOGD("winChecker_ is not null in  %{public}d", getpid());
        winChecker_ = windowChecker;
    #endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    return;
}

int32_t InputManagerImpl::SetNapStatus(int32_t pid, int32_t uid, std::string bundleName, int32_t napStatus)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->SetNapStatus(pid, uid, bundleName, napStatus);
    if (ret != RET_OK) {
        MMI_HILOGE("Set napStatus failed, ret:%{public}d", ret);
    }
    return ret;
}

void InputManagerImpl::NotifyBundleName(int32_t pid, int32_t uid, std::string bundleName, int32_t syncStatus)
{
    CALL_DEBUG_ENTER;
    if (eventObserver_ == nullptr) {
        MMI_HILOGE("eventObserver_ is nullptr");
        return;
    }
    eventObserver_->SyncBundleName(pid, uid, bundleName, syncStatus);
}

void InputManagerImpl::SetWindowPointerStyle(WindowArea area, int32_t pid, int32_t windowId)
{
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Get mmi client is nullptr");
        return;
    }
    SendWindowAreaInfo(area, pid, windowId);
    return;
#else
    MMI_HILOGW("Pointer device or pointer drawing module does not support");
    return;
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
}

void InputManagerImpl::SendWindowAreaInfo(WindowArea area, int32_t pid, int32_t windowId)
{
    CALL_DEBUG_ENTER;
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
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Get mmi client is nullptr");
        return;
    }
    int32_t ret = MultimodalInputConnMgr->ClearWindowPointerStyle(pid, windowId);
    if (ret != RET_OK) {
        MMI_HILOGE("ClearWindowPointerStyle failed, ret:%{public}d", ret);
        return;
    }
}

int32_t InputManagerImpl::SetShieldStatus(int32_t shieldMode, bool isShield)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->SetShieldStatus(shieldMode, isShield);
    if (ret != RET_OK) {
        MMI_HILOGE("Set shield event interception status failed, ret:%{public}d", ret);
    }
    return ret;
}

int32_t InputManagerImpl::GetShieldStatus(int32_t shieldMode, bool &isShield)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    int32_t ret = MultimodalInputConnMgr->GetShieldStatus(shieldMode, isShield);
    if (ret != RET_OK) {
        MMI_HILOGE("Get shield event interception status failed, ret:%{public}d", ret);
    }
    return ret;
}
} // namespace MMI
} // namespace OHOS
