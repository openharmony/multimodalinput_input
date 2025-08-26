/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <memory>
#include <iostream>
#include "i_input_event_handler.h"
#include "event_filter_handler.h"
#include "event_interceptor_handler.h"
#include "key_command_handler.h"
#include "event_monitor_handler.h"
#include "mmi_log.h"
#include "multimodal_input_plugin_manager.h"




#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MultiModalInputPluginManager"

namespace OHOS {
namespace MMI {

const char *FILE_EXTENSION = ".so";
const char *FOLDER_PATH = "/system/lib64/multimodalinput/autorun";
const int32_t TIMEOUT_US = 300;
const int32_t MAX_TIMER = 3;

InputPluginManager::~InputPluginManager()
{
    plugins_.clear();
    if (instance_ != nullptr) {
        instance_ = nullptr;
    }
    MMI_HILOGI("~InputPluginManager");
}

InputPluginManager* InputPluginManager::GetInstance(const std::string &directory)
{
    std::call_once(init_flag_, [directory] {
        if (instance_ == nullptr) {
            MMI_HILOGI("New InputPluginManager");
            std::string dir = directory.empty() ? FOLDER_PATH : directory;
            instance_ = new InputPluginManager(dir);
        }
    });
    return instance_;
}

int32_t InputPluginManager::Init(UDSServer& udsServer)
{
    CALL_DEBUG_ENTER;
    udsServer_ = udsServer;
    DIR *dir = opendir(directory_.c_str());
    if (!dir) {
        MMI_HILOGE("Failed to open error:%{private}s", strerror(errno));
        return RET_OK;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_REG && std::string(entry->d_name) != "." && std::string(entry->d_name) != "..") {
            std::string path = directory_ + "/" + entry->d_name;
            if (path.length() >= strlen(FILE_EXTENSION) &&
                path.substr(path.size() - strlen(FILE_EXTENSION)) == FILE_EXTENSION) {
                LoadPlugin(path);
            }
        }
    }
    closedir(dir);
    PrintPlugins();
    return RET_OK;
}

bool InputPluginManager::LoadPlugin(const std::string &path)
{
    CALL_DEBUG_ENTER;
    void *handle = dlopen(path.c_str(), RTLD_LAZY);
    if (!handle) {
        MMI_HILOGE("Failed to load directory: %{private}s", dlerror());
        return false;
    }

    InitPlugin func = reinterpret_cast<InitPlugin>(dlsym(handle, "InitPlugin"));
    if (!func) {
        MMI_HILOGE("Failed to find symbol InitPlugin in: %{private}s", dlerror());
        dlclose(handle);
        return false;
    }

    std::shared_ptr<InputPlugin> cPin = std::make_shared<InputPlugin>();
    if (!cPin) {
        dlclose(handle);
        return false;
    }

    cPin->unintPlugin_ = reinterpret_cast<UnintPlugin>(dlsym(handle, "UnintPlugin"));
    if (!cPin->unintPlugin_) {
        MMI_HILOGE("Failed to find symbol UnintPlugin in: %{private}s", dlerror());
        dlclose(handle);
        return false;
    }
    std::shared_ptr<IInputPlugin> iPin;
    int32_t ret = func(cPin, iPin);
    if (ret != 0 || !iPin) {
        MMI_HILOGE("Failed to InitPlugin plugin.");
        dlclose(handle);
        return false;
    }
    ret = cPin->Init(iPin);
    if (ret != 0) {
        MMI_HILOGE("Failed to Init plugin.");
        dlclose(handle);
        return false;
    }
    cPin->handle_ = handle;
    InputPluginStage stage = iPin->GetStage();

    auto result = plugins_.insert({stage, {cPin}});
    if (!result.second) {
        auto it = std::lower_bound(result.first->second.begin(), result.first->second.end(), cPin,
            [](const std::shared_ptr<IPluginContext> &a, const std::shared_ptr<IPluginContext> &b) {
                return a->GetPriority() < b->GetPriority();
            });
        result.first->second.insert(it, cPin);
    }
    return true;
}

void InputPluginManager::PrintPlugins()
{
    for (const auto &stagePlugins : plugins_) {
        MMI_HILOGI("InputPluginManager InputPluginStage : %{public}d", stagePlugins.first);
        for (const auto &plugin : stagePlugins.second) {
            MMI_HILOGI("InputPluginManager : name:%{public}s prio_:%{public}d",
                plugin->GetName().c_str(), plugin->GetPriority());
        }
    }
}

void InputPluginManager::PluginAssignmentCallBack(
    std::function<void(PluginEventType, int64_t)> callback, InputPluginStage stage)
{
    CALL_DEBUG_ENTER;
    auto it = plugins_.find(stage);
    if (it == plugins_.end()) {
        MMI_HILOGI("plugins_ not stage:%{public}d.", stage);
        return;
    }
    for (auto &plugin : it->second) {
        plugin->SetCallback(callback);
    }
}

PluginResult InputPluginManager::ProcessEvent(
    PluginEventType event, std::shared_ptr<IPluginContext> iplugin, std::shared_ptr<IPluginData> data)
{
    return std::visit(
        overloaded{
            [data, iplugin](libinput_event* evt) { return iplugin->HandleEvent(evt, data); },
            [data, iplugin](std::shared_ptr<PointerEvent> evt) { return iplugin->HandleEvent(evt, data); },
            [data, iplugin](std::shared_ptr<AxisEvent> evt) { return iplugin->HandleEvent(evt, data); },
            [data, iplugin](std::shared_ptr<KeyEvent> evt) { return iplugin->HandleEvent(evt, data); }
        }, event);
}

int32_t InputPluginManager::DoHandleEvent(
    PluginEventType event, std::shared_ptr<IPluginData> data, IPluginContext* iplugin)
{
    CALL_DEBUG_ENTER;
    InputPluginStage stage = data->stage;
    if (checkPluginEventNull(event)) {
        return RET_NOTDO;
    }
    auto it = plugins_.find(stage);
    if (it == plugins_.end()) {
        return RET_NOTDO;
    }

    auto &plugins = it->second;
    auto start_plugin = plugins.begin();
    if (iplugin != nullptr) {
        auto cur_plugin = std::find_if(plugins.begin(), plugins.end(),
            [iplugin](const std::shared_ptr<IPluginContext> &plugin) { return plugin.get() == iplugin; });
        if (cur_plugin == plugins.end()) {
            return RET_NOTDO;
        }
        start_plugin = std::next(cur_plugin);
    }
    int64_t beginTime = 0;
    PluginResult result;
    int64_t endTime = 0;
    int64_t lostTime = 0;
    for (auto pluginIt = start_plugin; pluginIt != plugins.end(); ++pluginIt) {
        if ((*pluginIt) == nullptr) {
            continue;
        }
        beginTime = GetSysClockTime();
        result = ProcessEvent(event, *pluginIt, data);
        endTime = GetSysClockTime();
        lostTime = endTime - beginTime;
        if (lostTime >= TIMEOUT_US) {
            MMI_HILOGE("pluginIt timeout name:%{public}s ,endTime:%{public}" PRId64 ",lostTime:%{public}" PRId64,
                (*pluginIt)->GetName().c_str(), endTime, lostTime);
        }
        if (result == PluginResult::UseNeedReissue) {
            if (IntermediateEndEvent(event)) {
                MMI_HILOGE("pluginIt is intermediate or end event");
                continue;
            }
            return RET_DO;
        } else if (result == PluginResult::UseNoNeedReissue) {
            return RET_DO;
        } else if (result == PluginResult::Error) {
            MMI_HILOGE("pluginIt err name:%{public}s", (*pluginIt)->GetName().c_str());
        }
    }
    return RET_NOTDO;
}

int32_t InputPluginManager::HandleEvent(PluginEventType event, std::shared_ptr<IPluginData> data)
{
    return DoHandleEvent(keyEvent, data, nullptr);
}

// LIBINPUT_EVENT_TABLET_TOOL_BUTTON、LIBINPUT_EVENT_TABLET_PAD_BUTTON、LIBINPUT_EVENT_TABLET_PAD_KEY
// These few existence termination events are currently not used and will be supplemented after use
bool InputPluginManager::IntermediateEndEvent(PluginEventType pluginEvent)
{
    auto event = std::get_if<libinput_event*>(&pluginEvent);
    if (!event) {
        return false;
    }
    const libinput_event_type type = libinput_event_get_type(*event);
    switch (type) {
        case LIBINPUT_EVENT_POINTER_MOTION:
        case LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE:
        case LIBINPUT_EVENT_POINTER_AXIS:
        case LIBINPUT_EVENT_POINTER_SCROLL_FINGER:
        case LIBINPUT_EVENT_POINTER_SCROLL_CONTINUOUS:
        case LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD:
        case LIBINPUT_EVENT_POINTER_SCROLL_FINGER_END:
        case LIBINPUT_EVENT_JOYSTICK_AXIS:
        case LIBINPUT_EVENT_TOUCH_UP:
        case LIBINPUT_EVENT_TOUCH_MOTION:
        case LIBINPUT_EVENT_TOUCH_CANCEL:
        case LIBINPUT_EVENT_TOUCHPAD_UP:
        case LIBINPUT_EVENT_TOUCHPAD_MOTION:
        case LIBINPUT_EVENT_TABLET_TOOL_AXIS:
        case LIBINPUT_EVENT_TABLET_PAD_RING:
        case LIBINPUT_EVENT_TABLET_PAD_STRIP:
        case LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE:
        case LIBINPUT_EVENT_GESTURE_SWIPE_END:
        case LIBINPUT_EVENT_GESTURE_PINCH_UPDATE:
        case LIBINPUT_EVENT_GESTURE_PINCH_END:
        case LIBINPUT_EVENT_GESTURE_HOLD_END:
            return true;
        case LIBINPUT_EVENT_KEYBOARD_KEY: {
            struct libinput_event_keyboard *keyboardEvent = libinput_event_get_keyboard_event(*event);
            CHKPR(keyboardEvent, false);
            return libinput_event_keyboard_get_key_state(keyboardEvent) == LIBINPUT_KEY_STATE_RELEASED;
        }
        case LIBINPUT_EVENT_POINTER_BUTTON:
        case LIBINPUT_EVENT_POINTER_TAP:
        case LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD: {
            auto touchpadButtonEvent = libinput_event_get_pointer_event(*event);
            CHKPR(touchpadButtonEvent, false);
            return libinput_event_pointer_get_button_state(touchpadButtonEvent) == LIBINPUT_BUTTON_STATE_RELEASED;
        }
        case LIBINPUT_EVENT_JOYSTICK_BUTTON: {
            auto rawBtnEvent = libinput_event_get_joystick_button_event(*event);
            CHKPR(rawBtnEvent, false);
            return libinput_event_joystick_button_get_key_state(rawBtnEvent) == LIBINPUT_BUTTON_STATE_RELEASED;
        }
        case LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY: {
            auto tabletEvent = libinput_event_get_tablet_tool_event(*event);
            CHKPR(tabletEvent, false);
            return libinput_event_tablet_tool_get_proximity_state(tabletEvent) ==
                   LIBINPUT_TABLET_TOOL_PROXIMITY_STATE_OUT;
        }
        case LIBINPUT_EVENT_TABLET_TOOL_TIP: {
            auto tabletEvent = libinput_event_get_tablet_tool_event(*event);
            CHKPR(tabletEvent, false);
            return libinput_event_tablet_tool_get_tip_state(tabletEvent) == LIBINPUT_TABLET_TOOL_TIP_UP;
        }
        default:
            break;
    }
    return false;
}

int32_t InputPluginManager::GetPluginRemoteStub(const std::string &pluginName, sptr<IRemoteObject> &pluginRemoteStub)
{
    MMI_HILOGD("Get stub from plugin: %{public}s start", pluginName.c_str());
    std::list<std::shared_ptr<IPluginContext>> allPluginList;
    for (auto &[stage, inputPluginList] : plugins_)
    {
        std::copy(inputPluginList.begin(), inputPluginList.end(), std::back_inserter(allPluginList));
    }
    std::list<std::shared_ptr<IPluginContext>>::iterator pluginIt =
        std::find_if(allPluginList.begin(), allPluginList.end(), [pluginName](std::shared_ptr<IPluginContext> iplugin)
                     { return iplugin->GetPlugin()->GetName() == pluginName; });
    if (pluginIt == allPluginList.end()) {
        MMI_HILOGE("Get plugin stub failed due to there is no plugin named: %{public}s", pluginName.c_str());
        return ERROR_NULL_POINTER;
    }

    pluginRemoteStub = (*pluginIt)->GetPlugin()->GetPluginRemoteStub();
    if (!pluginRemoteStub) {
        MMI_HILOGE("Get plugin stub failed due to there is no plugin named: %{public}s", pluginName.c_str());
        return ERROR_NULL_POINTER;
    }
    return RET_OK;
}

std::shared_ptr<IPluginData> InputPluginManager::GetPluginDataFromLibInput(libinput_event* event)
{
    std::shared_ptr<IPluginData> data = std::make_shared<IPluginData>();
    auto touch = libinput_event_get_touch_event(event);
    if (!touch) {
        return data;
    }
    auto& libInputData = data->libInputEventData;
    libInputData.orientation = libinput_event_touch_get_orientaion(touch);
    libInputData.toolType = libinput_event_touch_get_tool_type(touch);
    auto device = libinput_event_get_device(event);
    if (!device) {
        return data;
    }
    libInputData.deviceName = libinput_device_get_name(device);
    return data;
}

UDSServer* InputPluginManager::GetUdsServer()
{
    return udsServer_;
}

int32_t InputPlugin::Init(std::shared_ptr<IInputPlugin> pin)
{
    name_ = pin->GetName();
    prio_ = pin->GetPriority();
    stage_ = pin->GetStage();
    plugin_ = pin;
    return RET_OK;
}

void InputPlugin::UnInit()
{
    CHKPV(plugin_);
    MMI_HILOGI("InputPlugin UnInit Start name:%{public}s.", name_.c_str());
    if (unintPlugin_) {
        unintPlugin_(plugin_);
    }
}

void InputPlugin::DispatchEvent(PluginEventType event, int64_t frameTime)
{
    std::shared_ptr<IPluginData> data = std::make_shared<IPluginData>();
    data->frameTime = frameTime;
    data->stage = stage_;
    int32_t result = InputPluginManager::GetInstance()->DoHandleEvent(event, data, this);
    if (result == RET_NOTDO) {
        CHKPV(callback_);
        callback_(event, frameTime);
    }
}

void InputPlugin::DispatchEvent(PluginEventType pluginEvent, InputDispatchStage stage)
{
    std::shared_ptr<IInputEventHandler> eventHandler = nullptr;
    switch (stage) {
        case InputDispatchStage::Filter: {
            eventHandler = std::make_shared<EventFilterHandler>();
        }
        case InputDispatchStage::Intercept: {
            eventHandler = std::make_shared<EventInterceptorHandler>();
        }
        case InputDispatchStage::KeyCommand: {
            eventHandler = std::make_shared<KeyCommandHandler>();
        }
        case InputDispatchStage::Monitor: {
            eventHandler = std::make_shared<EventMonitorHandler>();
        }
        default: {
            MMI_HILOGD("Abnormal input dispatch stage");
            return;
        }
    }

    std::visit(overloaded{
        [&eventHandler](std::shared_ptr<KeyEvent> evt) { return eventHandler->HandleKeyEvent(evt); },
        [&eventHandler](std::shared_ptr<PointerEvent> evt) { return eventHandler->HandlePointerEvent(evt); },
        [](libinput* evt) { return; }
        [](std::shared_ptr<AxisEvent> evt) { return; }
    }, pluginEvent);
}

void InputPlugin::DispatchEvent(NetPacket& pkt, int32_t pid)
{
    auto session = InputPluginManager::GetInstance()->GetUdsServer()->GetSessionByPid(pid);
    if (!session) {
        MMI_HILOGE("Get session from uds server failed when plugin dispatch event");
        return;
    }
    if (!session->SendMsg(pkt)) {
        MMI_HILOGE("Send message to oid: %{public}d failed, errCode: %{public}d", pid, MSG_SEND_FAIL);
    }
}

PluginResult InputPlugin::HandleEvent(libinput_event *event, std::shared_ptr<IPluginData> data)
{
    CHKPR(plugin_, PluginResult::NotUse);
    return plugin_->HandleEvent(event, data);
}

PluginResult InputPlugin::HandleEvent(std::shared_ptr<PointerEvent> pointerEvent, std::shared_ptr<IPluginData> data)
{
    CHKPR(plugin_, PluginResult::NotUse);
    return plugin_->HandleEvent(pointerEvent, data);
}

PluginResult InputPlugin::HandleEvent(std::shared_ptr<KeyEvent> keyEvent, std::shared_ptr<IPluginData> data)
{
    CHKPR(plugin_, PluginResult::NotUse);
    return plugin_->HandleEvent(keyEvent, data);
}

PluginResult InputPlugin::HandleEvent(std::shared_ptr<AxisEvent> axisEvent, std::shared_ptr<IPluginData> data)
{
    CHKPR(plugin_, PluginResult::NotUse);
    return plugin_->HandleEvent(axisEvent, data);
}

PluginResult InputPlugin::HandleEvent(std::shared_ptr<KeyEvent> keyEvent, InputPluginStage stage)
{
    CHKPR(plugin_, PluginResult::NotUse);
    return plugin_->HandleEvent(keyEvent, stage);
}

int32_t InputPlugin::AddTimer(std::function<void()> func, int32_t intervalMs, int32_t repeatCount)
{
    if (timerCnt_ >= MAX_TIMER) {
        return RET_ERR;
    }
    int32_t timerId = TimerMgr->AddTimerInternal(intervalMs, repeatCount, func, name_);
    if (timerId != -1) {
        timerCnt_++;
    }
    return timerId;
}

int32_t InputPlugin::RemoveTimer(int32_t id)
{
    int32_t result = TimerMgr->RemoveTimer(id, name_);
    if (timerCnt_ > 0) {
        timerCnt_--;
    }
    return result;
}

std::string InputPlugin::GetName()
{
    return name_;
}

int32_t InputPlugin::GetPriority()
{
    return prio_;
}

void InputPlugin::SetCallback(std::function<void(PluginEventType, int64_t)>& callback)
{
    callback_ = callback;
}

std::shared_ptr<IInputPlugin> InputPlugin::GetPlugin()
{
    return plugin_;
}

InputPlugin::~InputPlugin()
{
    if (handle_) {
        dlclose(handle_);
        handle_ = nullptr;
    }
    MMI_HILOGI("~InputPlugin");
}
} // namespace MMI
} // namespace OHOS
