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

#include "multimodal_input_plugin_manager.h"

#include "mmi_log.h"
#include <memory>

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MultiModalInputPluginManager"

namespace OHOS {
namespace MMI {
std::shared_ptr<InputPluginManager> InputPluginManager::instance_;
std::once_flag InputPluginManager::init_flag_;

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

std::shared_ptr<InputPluginManager> InputPluginManager::GetInstance(const std::string &directory)
{
    std::call_once(init_flag_, [&directory] {
        if (instance_ == nullptr) {
            MMI_HILOGI("New InputPluginManager");
            std::string dir = directory.empty() ? FOLDER_PATH : directory;
            instance_ = std::make_shared<InputPluginManager>(dir);
        }
    });
    return instance_;
}

int32_t InputPluginManager::Init()
{
    CALL_DEBUG_ENTER;
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
            [](const std::shared_ptr<InputPlugin> &a, const std::shared_ptr<InputPlugin> &b) {
                return a->prio_ < b->prio_;
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
                plugin->name_.c_str(), plugin->prio_);
        }
    }
}

void InputPluginManager::PluginAssignmentCallBack(
    std::function<void(libinput_event *, int64_t)> callback, InputPluginStage stage)
{
    CALL_DEBUG_ENTER;
    auto it = plugins_.find(stage);
    if (it == plugins_.end()) {
        MMI_HILOGI("plugins_ not stage:%{public}d.", stage);
        return;
    }
    for (auto &plugin : it->second) {
        plugin->callback_ = callback;
    }
}

void InputPluginManager::PluginAssignmentCallBack(
    std::function<void(std::shared_ptr<KeyEvent>)> callback, InputPluginStage stage)
{
    CALL_DEBUG_ENTER;
    auto it = plugins_.find(stage);
    if (it == plugins_.end()) {
        MMI_HILOGI("plugins_ not stage:%{public}d.", stage);
        return;
    }
    for (auto &plugin : it->second) {
        if (plugin != nullptr) {
            plugin->keyEventCallback_ = callback;
        }
    }
}

int32_t InputPluginManager::HandleEvent(libinput_event *event, int64_t frameTime, InputPluginStage stage)
{
    return DoHandleEvent(event, frameTime, nullptr, stage);
}

int32_t InputPluginManager::DoHandleEvent(
    libinput_event *event, int64_t frameTime, InputPlugin *iplugin, InputPluginStage stage)
{
    if (event == nullptr) {
        return RET_NOTDO;
    }
    auto it = plugins_.find(stage);
    if (it == plugins_.end()) {
        return RET_NOTDO;
    }
    CALL_DEBUG_ENTER;
    auto &plugins = it->second;
    auto start_plugin = plugins.begin();
    if (iplugin != nullptr) {
        auto cur_plugin = std::find_if(plugins.begin(), plugins.end(),
            [iplugin](const std::shared_ptr<InputPlugin> &plugin) { return plugin.get() == iplugin; });
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
        result = (*pluginIt)->HandleEvent(event, frameTime);
        endTime = GetSysClockTime();
        lostTime = endTime - beginTime;
        if (lostTime >= TIMEOUT_US) {
            MMI_HILOGE("pluginIt timeout name:%{public}s ,endTime:%{public}" PRId64 ",lostTime:%{public}" PRId64,
                (*pluginIt)->name_.c_str(), endTime, lostTime);
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
            MMI_HILOGE("pluginIt err name:%{public}s", (*pluginIt)->name_.c_str());
        }
    }
    return RET_NOTDO;
}

int32_t InputPluginManager::HandleEvent(std::shared_ptr<KeyEvent> keyEvent, InputPluginStage stage)
{
    return DoHandleEvent(keyEvent, nullptr, stage);
}

int32_t InputPluginManager::DoHandleEvent(
    std::shared_ptr<KeyEvent> keyEvent, InputPlugin *iplugin, InputPluginStage stage)
{
    if (keyEvent == nullptr) {
        return RET_NOTDO;
    }
    auto it = plugins_.find(stage);
    if (it == plugins_.end()) {
        return RET_NOTDO;
    }
    CALL_DEBUG_ENTER;
    auto &plugins = it->second;
    auto start_plugin = plugins.begin();
    if (iplugin != nullptr) {
        auto cur_plugin = std::find_if(plugins.begin(), plugins.end(),
            [iplugin](const std::shared_ptr<InputPlugin> &plugin) { return plugin.get() == iplugin; });
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
        result = (*pluginIt)->HandleEvent(keyEvent, stage);
        endTime = GetSysClockTime();
        lostTime = endTime - beginTime;
        if (lostTime >= TIMEOUT_US) {
            MMI_HILOGE("pluginIt timeout name:%{public}s ,endTime:%{public}" PRId64 ",lostTime:%{public}" PRId64,
                (*pluginIt)->name_.c_str(), endTime, lostTime);
        }
        if (result == PluginResult::UseNeedReissue) {
            return RET_DO;
        } else if (result == PluginResult::UseNoNeedReissue) {
            return RET_DO;
        } else if (result == PluginResult::Error) {
            MMI_HILOGE("pluginIt err name:%{public}s", (*pluginIt)->name_.c_str());
        }
    }
    return RET_NOTDO;
}

// LIBINPUT_EVENT_TABLET_TOOL_BUTTON、LIBINPUT_EVENT_TABLET_PAD_BUTTON、LIBINPUT_EVENT_TABLET_PAD_KEY
// These few existence termination events are currently not used and will be supplemented after use
bool InputPluginManager::IntermediateEndEvent(libinput_event *event)
{
    const libinput_event_type type = libinput_event_get_type(event);
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
            struct libinput_event_keyboard *keyboardEvent = libinput_event_get_keyboard_event(event);
            CHKPF(keyboardEvent);
            return libinput_event_keyboard_get_key_state(keyboardEvent) == LIBINPUT_KEY_STATE_RELEASED;
        }
        case LIBINPUT_EVENT_POINTER_BUTTON:
        case LIBINPUT_EVENT_POINTER_TAP:
        case LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD: {
            auto touchpadButtonEvent = libinput_event_get_pointer_event(event);
            CHKPF(touchpadButtonEvent);
            return libinput_event_pointer_get_button_state(touchpadButtonEvent) == LIBINPUT_BUTTON_STATE_RELEASED;
        }
        case LIBINPUT_EVENT_JOYSTICK_BUTTON: {
            auto rawBtnEvent = libinput_event_get_joystick_button_event(event);
            CHKPF(rawBtnEvent);
            return libinput_event_joystick_button_get_key_state(rawBtnEvent) == LIBINPUT_BUTTON_STATE_RELEASED;
        }
        case LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY: {
            auto tabletEvent = libinput_event_get_tablet_tool_event(event);
            CHKPF(tabletEvent);
            return libinput_event_tablet_tool_get_proximity_state(tabletEvent) ==
                   LIBINPUT_TABLET_TOOL_PROXIMITY_STATE_OUT;
        }
        case LIBINPUT_EVENT_TABLET_TOOL_TIP: {
            auto tabletEvent = libinput_event_get_tablet_tool_event(event);
            CHKPF(tabletEvent);
            return libinput_event_tablet_tool_get_tip_state(tabletEvent) == LIBINPUT_TABLET_TOOL_TIP_UP;
        }
        default:
            break;
    }
    return false;
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

void InputPlugin::DispatchEvent(libinput_event *event, int64_t frameTime)
{
    int32_t result = InputPluginManager::GetInstance()->DoHandleEvent(event, frameTime, this, stage_);
    if (result == RET_NOTDO) {
        CHKPV(callback_);
        callback_(event, frameTime);
    }
}

void InputPlugin::DispatchEvent(std::shared_ptr<KeyEvent> keyEvent, InputDispatchStage stage)
{
    int32_t result = InputPluginManager::GetInstance()->DoHandleEvent(keyEvent, this, stage_);
    if (result == RET_NOTDO) {
        CHKPV(keyEventCallback_);
        keyEventCallback_(keyEvent);
    }
}

PluginResult InputPlugin::HandleEvent(libinput_event *event, int64_t frameTime)
{
    CHKPR(plugin_, PluginResult::NotUse);
    return plugin_->HandleEvent(event, frameTime);
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
