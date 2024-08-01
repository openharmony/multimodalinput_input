/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "mock.h"

extern "C" {
double libinput_event_tablet_tool_get_x_transformed(struct libinput_event_tablet_tool *event, uint32_t width)
{
    return -1.0;
}

double libinput_event_tablet_tool_get_y_transformed(struct libinput_event_tablet_tool *event, uint32_t height)
{
    return -1.0;
}

double libinput_event_touch_get_x_transformed(struct libinput_event_touch *event, uint32_t width)
{
    return -1.0;
}

double libinput_event_touch_get_y_transformed(struct libinput_event_touch *event, uint32_t height)
{
    return -1.0;
}

double libinput_event_touch_get_tool_x_transformed(struct libinput_event_touch *event, uint32_t width)
{
    return -1.0;
}

double libinput_event_touch_get_tool_y_transformed(struct libinput_event_touch *event, uint32_t height)
{
    return -1.0;
}

double libinput_event_touch_get_tool_width_transformed(struct libinput_event_touch *event, uint32_t width)
{
    return -1.0;
}

double libinput_event_touch_get_tool_height_transformed(struct libinput_event_touch *event, uint32_t height)
{
    return -1.0;
}
} // extern "C"

namespace OHOS {
using namespace OHOS::MMI;

InputDisplayBindHelper::InputDisplayBindHelper(const std::string bindCfgFile)
    : fileName_(bindCfgFile), infos_(std::make_shared<BindInfos>()), configFileInfos_(std::make_shared<BindInfos>())
{}

void InputDisplayBindHelper::Load()
{}

std::string InputDisplayBindHelper::Dumps() const
{
    return "";
}

int32_t InputDisplayBindHelper::GetDisplayBindInfo(DisplayBindInfos &infos)
{
    return 0;
}

int32_t InputDisplayBindHelper::SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg)
{
    return 0;
}

std::string InputDisplayBindHelper::GetBindDisplayNameByInputDevice(int32_t inputDeviceId) const
{
    return "";
}

std::set<std::pair<int32_t, std::string>> InputDisplayBindHelper::GetDisplayIdNames() const
{
    std::set<std::pair<int32_t, std::string>> idNames;
    return idNames;
}

void InputDisplayBindHelper::RemoveDisplay(int32_t id)
{}

void InputDisplayBindHelper::AddLocalDisplay(int32_t id, const std::string &name)
{}

bool InputDisplayBindHelper::IsDisplayAdd(int32_t id, const std::string &name)
{
    return false;
}

void InputDisplayBindHelper::AddDisplay(int32_t id, const std::string &name)
{}

void InputDisplayBindHelper::RemoveInputDevice(int32_t id)
{}

void InputDisplayBindHelper::AddInputDevice(int32_t id, const std::string &name)
{}

UDSServer::~UDSServer() {}

void UDSServer::AddSessionDeletedCallback(std::function<void(SessionPtr)> callback)
{}

SessionPtr UDSServer::GetSession(int32_t fd) const
{
    return DfsMessageParcel::messageParcel->GetSession(fd);
}

int32_t UDSServer::GetClientFd(int32_t pid) const
{
    return DfsMessageParcel::messageParcel->GetClientFd(pid);
}

SessionPtr UDSServer::GetSessionByPid(int32_t pid) const
{
    return nullptr;
}

void UDSServer::OnConnected(SessionPtr sess)
{}

void UDSServer::OnDisconnected(SessionPtr sess)
{}

int32_t UDSServer::AddEpoll(EpollEventType type, int32_t fd)
{
    return RET_ERR;
}

int32_t UDSServer::AddSocketPairInfo(const std::string& programName,
    const int32_t moduleType, const int32_t uid, const int32_t pid,
    int32_t& serverFd, int32_t& toReturnClientFd, int32_t& tokenType)
{
    return RET_ERR;
}

std::shared_ptr<InputDeviceManager> InputDeviceManager::instance_ = nullptr;
std::mutex InputDeviceManager::mutex_;
std::shared_ptr<InputDeviceManager> InputDeviceManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<InputDeviceManager>();
        }
    }
    return instance_;
}

void InputDeviceManager::Attach(std::shared_ptr<IDeviceObserver> observer)
{}

void InputDeviceManager::Detach(std::shared_ptr<IDeviceObserver> observer)
{}

void InputDeviceManager::NotifyPointerDevice(bool hasPointerDevice, bool isVisible, bool isHotPlug)
{}

void InputDeviceManager::SetInputStatusChangeCallback(inputDeviceCallback callback)
{}

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
bool InputDeviceManager::HasPointerDevice()
{
    return DfsMessageParcel::messageParcel->HasPointerDevice();
}
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

std::shared_ptr<InputDevice> InputDeviceManager::GetInputDevice(int32_t deviceId, bool checked) const
{
    return DfsMessageParcel::messageParcel->GetInputDevice(deviceId, checked);
}

TimerManager::TimerManager() {}

TimerManager::~TimerManager() {}

int32_t TimerManager::AddTimer(int32_t intervalMs, int32_t repeatCount, std::function<void()> callback)
{
    return 0;
}

void DfxHisysevent::OnFocusWindowChanged(int32_t oldFocusWindowId, int32_t newFocusWindowId,
    int32_t oldFocusWindowPid, int32_t newFocusWindowPid)
{}

void DfxHisysevent::OnZorderWindowChanged(int32_t oldZorderFirstWindowId, int32_t newZorderFirstWindowId,
    int32_t oldZorderFirstWindowPid, int32_t newZorderFirstWindowPid)
{}

TouchDrawingManager::TouchDrawingManager() {}

TouchDrawingManager::~TouchDrawingManager() {}

void TouchDrawingManager::UpdateDisplayInfo(const DisplayInfo& displayInfo)
{}

void TouchDrawingManager::RotationScreen()
{}

void TouchDrawingManager::TouchDrawHandler(std::shared_ptr<PointerEvent> pointerEvent)
{}

void TouchDrawingManager::GetOriginalTouchScreenCoordinates(Direction direction, int32_t width, int32_t height,
    int32_t &physicalX, int32_t &physicalY)
{}

bool TouchDrawingManager::IsWindowRotation()
{
    return false;
}

PointerDrawingManager::PointerDrawingManager() {}

std::shared_ptr<IPointerDrawingManager> IPointerDrawingManager::GetInstance()
{
    if (iPointDrawMgr_ == nullptr) {
        iPointDrawMgr_ = std::make_shared<PointerDrawingManager>();
    }
    return iPointDrawMgr_;
}

void PointerDrawingManager::UpdatePointerDevice(bool hasPointerDevice, bool isPointerVisible,
    bool isHotPlug)
{}
void PointerDrawingManager::DrawPointer(int32_t displayId, int32_t physicalX, int32_t physicalY,
    const PointerStyle pointerStyle, Direction direction) {}
void PointerDrawingManager::UpdateDisplayInfo(const DisplayInfo& displayInfo) {}
void PointerDrawingManager::OnDisplayInfo(const DisplayGroupInfo& displayGroupInfo) {}
void PointerDrawingManager::OnWindowInfo(const WinInfo &info) {}
bool PointerDrawingManager::Init()
{
    return true;
}
void PointerDrawingManager::DeletePointerVisible(int32_t pid) {}
int32_t PointerDrawingManager::SetPointerVisible(int32_t pid, bool visible, int32_t priority, bool isHap)
{
    return 0;
}
bool PointerDrawingManager::GetPointerVisible(int32_t pid)
{
    return true;
}
int32_t PointerDrawingManager::SetPointerColor(int32_t color)
{
    return 0;
}
int32_t PointerDrawingManager::GetPointerColor()
{
    return 0;
}
int32_t PointerDrawingManager::SetPointerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle,
    bool isUiExtension)
{
    return 0;
}
int32_t PointerDrawingManager::ClearWindowPointerStyle(int32_t pid, int32_t windowId)
{
    return 0;
}
int32_t PointerDrawingManager::GetPointerStyle(int32_t pid, int32_t windowId, PointerStyle &pointerStyle,
    bool isUiExtension)
{
    return 0;
}
void PointerDrawingManager::DrawPointerStyle(const PointerStyle& pointerStyle, bool simulate) {}
bool PointerDrawingManager::IsPointerVisible()
{
    return false;
}
void PointerDrawingManager::SetPointerLocation(int32_t x, int32_t y) {}
void PointerDrawingManager::SetMouseDisplayState(bool state) {}
bool PointerDrawingManager::GetMouseDisplayState() const
{
    return DfsMessageParcel::messageParcel->GetMouseDisplayState();
}
int32_t PointerDrawingManager::SetCustomCursor(void* pixelMap, int32_t pid, int32_t windowId,
    int32_t focusX, int32_t focusY)
{
    return 0;
}
int32_t PointerDrawingManager::SetMouseIcon(int32_t pid, int32_t windowId, void* pixelMap)
{
    return 0;
}
int32_t PointerDrawingManager::SetMouseHotSpot(int32_t pid, int32_t windowId, int32_t hotSpotX, int32_t hotSpotY)
{
    return 0;
}
int32_t PointerDrawingManager::SetPointerSize(int32_t size)
{
    return 0;
}
int32_t PointerDrawingManager::GetPointerSize()
{
    return 0;
}
PointerStyle PointerDrawingManager::GetLastMouseStyle()
{
    return {};
}
IconStyle PointerDrawingManager::GetIconStyle(const MOUSE_ICON mouseStyle)
{
    return {};
}
std::map<MOUSE_ICON, IconStyle> PointerDrawingManager::GetMouseIconPath()
{
    return {};
}
int32_t PointerDrawingManager::SwitchPointerStyle()
{
    return 0;
}
void PointerDrawingManager::DrawMovePointer(int32_t displayId, int32_t physicalX, int32_t physicalY) {}
void PointerDrawingManager::Dump(int32_t fd, const std::vector<std::string> &args) {}
int32_t PointerDrawingManager::EnableHardwareCursorStats(int32_t pid, bool enable)
{
    return 0;
}
int32_t PointerDrawingManager::GetHardwareCursorStats(int32_t pid, uint32_t &frameCount, uint32_t &vsyncCount)
{
    return 0;
}
int32_t PointerDrawingManager::GetPointerSnapshot(void *pixelMap)
{
    return 0;
}
void PointerDrawingManager::ForceClearPointerVisiableStatus()
{}
void PointerDrawingManager::InitPointerCallback()
{}
void PointerDrawingManager::InitPointerObserver()
{}
void PointerDrawingManager::OnSessionLost(int pid)
{}
int32_t PointerDrawingManager::SkipPointerLayer(bool isSkip)
{
    return 0;
}
std::shared_ptr<IPreferenceManager> IPreferenceManager::instance_;
std::mutex IPreferenceManager::mutex_;
std::shared_ptr<IPreferenceManager> IPreferenceManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<MultiModalInputPreferencesManager>();
        }
    }
    return instance_;
}

int32_t MultiModalInputPreferencesManager::InitPreferences()
{
    return 0;
}

int32_t MultiModalInputPreferencesManager::GetIntValue(const std::string &key, int32_t defaultValue)
{
    return 0;
}

bool MultiModalInputPreferencesManager::GetBoolValue(const std::string &key, bool defaultValue)
{
    return DfsMessageParcel::messageParcel->GetBoolValue(key, defaultValue);
}

int32_t MultiModalInputPreferencesManager::SetIntValue(const std::string &key, const std::string &setFile,
    int32_t setValue)
{
    return 0;
}

int32_t MultiModalInputPreferencesManager::SetBoolValue(const std::string &key, const std::string &setFile,
    bool setValue)
{
    return 0;
}

int32_t MultiModalInputPreferencesManager::GetShortKeyDuration(const std::string &key)
{
    return 0;
}

int32_t MultiModalInputPreferencesManager::SetShortKeyDuration(const std::string &key, int32_t setValue)
{
    return 0;
}

InputEventHandler::InputEventHandler() {}

InputEventHandler::~InputEventHandler() {}

std::shared_ptr<EventFilterHandler> InputEventHandler::GetFilterHandler() const
{
    return nullptr;
}

std::shared_ptr<EventNormalizeHandler> InputEventHandler::GetEventNormalizeHandler() const
{
    return nullptr;
}

std::shared_ptr<KeyCommandHandler> InputEventHandler::GetKeyCommandHandler() const
{
    return eventKeyCommandHandler_;
}

#ifdef OHOS_BUILD_ENABLE_POINTER
void EventFilterHandler::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{}
#endif // OHOS_BUILD_ENABLE_POINTER

MouseEventNormalize::MouseEventNormalize() {}

MouseEventNormalize::~MouseEventNormalize() {}

int32_t MouseEventNormalize::GetDisplayId() const
{
    return 0;
}

KnuckleDrawingManager::KnuckleDrawingManager()
{}

void KnuckleDrawingManager::UpdateDisplayInfo(const DisplayInfo& displayInfo)
{}

void KnuckleDrawingManager::KnuckleDrawHandler(std::shared_ptr<PointerEvent> touchEvent)
{}

KnuckleDynamicDrawingManager::KnuckleDynamicDrawingManager()
{}

void KnuckleDynamicDrawingManager::UpdateDisplayInfo(const DisplayInfo& displayInfo)
{}

void KnuckleDynamicDrawingManager::KnuckleDynamicDrawHandler(std::shared_ptr<PointerEvent> pointerEvent)
{}

void KnuckleDynamicDrawingManager::SetKnuckleDrawingManager(std::shared_ptr<KnuckleDrawingManager> knuckleDrawMgr)
{}

SettingDataShare::~SettingDataShare() {}

std::shared_ptr<SettingDataShare> SettingDataShare::instance_ = nullptr;
std::mutex SettingDataShare::mutex_;
SettingDataShare& SettingDataShare::GetInstance(int32_t systemAbilityId)
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<SettingDataShare>();
        }
    }
    return *instance_;
}

ErrCode SettingDataShare::GetBoolValue(const std::string& key, bool& value, const std::string &strUri)
{
    return ERR_OK;
}

sptr<SettingObserver> SettingDataShare::CreateObserver(const std::string& key, SettingObserver::UpdateFunc& func)
{
    return nullptr;
}

ErrCode SettingDataShare::RegisterObserver(const sptr<SettingObserver>& observer, const std::string &strUri)
{
    return ERR_OK;
}

FingersenseWrapper::FingersenseWrapper() {}

FingersenseWrapper::~FingersenseWrapper() {}

bool UDSSession::SendMsg(NetPacket &pkt) const
{
    return DfsMessageParcel::messageParcel->SendMsg(pkt);
}

bool Rosen::SceneBoardJudgement::IsSceneBoardEnabled()
{
    return DfsMessageParcel::messageParcel->IsSceneBoardEnabled();
}

#ifdef OHOS_BUILD_ENABLE_ANCO
int32_t InputWindowsManager::AncoAddConsumer(std::shared_ptr<IAncoConsumer> consumer)
{
    return ERR_OK;
}

int32_t InputWindowsManager::AncoRemoveConsumer(std::shared_ptr<IAncoConsumer> consumer)
{
    return ERR_OK;
}

void InputWindowsManager::CleanShellWindowIds()
{}
#endif // OHOS_BUILD_ENABLE_ANCO

bool KeyCommandHandler::GetKnuckleSwitchValue()
{
    return false;
}
} // namespace OHOS