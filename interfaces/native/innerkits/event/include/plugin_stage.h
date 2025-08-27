/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef PLUGIN_STAGE_H
#define PLUGIN_STAGE_H

#include "key_event.h"
#include "pointer_event.h"
#include "axis_event.h"
#include "input_device.h"
#include "libinput.h"
#include "net_packet.h"
#include "iremote_broker.h"
#include "i_input_device_consumer.h"

namespace OHOS {
namespace MMI {

using PluginEventType = std::variant<libinput_event *, std::shared_ptr<PointerEvent>, std::shared_ptr<AxisEvent>,
                                     std::shared_ptr<KeyEvent>>;

template<class... Ts>
struct overloaded : Ts... {
    using Ts::operator()...;
};

template<class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

enum class InputPluginStage {
    INPUT_GLOBAL_INIT = 0,
    INPUT_DEV_ADDED = 3,
    INPUT_DEV_REMOVEED = 6,
    INPUT_BEFORE_LIBINPUT_ADAPTER_ON_EVENT = 12,
    INPUT_AFTER_LIBINPUT_ADAPTER_ON_EVENT = 13,
    INPUT_BEFORE_NORMALIZED = 15,
    INPUT_AFTER_NORMALIZED,
    INPUT_DEVICE_CHANGE = 20,
    INPUT_BEFORE_FILTER = 25,
    INPUT_AFTER_FILTER,
    INPUT_BEFORE_INTERCEPT = 30,
    INPUT_AFTER_INTERCEPT,
    INPUT_BEFORE_KEYCOMMAND = 35,
    INPUT_AFTER_KEYCOMMAND,
    INPUT_BEFORE_MONITOR = 40,
    INPUT_AFTER_MONITOR,
    INPUT_STAGE_BUTT,
};

enum class PluginResult {
    Error = -1,
    UseNeedReissue = 0,
    NotUse,
    UseNoNeedReissue,
};

enum class InputDispatchStage {
    Filter = 0,
    Intercept,
    KeyCommand,
    Monitor,
};

struct LibInputEventData {
    int32_t orientation;
    int32_t toolType;
    std::string deviceName;
};

struct IPluginData {
    int64_t frameTime;
    InputPluginStage stage;
    LibInputEventData libInputEventData;
};

struct IInputPlugin {
    virtual int32_t GetPriority() const = 0;
    virtual const std::string GetVersion() const = 0;
    virtual const std::string GetName() const = 0;
    virtual InputPluginStage GetStage() const = 0;
    virtual void DeviceWillAdded(std::shared_ptr<InputDevice> inputDevice){};
    virtual void DeviceDidAdded(std::shared_ptr<InputDevice> inputDevice){};
    virtual void DeviceWillRemoved(std::shared_ptr<InputDevice> inputDevice){};
    virtual void DeviceDidRemoved(std::shared_ptr<InputDevice> inputDevice){};
    virtual PluginResult HandleEvent(libinput_event *event, std::shared_ptr<IPluginData> data) const = 0;
    virtual PluginResult HandleEvent(std::shared_ptr<KeyEvent> keyEvent, std::shared_ptr<IPluginData> data) const = 0;
    virtual PluginResult HandleEvent(
        std::shared_ptr<PointerEvent> pointerEvent, std::shared_ptr<IPluginData> data) const = 0;
    virtual PluginResult HandleEvent(
        std::shared_ptr<AxisEvent> axisEvent, std::shared_ptr<IPluginData> data) const = 0;
    virtual sptr<IRemoteObject> GetPluginRemoteStub() { return nullptr;}
};

struct IPluginContext {
    virtual ~IPluginContext() = default;
    virtual std::string GetName() = 0;
    virtual int32_t GetPriority() = 0;
    virtual std::shared_ptr<IInputPlugin> GetPlugin() = 0;
    virtual void SetCallback(std::function<void(PluginEventType, int64_t)>& callback) = 0;
    virtual int32_t AddTimer(std::function<void()> func, int32_t intervalMs, int32_t repeatCount) = 0;
    virtual int32_t RemoveTimer(int32_t id) = 0;
    virtual void DispatchEvent(PluginEventType pluginEvent, int64_t frameTime) = 0;
    virtual void DispatchEvent(PluginEventType pluginEvent, InputDispatchStage stage) = 0;
    virtual void DispatchEvent(NetPacket &pkt, int32_t pid) = 0;
    virtual PluginResult HandleEvent(libinput_event *event, std::shared_ptr<IPluginData> data) =  0;
    virtual PluginResult HandleEvent(
        std::shared_ptr<PointerEvent> pointerEvent, std::shared_ptr<IPluginData> data) =  0;
    virtual PluginResult HandleEvent(std::shared_ptr<KeyEvent> keyEvent, std::shared_ptr<IPluginData> data) =  0;
    virtual PluginResult HandleEvent(std::shared_ptr<AxisEvent> axisEvent, std::shared_ptr<IPluginData> data) =  0;
};

inline bool checkPluginEventNull(PluginEventType &event)
{
  return std::visit([](auto &&v) { return v == nullptr; }, event);
}
} // namespace MMI
} // namespace OHOS
#endif // PLUGIN_STAGE_H