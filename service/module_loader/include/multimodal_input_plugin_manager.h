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

#ifndef MULTIMODAL_INPUT_PLUGIN_MANAGER_H
#define MULTIMODAL_INPUT_PLUGIN_MANAGER_H

#include <dirent.h>
#include <dlfcn.h>
#include <atomic>
#include <map>
#include "plugin_stage.h"
#include "timer_manager.h"
#include "uds_server.h"
#include "net_packet.h"
#include "i_delegate_interface.h"
#include "input_event_data_transformation.h"
#include "key_command_handler.h"
#include "key_option.h"
#include "setting_observer.h"

namespace OHOS {
namespace MMI {

/*  框架获取plugin对象
  * ctx: 框架注册给plugin调用框架的对象实例
  * plugin：plugin实例
  * return：= 0: success
  *        !=0: error
 */
typedef int32_t (*InitPlugin)(std::shared_ptr<IPluginContext> ctx, std::shared_ptr<IInputPlugin>& plugin);
/*  框架通知plugin删除plugin对象
  * ctx: 框架注册给plugin调用框架的对象实例
  * plugin：plugin实例
  * return：= 0: success
  *        !=0: error
 */
typedef int32_t (*UnintPlugin)(std::shared_ptr<IInputPlugin> &plugin);

const int32_t RET_NOTDO = 0;
const int32_t RET_DO = 1;

enum class ObserverError : int32_t {
    SUCCESS = 0,
    INVALID_PARAM = -1,      // Invalid parameters (empty uri/key/null callback)
    CREATE_FAILED = -2,      // Failed to create observer
    REGISTER_FAILED = -3,    // Failed to register observer with DataShare
    NOT_FOUND = -4,          // Observer ID not found during unregister
};

struct InputPlugin : public IPluginContext {
public:
    InputPlugin(void *handle);
    virtual ~InputPlugin();
    int32_t Init(std::shared_ptr<IInputPlugin> pin);
    void UnInit();
    std::string GetName() override;
    int32_t GetPriority() override;
    std::shared_ptr<IInputPlugin> GetPlugin() override;
    void SetCallback(std::function<void(PluginEventType, int64_t)> callback) override;
    PluginResult HandleEvent(libinput_event *event, std::shared_ptr<IPluginData> data) override;
    PluginResult HandleEvent(std::shared_ptr<PointerEvent> pointerEvent, std::shared_ptr<IPluginData> data) override;
    PluginResult HandleEvent(std::shared_ptr<KeyEvent> keyEvent, std::shared_ptr<IPluginData> data) override;
    PluginResult HandleEvent(std::shared_ptr<AxisEvent> axisEvent, std::shared_ptr<IPluginData> data) override;

    int32_t AddTimer(std::function<void()> func, int32_t intervalMs, int32_t repeatCount) override;
    int32_t RemoveTimer(int32_t id) override;
    void DispatchEvent(PluginEventType pluginEvent, int64_t frameTime) override;
    void DispatchEvent(PluginEventType pluginEvent, InputDispatchStage stage) override;
    void DispatchEvent(NetPacket &pkt, int32_t pid) override;
    void HandleMonitorStatus(bool monitorStatus, const std::string &monitorType) override;
    std::string GetFocusedAppInfo() override;
    bool IsFingerPressed() const override;
    const ISessionHandlerCollection *GetMonitorCollection() const override;
    int32_t GetFocusedPid() const override;
    bool AttachDeviceObserver(const std::shared_ptr<IDeviceObserver> &observer) override;
    bool DetachDeviceObserver(const std::shared_ptr<IDeviceObserver> &observer) override;
    int32_t GetCurrentAccountId() const override;
    int32_t RegisterCommonEventCallback(
        const std::function<void(const EventFwk::CommonEventData &)> &callback) override;
    bool UnRegisterCommonEventCallback(int32_t callbackId) override;
    void HideMouseCursorTemporary() override;
    int32_t CalculateTipPoint(libinput_event *event, int32_t &displayId, PhysicalCoordinate &coord) override;
    void SetMouseAccelerateMotionSwitch(libinput_event *event, bool enable) override;
    int32_t GetCurrentMouseLocation(double &mouseX, double &mouseY) override;
    bool GetSettingValue(const std::string& uri, const std::string& key, std::string& value) override;
    int32_t RegisterSettingObserver(const std::string& uri, const std::string& key,
        std::function<void(const std::string&)> callback) override;
    bool UnregisterSettingObserver(int32_t observerId) override;
#ifdef OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER
    std::vector<int32_t> GetSubscribedKeysByPid(int32_t pid) const override;
    int32_t RegisterKeyMonitorCallback(
        const std::function<void(int32_t pid, int32_t keyCode,
        std::string bundleName, bool isAdd)> &callback) const override;
    bool UnregisterKeyMonitorCallback(int32_t callbackId) const override;
#endif
    void AddFlagForDevice(libinput_event *event) override;
    void RemoveFlagForDevice(libinput_event *event) override;
    std::vector<PluginDisplayGroupInfo> GetDisplayGroupInfos() const override;
    std::vector<std::shared_ptr<InputDevice>> GetInputDeviceInfos() const override;
    int32_t RegisterDisplayChangeCallback(const DisplayChangeCallback &callback) override;
    bool UnregisterDisplayChangeCallback(int32_t callbackId) override;
    int32_t EnableInputDeviceForPlugin(int32_t deviceId) override;
    int32_t DisableInputDeviceForPlugin(int32_t deviceId) override;

    int32_t prio_ = 200;
    std::function<void(PluginEventType, int64_t)> callback_;
    UnintPlugin unintPlugin_ = nullptr;
    std::shared_ptr<IInputPlugin> plugin_;
    std::string name_;

private:
    bool IsDataShareReady();

private:
    void* handle_ { nullptr };
    InputPluginStage stage_ { InputPluginStage::INPUT_GLOBAL_INIT };
    std::vector<InputPluginStage> stages_;
    int32_t timerCnt_ = 0;
    struct ObserverEntry {
        sptr<SettingObserver> observer;
        std::string uri;
    };
    std::map<int32_t, ObserverEntry> observers_;  // ID -> observer+uri mapping
    std::mutex observersMutex_;
    int32_t nextObserverId_ { 1 };  // Next available observer ID (start from 1)
};

class InputPluginManager final {
private:
    struct PluginConfig {
        std::string uuid_;
        int32_t uid_ { -1 };
        std::string name_;
        std::string mode_;

        bool IsValid() const;
    };

public:
    InputPluginManager(const InputPluginManager &) = delete;
    InputPluginManager &operator=(const InputPluginManager &) = delete;
    static InputPluginManager *GetInstance(const std::string &directory = "");
    void AttachDelegateInterface(std::shared_ptr<IDelegateInterface> delegate);
    int32_t PostSyncTask(const DTaskCallback &cb);
    int32_t RegisterDisplayChangeCallback(const IPluginContext::DisplayChangeCallback &callback, IPluginContext *owner);
    bool UnregisterDisplayChangeCallback(int32_t callbackId);
    int32_t Init(UDSServer &udsServer);
    void Dump(int fd);
    void PluginAssignmentCallBack(std::function<void(PluginEventType, int64_t)> callback, InputPluginStage stage);
    void PrintPlugins();
    std::shared_ptr<IPluginData> GetPluginDataFromLibInput(libinput_event *event);
    PluginResult ProcessEvent(
        PluginEventType event, std::shared_ptr<IPluginContext> iplugin, std::shared_ptr<IPluginData> data);
    int32_t HandleEvent(PluginEventType event, std::shared_ptr<IPluginData> data);
    int32_t DoHandleEvent(PluginEventType event, std::shared_ptr<IPluginData> data, IPluginContext *iplugin);
    int32_t GetExternalObject(const std::string &pluginName, sptr<IRemoteObject> &pluginRemoteStub);
    UDSServer *GetUdsServer();
    void HandleMonitorStatus(bool monitorStatus, const std::string &monitorType);
    bool HandleShortcutKey(const ShortcutKey &key);
    bool HandleShortcutKey(const KeyOption &option);
    bool HandleSequenceKeys(const Sequence &sequence);
    void NotifyDisplayChange();

    int32_t LoadDynamicPlugin(int32_t uid, const std::string &uuid);
    int32_t UnloadDynamicPlugin(int32_t uid, const std::string &uuid);

private:
    explicit InputPluginManager(const std::string& directory) : directory_(directory) {};
    ~InputPluginManager();
    bool IntermediateEndEvent(PluginEventType pluginEvent);
    std::shared_ptr<InputPlugin> LoadPlugin(const std::string &path);
    bool ProcessShortcutKey(const IShortcutKey &shortcutKey);
    bool ProcessSequenceKeys(const std::vector<ISequenceKey> &sequenceKeys);
    void AddPluginToStages(const std::shared_ptr<IPluginContext> &cPin);
    void RemovePluginFromStages(const std::shared_ptr<IPluginContext> &plugin);
    void LoadPluginConfig();
    bool ParsePluginConfig(const char *cfgPath, cJSON *jsonCfg);
    bool ParsePluginItem(cJSON *item);
    bool ReadStringField(cJSON *obj, const char *field, std::string &out);
    bool ReadNumberField(cJSON *obj, const char *field, int32_t &out);
    PluginConfig* FindPluginConfig(const std::string &uuid);
    void LoadPluginAsync(std::shared_ptr<IDelegateInterface> delegate,
        const std::string &uuid, const std::string &pluginPath);
    void OnPluginLoaded(const std::string &uuid, std::shared_ptr<InputPlugin> plugin);
    void AddCallbackToPlugin(const std::shared_ptr<IPluginContext> &cPin);

    std::weak_ptr<IDelegateInterface> delegate_;
    UDSServer* udsServer_ {nullptr};
    std::string directory_;
    std::map<InputPluginStage, std::list<std::shared_ptr<IPluginContext>>> plugins_;
    std::map<std::string, std::shared_ptr<InputPlugin>> dynamicPlugins_;
    std::map<std::string, PluginConfig> pluginConfigs_;
    std::atomic_bool loading_ { false };
    inline static InputPluginManager* instance_ { nullptr };
    inline static std::once_flag init_flag_;
    struct DisplayCallbackEntry {
        IPluginContext::DisplayChangeCallback callback;
        IPluginContext *owner { nullptr };
    };
    std::map<int32_t, DisplayCallbackEntry> displayCallbacks_;
    std::mutex displayCallbacksMutex_;
    int32_t nextDisplayCallbackId_ { 1 };
    void RemoveDisplayCallbacksOf(IPluginContext *owner);
};
} // namespace MMI
} // namespace OHOS
#endif // MULTIMODAL_INPUT_PLUGIN_MANAGER_H
