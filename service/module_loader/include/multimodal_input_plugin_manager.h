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
#include <map>
#include "plugin_stage.h"
#include "timer_manager.h"
#include "uds_server.h"
#include "net_packet.h"
#include "input_event_data_transformation.h"

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
typedef int32_t (*UnintPlugin)(std::shared_ptr<IInputPlugin> plugin);

const int32_t RET_NOTDO = 0;
const int32_t RET_DO = 1;

struct InputPlugin : public IPluginContext {
public:
    InputPlugin() {};
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

    int32_t prio_ = 200;
    std::function<void(PluginEventType, int64_t)> callback_;
    UnintPlugin unintPlugin_ = nullptr;
    std::shared_ptr<IInputPlugin> plugin_;
    std::string name_;
    void* handle_;

private:
    InputPluginStage stage_;
    int32_t timerCnt_ = 0;
};

struct InputPluginManager {
public:
    InputPluginManager(const InputPluginManager &) = delete;
    InputPluginManager &operator=(const InputPluginManager &) = delete;
    static InputPluginManager *GetInstance(const std::string &directory = "");
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

private:
    explicit InputPluginManager(const std::string& directory) : directory_(directory) {};
    ~InputPluginManager();
    bool IntermediateEndEvent(PluginEventType pluginEvent);
    bool LoadPlugin(const std::string &path);

    UDSServer* udsServer_ {nullptr};
    std::string directory_;
    std::map<InputPluginStage, std::list<std::shared_ptr<IPluginContext>>> plugins_;
    inline static InputPluginManager* instance_ { nullptr };
    inline static std::once_flag init_flag_;
};
} // namespace MMI
} // namespace OHOS
#endif // MULTIMODAL_INPUT_PLUGIN_MANAGER_H
