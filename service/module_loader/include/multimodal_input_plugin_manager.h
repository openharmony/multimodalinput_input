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

#include <plugin_stage.h>
#include <timer_manager.h>

#include <dirent.h>
#include <dlfcn.h>
#include <map>

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
    PluginResult HandleEvent(libinput_event *event, int64_t frameTime);
    PluginResult HandleEvent(std::shared_ptr<KeyEvent> keyEvent, InputPluginStage stage);

    int32_t AddTimer(std::function<void()> func, int32_t intervalMs, int32_t repeatCount) override;
    int32_t RemoveTimer(int32_t id) override;
    void DispatchEvent(libinput_event *event, int64_t frameTime) override;
    void DispatchEvent(std::shared_ptr<KeyEvent> keyEvent, InputDispatchStage stage) override;

    int32_t timerCnt_ = 0;
    int32_t prio_ = 200;
    std::function<void(libinput_event*, int64_t)> callback_;
    std::function<void(std::shared_ptr<KeyEvent>)> keyEventCallback_;
    UnintPlugin unintPlugin_ = nullptr;
    std::shared_ptr<IInputPlugin> plugin_;
    std::string name_;
    void* handle_;

private:
    InputPluginStage stage_;
};

struct InputPluginManager {
public:
    ~InputPluginManager();
    explicit InputPluginManager(const std::string& directory) : directory_(directory) {};
    static std::shared_ptr<InputPluginManager> GetInstance(const std::string &directory = "");
    int32_t Init();
    void Dump(int fd);
    int32_t HandleEvent(libinput_event* event, int64_t frameTime, InputPluginStage stage);
    int32_t HandleEvent(std::shared_ptr<KeyEvent> keyEvent, InputPluginStage stage);
    void PluginAssignmentCallBack(std::function<void(libinput_event*, int64_t)> callback, InputPluginStage stage);
    void PluginAssignmentCallBack(std::function<void(std::shared_ptr<KeyEvent>)> callback, InputPluginStage stage);
    void PrintPlugins();
    int32_t DoHandleEvent(libinput_event *event, int64_t frameTime, InputPlugin *iplugin, InputPluginStage stage);
    int32_t DoHandleEvent(std::shared_ptr<KeyEvent> keyEvent, InputPlugin *iplugin, InputPluginStage stage);

private:
    bool IntermediateEndEvent(libinput_event *event);
    bool LoadPlugin(const std::string &path);

    std::string directory_;
    std::map<InputPluginStage, std::list<std::shared_ptr<InputPlugin>>> plugins_;
    static std::shared_ptr<InputPluginManager> instance_;
    static std::once_flag init_flag_;
};
} // namespace MMI
} // namespace OHOS
#endif // MULTIMODAL_INPUT_PLUGIN_MANAGER_H
