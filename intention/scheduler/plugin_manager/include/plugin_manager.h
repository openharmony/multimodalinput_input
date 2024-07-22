/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef PLUGIN_MANAGER_H
#define PLUGIN_MANAGER_H

#include <memory>
#include <mutex>

#include <dlfcn.h>

#include "nocopyable.h"

#include "i_context.h"
#include "i_plugin_manager.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

// Loading、unloading and bookkeeping of modules.
class PluginManager final : public IPluginManager {
    template<typename IPlugin>
    class Plugin final {
    public:
        Plugin(IContext *context, void *handle);
        ~Plugin();
        DISALLOW_COPY_AND_MOVE(Plugin);

        IPlugin* GetInstance();

    private:
        IContext *context_ { nullptr };
        void *handle_ { nullptr };
        IPlugin *instance_ { nullptr };
    };

    template<typename IPlugin>
    using CreatePlugin = IPlugin* (*)(IContext *context);

    template<typename IPlugin>
    using DestroyPlugin = void (*)(IPlugin *);

public:
    PluginManager(IContext *context) : context_(context) {}
    ~PluginManager() = default;
    DISALLOW_COPY_AND_MOVE(PluginManager);

    ICooperate* LoadCooperate() override;
    void UnloadCooperate() override;

private:
    template<typename IPlugin>
    std::unique_ptr<Plugin<IPlugin>> LoadLibrary(IContext *context, const char *libPath);

private:
    std::mutex lock_;
    IContext *context_ { nullptr };
    std::unique_ptr<Plugin<ICooperate>> cooperate_ { nullptr };
};

template<typename IPlugin>
PluginManager::Plugin<IPlugin>::Plugin(IContext *context, void *handle)
    : context_(context), handle_(handle)
{}

template<typename IPlugin>
PluginManager::Plugin<IPlugin>::~Plugin()
{
    if (instance_ != nullptr) {
        DestroyPlugin<IPlugin> destroy =
            reinterpret_cast<DestroyPlugin<IPlugin>>(::dlsym(handle_, "DestroyInstance"));
        if (destroy != nullptr) {
            destroy(instance_);
        }
    }
    ::dlclose(handle_);
}

template<typename IPlugin>
IPlugin* PluginManager::Plugin<IPlugin>::GetInstance()
{
    if (instance_ != nullptr) {
        return instance_;
    }
    CreatePlugin<IPlugin> create = reinterpret_cast<CreatePlugin<IPlugin>>(::dlsym(handle_, "CreateInstance"));
    if (create != nullptr) {
        instance_ = create(context_);
    }
    return instance_;
}

template<typename IPlugin>
std::unique_ptr<PluginManager::Plugin<IPlugin>> PluginManager::LoadLibrary(IContext *context, const char *libPath)
{
    char realPath[PATH_MAX] = { 0 };
    if (realpath(libPath, realPath) == nullptr) {
        FI_HILOGE("Path is error, path is %{public}s", libPath);
        return nullptr;
    }
    void *handle = ::dlopen(libPath, RTLD_NOW);
    return (handle != nullptr ? std::make_unique<Plugin<IPlugin>>(context, handle) : nullptr);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // PLUGIN_MANAGER_H