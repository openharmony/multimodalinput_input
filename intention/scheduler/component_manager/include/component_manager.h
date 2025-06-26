/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef COMPONENT_MANAGER_H
#define COMPONENT_MANAGER_H

#include <memory>
#include <dlfcn.h>
#include <nocopyable.h>

#include "define_multimodal.h"
#include "i_context.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ComponentManager"

namespace OHOS {
namespace MMI {

// Loading、unloading and bookkeeping of modules.
class ComponentManager final {
private:
    template<typename IComponent>
    using CreateComponent = IComponent* (*)(IContext *context);

    template<typename IComponent>
    using DestroyComponent = void (*)(IComponent *);

public:
    template<typename IComponent>
    class Component final {
    public:
        Component(IContext *context, void *handle);
        Component(Component &&other);
        ~Component();
        DISALLOW_COPY(Component);

        Component<IComponent>& operator=(Component<IComponent> &&other);
        void operator()(IComponent *instance);
        IComponent* GetInstance();

    private:
        void DeleteInstance(IComponent *instance);
        void Unload();

        IContext *context_ { nullptr };
        void *handle_ { nullptr };
        IComponent *instance_ { nullptr };
    };

    ComponentManager() = default;
    ~ComponentManager() = default;
    DISALLOW_COPY_AND_MOVE(ComponentManager);

    template<typename IComponent>
    static std::unique_ptr<IComponent, Component<IComponent>> LoadLibrary(IContext *context, const char *libPath);
};

template<typename IComponent>
ComponentManager::Component<IComponent>::Component(IContext *context, void *handle)
    : context_(context), handle_(handle)
{}

template<typename IComponent>
ComponentManager::Component<IComponent>::~Component()
{
    Unload();
}

template<typename IComponent>
ComponentManager::Component<IComponent>::Component(ComponentManager::Component<IComponent> &&other)
    : context_(other.context_), handle_(other.handle_), instance_(other.instance_)
{
    other.context_ = nullptr;
    other.handle_ = nullptr;
    other.instance_ = nullptr;
}

template<typename IComponent>
ComponentManager::Component<IComponent>& ComponentManager::Component<IComponent>::operator=(
    Component<IComponent> &&other)
{
    if (&other == this) {
        return *this;
    }
    Unload();
    context_ = other.context_;
    handle_ = other.handle_;
    instance_ = other.instance_;
    other.context_ = nullptr;
    other.handle_ = nullptr;
    other.instance_ = nullptr;
    return *this;
}

template<typename IComponent>
void ComponentManager::Component<IComponent>::operator()(IComponent *instance)
{
    DeleteInstance(instance);
}

template<typename IComponent>
IComponent* ComponentManager::Component<IComponent>::GetInstance()
{
    if (instance_ != nullptr) {
        return instance_;
    }
    ::dlerror();
    CreateComponent<IComponent> create =
        reinterpret_cast<CreateComponent<IComponent>>(::dlsym(handle_, "CreateInstance"));
    if (auto err = ::dlerror(); err != nullptr) {
        MMI_HILOGE("dlsym('CreateInstance') fail: %{public}s", err);
        return nullptr;
    }
    instance_ = create(context_);
    return instance_;
}

template<typename IComponent>
void ComponentManager::Component<IComponent>::DeleteInstance(IComponent *instance)
{
    if ((handle_ == nullptr) || (instance_ == nullptr) || (instance_ != instance)) {
        return;
    }
    ::dlerror();
    DestroyComponent<IComponent> destroy =
        reinterpret_cast<DestroyComponent<IComponent>>(::dlsym(handle_, "DestroyInstance"));
    if (auto err = ::dlerror(); err != nullptr) {
        MMI_HILOGE("dlsym('DestroyInstance') fail: %{public}s", err);
        return;
    }
    destroy(instance_);
    instance_ = nullptr;
}

template<typename IComponent>
void ComponentManager::Component<IComponent>::Unload()
{
    if (handle_ != nullptr) {
        DeleteInstance(instance_);
        if (::dlclose(handle_) != RET_OK) {
            MMI_HILOGE("dlclose fail: %{public}s", ::dlerror());
        }
        handle_ = nullptr;
    }
}

template<typename IComponent>
std::unique_ptr<IComponent, ComponentManager::Component<IComponent>> ComponentManager::LoadLibrary(
    IContext *context, const char *libPath)
{
    if (libPath == nullptr) {
        MMI_HILOGE("libPath is null");
        return { nullptr, ComponentManager::Component<IComponent>(nullptr, nullptr) };
    }
    void *handle = ::dlopen(libPath, RTLD_NOW);
    if (handle == nullptr) {
        if (auto err = ::dlerror(); err != nullptr) {
            MMI_HILOGE("dlopen fail for %{public}s: %{public}s", libPath, err);
        } else {
            MMI_HILOGE("dlopen fail for %{public}s", libPath);
        }
        return { nullptr, ComponentManager::Component<IComponent>(nullptr, nullptr) };
    }
    Component<IComponent> plugin(context, handle);
    return { plugin.GetInstance(), std::move(plugin) };
}
} // namespace MMI
} // namespace OHOS
#endif // COMPONENT_MANAGER_H
