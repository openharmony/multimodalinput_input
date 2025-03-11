/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "input_screen_capture_agent.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputScreenCaptureAgent"

namespace OHOS {
namespace MMI {
namespace {
#ifdef __aarch64__
const std::string REFERENCE_LIB_PATH = "/system/lib64/platformsdk";
#else
const std::string REFERENCE_LIB_PATH = "/system/lib/platformsdk";
#endif
const std::string FILESEPARATOR = "/";
const std::string REFERENCE_LIB_NAME = "libmmi-screen_capture.z.so";
const std::string REFENCE_LIB_ABSOLUTE_PATH = REFERENCE_LIB_PATH + FILESEPARATOR + REFERENCE_LIB_NAME;
}

InputScreenCaptureAgent::~InputScreenCaptureAgent()
{
    std::lock_guard<std::mutex> guard(agentMutex_);
    if (handle_.handle != nullptr) {
        handle_.Free();
    }
}

int32_t InputScreenCaptureAgent::LoadLibrary()
{
    std::lock_guard<std::mutex> guard(agentMutex_);
    if (handle_.handle != nullptr) {
        MMI_HILOGD("The library has already been loaded");
        return RET_OK;
    }
    char libRealPath[PATH_MAX] = {};
    if (realpath(REFENCE_LIB_ABSOLUTE_PATH.c_str(), libRealPath) == nullptr) {
        MMI_HILOGE("Get file real path fail");
        return RET_ERR;
    }
    handle_.handle = dlopen(libRealPath, RTLD_LAZY);
    if (handle_.handle == nullptr) {
        MMI_HILOGE("dlopen failed, reason:%{public}s", dlerror());
        return RET_ERR;
    }
    handle_.isWorking = reinterpret_cast<int32_t (*)(int32_t)>(dlsym(handle_.handle, "IsScreenCaptureWorking"));
    if (handle_.isWorking == nullptr) {
        MMI_HILOGE("dlsym isWorking failed: error:%{public}s", dlerror());
        handle_.Free();
        return RET_ERR;
    }
    handle_.registerListener = reinterpret_cast<void (*)(ScreenCaptureCallback)>(
        dlsym(handle_.handle, "RegisterListener"));
    if (handle_.registerListener == nullptr) {
        MMI_HILOGE("dlsym registerListener failed: error:%{public}s", dlerror());
        handle_.Free();
        return RET_ERR;
    }
    return RET_OK;
}

bool InputScreenCaptureAgent::IsScreenCaptureWorking(int32_t capturePid)
{
    if (LoadLibrary() != RET_OK) {
        MMI_HILOGE("LoadLibrary fail");
        return {};
    }
    return handle_.isWorking(capturePid);
}

void InputScreenCaptureAgent::RegisterListener(ScreenCaptureCallback callback)
{
    if (LoadLibrary() != RET_OK) {
        MMI_HILOGE("LoadLibrary fail");
        return;
    }
    handle_.registerListener(callback);
}

bool InputScreenCaptureAgent::IsMusicActivate()
{
    if (LoadAudioLibrary() != RET_OK) {
        MMI_HILOGE("LoadLibrary fail");
        return false;
    }
    return handle_.isMusicActivate();
}

int32_t InputScreenCaptureAgent::LoadAudioLibrary()
{
    std::lock_guard<std::mutex> guard(agentMutex_);
    if (handle_.handle != nullptr) {
        MMI_HILOGD("The library has already been loaded");
        return RET_OK;
    }
    char libRealPath[PATH_MAX] = {};
    if (realpath(REFENCE_LIB_ABSOLUTE_PATH.c_str(), libRealPath) == nullptr) {
        MMI_HILOGE("Get file real path fail");
        return RET_ERR;
    }
    handle_.handle = dlopen(libRealPath, RTLD_LAZY);
    if (handle_.handle == nullptr) {
        MMI_HILOGE("dlopen failed, reason:%{public}s", dlerror());
        return RET_ERR;
    }
    handle_.isMusicActivate = reinterpret_cast<bool (*)()>(dlsym(handle_.handle, "IsMusicActivate"));
    if (handle_.isMusicActivate == nullptr) {
        MMI_HILOGE("dlsym isWorking failed: error:%{public}s", dlerror());
        handle_.Free();
        return RET_ERR;
    }
    return RET_OK;
}
}
}