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

#ifndef INPUT_SCREEN_CAPTURE_AGENT_H
#define INPUT_SCREEN_CAPTURE_AGENT_H

#include <dlfcn.h>

#include "singleton.h"
#include "util.h"

namespace OHOS {
namespace MMI {

struct ScreenCaptureHandle {
    void *handle;
    int32_t (*isWorking)(int32_t);
    void (*registerListener)(ScreenCaptureCallback);

    ScreenCaptureHandle(): handle(nullptr), isWorking(nullptr), registerListener(nullptr) {}

    void Free()
    {
        if (handle != nullptr) {
            dlclose(handle);
            handle = nullptr;
        }
        isWorking = nullptr;
        registerListener = nullptr;
    }
};

class InputScreenCaptureAgent : public Singleton<InputScreenCaptureAgent> {
public:
    ~InputScreenCaptureAgent() override;
    bool IsScreenCaptureWorking(int32_t capturePid);
    void RegisterListener(ScreenCaptureCallback callback);

private:
    int32_t LoadLibrary();
    ScreenCaptureHandle handle_;
    std::mutex agentMutex_;
};
}
}

#endif