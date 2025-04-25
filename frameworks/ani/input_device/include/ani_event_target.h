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

#ifndef ANI_EVENT_TARGET_H
#define ANI_EVENT_TARGET_H

#include <ani.h>

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_manager.h"
#include "ani_util.h"

namespace OHOS {
namespace MMI {
class AniEventTarget : public IInputDeviceListener, public std::enable_shared_from_this<AniEventTarget> {
public:
    AniEventTarget();
    virtual ~AniEventTarget();
    DISALLOW_COPY_AND_MOVE(AniEventTarget);
    void AddListener(ani_env *env, const std::string &type, ani_object handle);
    void ResetEnv();
    void OnDeviceAdded(int32_t deviceId, const std::string &type) override;
    void OnDeviceRemoved(int32_t deviceId, const std::string &type) override;

private:
    static void EmitAddedDeviceEvent(const std::shared_ptr<AniUtil::ReportData> &reportData);
    static void EmitRemoveDeviceEvent(const std::shared_ptr<AniUtil::ReportData> &reportData);
    static bool EmitCallbackWork(ani_env *env, const std::shared_ptr<AniUtil::ReportData> &reportData,
        const std::string &type);
    void GetMainEventHandler();
    void PostMainThreadTask(const std::function<void()> task);

private:
    inline static std::map<std::string, std::vector<std::unique_ptr<AniUtil::CallbackInfo>>> devListener_ {};
    bool isListeningProcess_ { false };
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler_ = nullptr;
};
} // namespace MMI
} // namespace OHOS
#endif // ANI_EVENT_TARGET_H