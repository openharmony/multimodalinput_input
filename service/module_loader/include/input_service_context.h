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

#ifndef INPUT_SERVICE_CONTEXT_H
#define INPUT_SERVICE_CONTEXT_H

#include "nocopyable.h"

#include "i_input_service_context.h"

namespace OHOS {
namespace MMI {
class InputServiceContext final : public IInputServiceContext {
public:
    InputServiceContext() = default;
    ~InputServiceContext() = default;
    DISALLOW_COPY_AND_MOVE(InputServiceContext);

    std::shared_ptr<IDelegateInterface> GetDelegateInterface() const override;
    IUdsServer* GetUDSServer() const override;
    std::shared_ptr<IInputEventHandler> GetEventNormalizeHandler() const override;
    std::shared_ptr<IInputEventHandler> GetMonitorHandler() const override;
    std::shared_ptr<ITimerManager> GetTimerManager() const override;
    std::shared_ptr<IInputWindowsManager> GetInputWindowsManager() const override;

    void AttachDelegateInterface(std::shared_ptr<IDelegateInterface> delegate);

private:
    std::weak_ptr<IDelegateInterface> delegate_;
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_SERVICE_CONTEXT_H