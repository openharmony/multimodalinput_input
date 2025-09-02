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

#ifndef TAIHE_EVENT_H
#define TAIHE_EVENT_H

#include "ohos.multimodalInput.inputDevice.impl.h"
#include "define_multimodal.h"
#include "input_manager.h"

namespace OHOS {
namespace MMI {
class TaiheEvent : public IInputDeviceListener, public std::enable_shared_from_this<TaiheEvent> {
public:
    static std::shared_ptr<TaiheEvent> GetInstance();
    bool AddCallback(std::string const &type, callbackTypes &&cb, uintptr_t opq);
    bool RemoveCallback(std::string const &type, uintptr_t opq);
    TaiheEvent();
    ~TaiheEvent();
    DISALLOW_COPY_AND_MOVE(TaiheEvent);
    void RegisterListener(std::string const &type, callbackTypes &&cb, uintptr_t opq);
    void UnregisterListener(std::string const &type, uintptr_t opq);
    void UnregisterAllListener(std::string const &type);
    void OnDeviceAdded(int32_t deviceId, const std::string &type) override;
    void OnDeviceRemoved(int32_t deviceId, const std::string &type) override;
private:
    std::map<std::string, std::vector<std::shared_ptr<CallbackObjects>>> devListener_;
    bool isListeningProcess_ { false };
    std::mutex mutex_;
};
} // namespace OHOS
} // namespace MMI
#endif // TAIHE_EVENT_H