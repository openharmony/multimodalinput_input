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

#ifndef INPUT_ACTIVE_SUBSCRIBE_MANAGER_H
#define INPUT_ACTIVE_SUBSCRIBE_MANAGER_H

#include <map>
#include <singleton.h>
#include "i_input_event_consumer.h"

namespace OHOS {
namespace MMI {
class InputActiveSubscribeManager final {
    DECLARE_SINGLETON(InputActiveSubscribeManager);
public:
    class SubscribeInputActiveInfo {
    public:
        SubscribeInputActiveInfo(std::shared_ptr<IInputEventConsumer> inputEventConsumer, int64_t interval)
            : inputActiveInterval_(interval), callback_(inputEventConsumer) {};
        ~SubscribeInputActiveInfo() = default;
        int64_t GetInputActiveInterval() const
        {
            return inputActiveInterval_;
        }
        std::shared_ptr<IInputEventConsumer> GetCallback() const
        {
            return callback_;
        }
    private:
        int64_t inputActiveInterval_ { 0 };
        std::shared_ptr<IInputEventConsumer> callback_ { nullptr };
    };
public:
    DISALLOW_MOVE(InputActiveSubscribeManager);
    int32_t SubscribeInputActive(std::shared_ptr<IInputEventConsumer> inputEventConsumer, int64_t interval);
    int32_t UnsubscribeInputActive(int32_t subscribeId);

    int32_t OnSubscribeInputActiveCallback(std::shared_ptr<KeyEvent> keyEvent, int32_t subscribeId);
    int32_t OnSubscribeInputActiveCallback(std::shared_ptr<PointerEvent> pointerEvent, int32_t subscribeId);
    void OnConnected();

private:
    std::shared_ptr<SubscribeInputActiveInfo> subscribeInfo_ = nullptr;
    std::mutex mtx_;
};
#define INPUT_ACTIVE_SUBSCRIBE_MGR ::OHOS::Singleton<InputActiveSubscribeManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // INPUT_ACTIVE_SUBSCRIBE_MANAGER_H