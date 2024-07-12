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

#ifndef COOPERATE_HOTAREA_H
#define COOPERATE_HOTAREA_H

#include <set>

#include "nocopyable.h"
#include "pointer_event.h"

#include "cooperate_events.h"
#include "coordination_message.h"
#include "i_context.h"
#include "proto.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {
class HotArea final {
public:
    struct HotAreaInfo {
        int32_t pid { -1 };
        MessageId msgId { MessageId::INVALID };
        HotAreaType msg { HotAreaType::AREA_NONE };
        bool isEdge { false };

        bool operator<(const HotAreaInfo &other) const
        {
            return (pid < other.pid);
        }
    };

    HotArea(IContext *env) : env_(env) {}
    ~HotArea() = default;
    DISALLOW_COPY_AND_MOVE(HotArea);

    void AddListener(const RegisterHotareaListenerEvent &event);
    void RemoveListener(const UnregisterHotareaListenerEvent &event);

    void EnableCooperate(const EnableCooperateEvent &event);
    int32_t ProcessData(std::shared_ptr<MMI::PointerEvent> pointerEvent);
    void OnClientDied(const ClientDiedEvent &event);

private:
    void CheckInHotArea();
    void CheckPointerToEdge(HotAreaType type);
    void NotifyMessage();
    void OnHotAreaMessage(HotAreaType msg, bool isEdge);
    void NotifyHotAreaMessage(int32_t pid, MessageId msgId, HotAreaType msg, bool isEdge);

private:
    IContext *env_ { nullptr };
    int32_t width_ { 720 };
    int32_t height_ { 1280 };
    int32_t displayX_ { 0 };
    int32_t displayY_ { 0 };
    int32_t deltaX_ { 0 };
    int32_t deltaY_ { 0 };
    bool isEdge_ { false };
    HotAreaType type_ { HotAreaType::AREA_NONE };
    std::mutex lock_;
    std::set<HotAreaInfo> callbacks_;
};
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // COOPERATE_HOTAREA_H
