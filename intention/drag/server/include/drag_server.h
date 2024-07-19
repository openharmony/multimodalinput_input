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

#ifndef DRAG_SERVER_H
#define DRAG_SERVER_H

#include "nocopyable.h"

#include "accesstoken_kit.h"
#include "i_context.h"
#include "i_plugin.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DragServer final : public IPlugin {
public:
    DragServer(IContext *env);
    ~DragServer() = default;
    DISALLOW_COPY_AND_MOVE(DragServer);

    int32_t Enable(CallingContext &context, MessageParcel &data, MessageParcel &reply) override;
    int32_t Disable(CallingContext &context, MessageParcel &data, MessageParcel &reply) override;
    int32_t Start(CallingContext &context, MessageParcel &data, MessageParcel &reply) override;
    int32_t Stop(CallingContext &context, MessageParcel &data, MessageParcel &reply) override;
    int32_t AddWatch(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply) override;
    int32_t RemoveWatch(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply) override;
    int32_t SetParam(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply) override;
    int32_t GetParam(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply) override;
    int32_t Control(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply) override;

private:
    int32_t SetDragWindowVisible(CallingContext &context, MessageParcel &data, MessageParcel &reply);
    int32_t UpdateDragStyle(CallingContext &context, MessageParcel &data, MessageParcel &reply);
    int32_t UpdateShadowPic(CallingContext &context, MessageParcel &data, MessageParcel &reply);
    int32_t UpdatePreviewStyle(CallingContext &context, MessageParcel &data, MessageParcel &reply);
    int32_t UpdatePreviewAnimation(CallingContext &context, MessageParcel &data, MessageParcel &reply);
    int32_t RotateDragWindowSync(CallingContext &context, MessageParcel &data, MessageParcel &reply);
    int32_t GetDragTargetPid(CallingContext &context, MessageParcel &data, MessageParcel &reply);
    int32_t GetUdKey(CallingContext &context, MessageParcel &data, MessageParcel &reply);
    int32_t GetShadowOffset(CallingContext &context, MessageParcel &data, MessageParcel &reply);
    int32_t GetDragData(CallingContext &context, MessageParcel &data, MessageParcel &reply);
    int32_t GetDragState(CallingContext &context, MessageParcel &data, MessageParcel &reply);
    int32_t GetDragSummary(CallingContext &context, MessageParcel &data, MessageParcel &reply);
    int32_t GetDragAction(CallingContext &context, MessageParcel &data, MessageParcel &reply);
    int32_t GetExtraInfo(CallingContext &context, MessageParcel &data, MessageParcel &reply);
    int32_t EnterTextEditorArea(CallingContext &context, MessageParcel &data, MessageParcel &reply);
    int32_t SetDragWindowScreenId(CallingContext &context, MessageParcel &data, MessageParcel &reply);
    std::string GetPackageName(Security::AccessToken::AccessTokenID tokenId);
    int32_t AddSelectedPixelMap(CallingContext &context, MessageParcel &data, MessageParcel &reply);

    IContext *env_ { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DRAG_SERVER_H