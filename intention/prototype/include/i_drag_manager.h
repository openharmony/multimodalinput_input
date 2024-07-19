/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef I_DRAG_MANAGER_H
#define I_DRAG_MANAGER_H

#include <cstdint>
#include <functional>

#include <display_manager.h>
#include <input_manager.h>
#include "transaction/rs_transaction.h"

#include "drag_data.h"
#include "stream_session.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class IDragManager {
public:
    IDragManager() = default;
    virtual ~IDragManager() = default;

    virtual void Dump(int32_t fd) const = 0;
    virtual void RegisterStateChange(std::function<void(DragState)> callback) = 0;
    virtual int32_t AddListener(int32_t pid) = 0;
    virtual int32_t RemoveListener(int32_t pid) = 0;
    virtual int32_t AddSubscriptListener(int32_t pid) = 0;
    virtual int32_t RemoveSubscriptListener(int32_t pid) = 0;
    virtual int32_t StartDrag(const DragData &dragData, int32_t pid) = 0;
    virtual int32_t StopDrag(const DragDropResult &dropResult, const std::string &packageName = "") = 0;
    virtual int32_t GetDragData(DragData &dragData) = 0;
    virtual int32_t GetDragTargetPid() const = 0;
    virtual int32_t GetUdKey(std::string &udKey) const = 0;
    virtual int32_t OnGetShadowOffset(ShadowOffset &shadowOffset) = 0;
    virtual DragState GetDragState() const = 0;
    virtual int32_t GetDragState(DragState &dragState) = 0;
    virtual int32_t GetExtraInfo(std::string &extraInfo) const = 0;
    virtual void SetDragState(DragState state) = 0;
    virtual DragResult GetDragResult() const = 0;
    virtual int32_t GetDragSummary(std::map<std::string, int64_t> &summarys) = 0;
    virtual int32_t GetDragAction(DragAction &dragAction) const = 0;
    virtual int32_t OnSetDragWindowVisible(bool visible, bool isForce = false) = 0;
    virtual OHOS::MMI::ExtraData GetExtraData(bool appended) const = 0;
    virtual void RegisterNotifyPullUp(std::function<void(bool)> callback) = 0;
    virtual void SetPointerEventFilterTime(int64_t filterTime) = 0;
    virtual void MoveTo(int32_t x, int32_t y) = 0;
    virtual int32_t UpdateDragStyle(DragCursorStyle style, int32_t targetPid, int32_t targetTid) = 0;
    virtual int32_t UpdateShadowPic(const ShadowInfo &shadowInfo) = 0;
    virtual int32_t UpdatePreviewStyle(const PreviewStyle &previewStyle) = 0;
    virtual int32_t UpdatePreviewStyleWithAnimation(const PreviewStyle &previewStyle,
        const PreviewAnimation &animation) = 0;
    virtual int32_t RotateDragWindowSync(const std::shared_ptr<Rosen::RSTransaction>& rsTransaction = nullptr) = 0;
    virtual void GetAllowDragState(bool &isAllowDrag) = 0;
    virtual int32_t RotateDragWindow(Rosen::Rotation rotation) = 0;
    virtual int32_t EnterTextEditorArea(bool enable) = 0;
    virtual int32_t AddPrivilege(int32_t tokenId) = 0;
    virtual int32_t EraseMouseIcon() = 0;
    virtual void SetDragWindowScreenId(uint64_t displayId, uint64_t screenId) = 0;
    virtual int32_t AddSelectedPixelMap(std::shared_ptr<OHOS::Media::PixelMap> pixelMap) = 0;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // I_DRAG_MANAGER_H