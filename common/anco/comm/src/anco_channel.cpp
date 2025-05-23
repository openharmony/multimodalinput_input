/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "anco_channel.h"

#include "define_multimodal.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AncoChannel"

namespace OHOS {
namespace MMI {

AncoChannel::AncoChannel(std::shared_ptr<IAncoConsumer> consumer)
    : consumer_(consumer)
{}

ErrCode AncoChannel::SyncInputPointEvent(const PointerEvent &pointerEvent)
{
    CHKPR(consumer_, RET_ERR);
    auto pointerEventPtr = std::make_shared<PointerEvent>(pointerEvent);
    CHKPR(pointerEventPtr, RET_ERR);
    return consumer_->SyncInputEvent(pointerEventPtr);
}

ErrCode AncoChannel::SyncInputKeyEvent(const KeyEvent &keyEvent)
{
    CHKPR(consumer_, RET_ERR);
    auto keyEventPtr = std::make_shared<KeyEvent>(keyEvent);
    CHKPR(keyEventPtr, RET_ERR);
    return consumer_->SyncInputEvent(keyEventPtr);
}

ErrCode AncoChannel::UpdateWindowInfo(const AncoWindows &windows)
{
    CHKPR(consumer_, RET_ERR);
    auto windowsPtr = std::make_shared<AncoWindows>(windows);
    CHKPR(windowsPtr, RET_ERR);
    return consumer_->UpdateWindowInfo(windowsPtr);
}

ErrCode AncoChannel::UpdateOneHandData(const AncoOneHandData &oneHandData)
{
    CHKPR(consumer_, RET_ERR);
    return consumer_->UpdateOneHandData(oneHandData);
}

ErrCode AncoChannel::SyncKnuckleStatus(bool isKnuckleEnable)
{
    CHKPR(consumer_, RET_ERR);
    return consumer_->SyncKnuckleStatus(isKnuckleEnable);
}
} // namespace MMI
} // namespace OHOS
