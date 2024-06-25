/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

int32_t AncoChannel::SyncInputEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(consumer_, RET_ERR);
    return consumer_->SyncInputEvent(pointerEvent);
}

int32_t AncoChannel::SyncInputEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPR(consumer_, RET_ERR);
    return consumer_->SyncInputEvent(keyEvent);
}

int32_t AncoChannel::UpdateWindowInfo(std::shared_ptr<AncoWindows> windows)
{
    CHKPR(consumer_, RET_ERR);
    return consumer_->UpdateWindowInfo(windows);
}
} // namespace MMI
} // namespace OHOS
