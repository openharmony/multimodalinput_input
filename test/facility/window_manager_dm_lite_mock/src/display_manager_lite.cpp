/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "display_manager_lite.h"

namespace OHOS::Rosen {
DisplayManagerLite& DisplayManagerLite::GetInstance()
{
    static DisplayManagerLite instance {};
    return instance;
}

DMError DisplayManagerLite::RegisterFoldStatusListener(sptr<DisplayManagerLite::IFoldStatusListener> listener)
{
    listeners_.emplace(listener);
    return DMError::DM_OK;
}

DMError DisplayManagerLite::UnregisterFoldStatusListener(sptr<DisplayManagerLite::IFoldStatusListener> listener)
{
    listeners_.erase(listener);
    return DMError::DM_OK;
}

FoldStatus DisplayManagerLite::GetFoldStatus() const
{
    return foldStatus_;
}

void DisplayManagerLite::NotifyFoldStatusChanged(FoldStatus foldStatus)
{
    foldStatus_ = foldStatus;
    for (const auto &listener : listeners_) {
        listener->OnFoldStatusChanged(foldStatus);
    }
}
} // namespace OHOS::Rosen
