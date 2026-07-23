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

#ifndef FOUNDATION_WINDOW_MANAGER_DM_LITE_MOCK_H
#define FOUNDATION_WINDOW_MANAGER_DM_LITE_MOCK_H

#include <set>

#include "nocopyable.h"
#include "refbase.h"

namespace OHOS::Rosen {
enum class FoldStatus : uint32_t {
    UNKNOWN = 0,
    EXPAND = 1,
    FOLDED = 2,
};

enum class DMError : int32_t {
    DM_ERROR_UNKNOWN = -1,
    DM_OK = 0,
};

class DisplayManagerLite {
public:
    class IFoldStatusListener : public virtual RefBase {
    public:
        virtual void OnFoldStatusChanged(Rosen::FoldStatus foldStatus) = 0;
    };

    static DisplayManagerLite& GetInstance();

    DMError RegisterFoldStatusListener(sptr<IFoldStatusListener> listener);
    DMError UnregisterFoldStatusListener(sptr<IFoldStatusListener> listener);
    FoldStatus GetFoldStatus() const;
    void NotifyFoldStatusChanged(FoldStatus foldStatus);

private:
    DisplayManagerLite() = default;
    ~DisplayManagerLite() = default;
    DISALLOW_COPY_AND_MOVE(DisplayManagerLite);

    std::set<sptr<IFoldStatusListener>> listeners_;
    FoldStatus foldStatus_ { FoldStatus::UNKNOWN };
};
} // OHOS::Rosen
#endif // FOUNDATION_WINDOW_MANAGER_DM_LITE_MOCK_H