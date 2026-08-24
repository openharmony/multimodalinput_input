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

#ifndef MOCK_DISPLAY_MANAGER_LITE_H
#define MOCK_DISPLAY_MANAGER_LITE_H

#include "dm_common.h"
#include "refbase.h"

namespace OHOS::Rosen {
class DisplayLite : public RefBase {
public:
    static int32_t mockWidth;
    static int32_t mockHeight;
    static Rotation mockRotation;
    static bool mockValid;

    DisplayLite() = default;
    ~DisplayLite() override = default;

    int32_t GetWidth() const
    {
        return mockWidth;
    }

    int32_t GetHeight() const
    {
        return mockHeight;
    }

    Rotation GetRotation() const
    {
        return mockRotation;
    }
};

class DisplayManagerLite {
public:
    static DisplayManagerLite& GetInstance()
    {
        static DisplayManagerLite instance;
        return instance;
    }

    sptr<DisplayLite> GetDisplayById(DisplayId displayId)
    {
        if (!DisplayLite::mockValid) {
            return nullptr;
        }
        return sptr<DisplayLite>::MakeSptr();
    }

    bool IsFoldable()
    {
        return false;
    }
};
} // namespace OHOS:Rosen

#endif // MOCK_DISPLAY_MANAGER_LITE_H