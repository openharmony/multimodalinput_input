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
#include "cursor_drawing_adapter.h"
#include "mmi_log.h"
#include "i_pointer_drawing_manager.h"

#define MMI_LOG_TAG "CursorDrawingAdapter"
void* GetPointerInstance()
{
    auto instance = OHOS::MMI::IPointerDrawingManager::GetInstance();
    if (instance == nullptr) {
        MMI_HILOGE("instace is nullptr");
        return nullptr;
    }
    return reinterpret_cast<void*>(instance);
}