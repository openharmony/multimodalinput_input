/*
* Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "mock.h"
 
#include <fcntl.h>
#include <stdlib.h>
#include <iostream>
 
namespace OHOS {
namespace MMI {
bool InputManager::IsPointerInit()
{
    return MOCKHANDLER->mockIsPointerInitRet;
}
 
int32_t InputManager::GetCurrentCursorInfo(bool& visible, PointerStyle& pointerStyle)
{
    visible = MOCKHANDLER->mockVisible;
    pointerStyle.id = MOCKHANDLER->mockPointerStyleId;
    return MOCKHANDLER->mockGetCurrentCursorInfoRet;
}
 
int32_t InputManager::GetUserDefinedCursorPixelMap(void *pixelMapPtr)
{
    auto newPixelMapPtr = static_cast<std::shared_ptr<Media::PixelMap> *>(pixelMapPtr);
    *newPixelMapPtr = MOCKHANDLER->mockPixelMapPtr;
    return MOCKHANDLER->mockGetUserDefinedCursorPixelMapRet;
}
}  // namespace MMI
}  // namespace OHOS