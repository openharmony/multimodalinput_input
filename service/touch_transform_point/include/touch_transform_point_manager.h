/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef TOUCH_TRANSFORM_POINT_MANAGER_H
#define TOUCH_TRANSFORM_POINT_MANAGER_H


#include <map>
#include <memory>
#include "touch_transform_point_processor.h"
#include "touchpad_transform_point_processor.h"
#include "c_singleton.h"
namespace OHOS {
namespace MMI {
class TouchTransformPointManager : public CSingleton<TouchTransformPointManager> {
public:
    std::shared_ptr<PointerEvent> onLibinputTouchEvent(libinput_event& event);
    std::shared_ptr<PointerEvent> onLibinputTouchPadEvent(libinput_event& event);
private:
    std::map<int32_t, std::shared_ptr<TouchTransformPointProcessor>> processors_;
    std::map<int32_t, std::shared_ptr<TouchPadTransformPointProcessor>> touchpadpro_;
};
#define touchTransformPointManger OHOS::MMI::TouchTransformPointManager::GetInstance()
}
}
#endif
