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

#ifndef GESTURESENSE_WRAPPER_H
#define GESTURESENSE_WRAPPER_H

#include "nocopyable.h"
#include "singleton.h"

namespace OHOS {
namespace MMI {
typedef float scalar;

class GesturesenseWrapper final {
    DECLARE_DELAYED_SINGLETON(GesturesenseWrapper);
public:
    DISALLOW_COPY_AND_MOVE(GesturesenseWrapper);
    void InitGestureSenseWrapper();
    typedef int32_t (*TOUCH_UP)(const std::vector<float> &, const std::vector<int64_t> &, bool, bool);
    typedef scalar (*GET_BOUNDING_SQUARENESS)(const std::vector<scalar> &);
    TOUCH_UP touchUp_ { nullptr };
    GET_BOUNDING_SQUARENESS getBoundingSquareness_ { nullptr };

private:
    void* gesturesenseWrapperHandle_ { nullptr };
};

#define GESTURESENSE_WRAPPER ::OHOS::DelayedSingleton<GesturesenseWrapper>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // GESTURESENSE_WRAPPER_H