/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "setanrobserver_fuzzer.h"

#include "input_manager.h"
#include "i_anr_observer.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SetAnrObserverFuzzTest"

namespace OHOS {
namespace MMI {
class IAnrObserverTest : public IAnrObserver {
public:
    IAnrObserverTest() : IAnrObserver() {}
    virtual ~IAnrObserverTest() {}
    void OnAnr(int32_t pid, int32_t eventId) const override
    {
        MMI_HILOGD("Set anr success");
    };
};

void SetAnrObserverFuzzTest(const uint8_t* data, size_t /* size */)
{
    std::shared_ptr<IAnrObserverTest> observer = std::make_shared<IAnrObserverTest>();
    MMI_HILOGD("Set anr success");
    InputManager::GetInstance()->SetAnrObserver(observer);
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::SetAnrObserverFuzzTest(data, size);
    return 0;
}

