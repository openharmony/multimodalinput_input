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

#ifndef MOCK_H
#define MOCK_H

#include <singleton.h>

#include "define_multimodal.h"
#include "uds_session.h"


namespace OHOS {
namespace MMI {
class MockHandler : public DelayedSingleton<MockHandler> {
public:
    bool mockChkRWErrorRet { false };
    bool mockGetPointerItemRet { true };
    int32_t mockMarshallingRet { RET_OK };
    bool mockSendMsgRet { true };
    SessionPtr mockSessionPara { nullptr };
};
#define MOCKHANDLER DelayedSingleton<MockHandler>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif