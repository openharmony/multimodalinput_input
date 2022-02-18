/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef COMMON_EVENT_HANDLER_H
#define COMMON_EVENT_HANDLER_H

#include "standardized_event_handler.h"
#include "multimodal_event.h"

namespace OHOS {
namespace MMI {
class CommonEventHandler : public StandardizedEventHandler {
public:
    CommonEventHandler();
    virtual ~CommonEventHandler();
    virtual bool OnShowMenu(const MultimodalEvent& event) override;
    virtual bool OnSend(const MultimodalEvent& event) override;
    virtual bool OnCopy(const MultimodalEvent& event) override;
    virtual bool OnPaste(const MultimodalEvent& event) override;
    virtual bool OnCut(const MultimodalEvent& event) override;
    virtual bool OnUndo(const MultimodalEvent& event) override;
    virtual bool OnRefresh(const MultimodalEvent& event) override;
    virtual bool OnStartDrag(const MultimodalEvent& event) override;
    virtual bool OnCancel(const MultimodalEvent& event) override;
    virtual bool OnEnter(const MultimodalEvent& event) override;
    virtual bool OnPrevious(const MultimodalEvent& event) override;
    virtual bool OnNext(const MultimodalEvent& event) override;
    virtual bool OnBack(const MultimodalEvent& event) override;
    virtual bool OnPrint(const MultimodalEvent& event) override;
};
} // namespace MMI
} // namespace OHOS
#endif // COMMON_EVENT_HANDLER_H