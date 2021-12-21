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
#include "device_handler.h"
#include "log.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
DeviceHandler::DeviceHandler()
{
    type_ = MmiMessageId::DEVICE_BEGIN;
}

DeviceHandler::~DeviceHandler()
{
}

bool DeviceHandler::OnDeviceAdd(const DeviceEvent& multimodalEvent)
{
    return false;
}

bool DeviceHandler::OnDeviceRemove(const DeviceEvent& multimodalEvent)
{
    return false;
}
}
}
