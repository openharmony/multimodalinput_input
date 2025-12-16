/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef DRAG_SECURITY_MANAGER_H
#define DRAG_SECURITY_MANAGER_H

#include <map>
#include <mutex>
#include <vector>
#include <cstdint>
#include <string>
#include "hilog/log.h"
#include "pointer_event.h"
#include <unistd.h>
#include <dlfcn.h>

#ifdef OHOS_BUILD_ENABLE_DRAG_SECURITY
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <securec.h>
#endif // OHOS_BUILD_ENABLE_DRAG_SECURITY

namespace OHOS {
namespace MMI {

struct DragSecurityData {
    uint64_t timestampMs = 0;
    double coordinateX = 0.0;
    double coordinateY = 0.0;
};

typedef char* (*InputGenerateSignaturePtr)(const char *nonce, double coordinateX,
    double coordinateY, uint64_t timestampMs);
typedef void (*FreeSignaturePtr)(char* signature);

class DragSecurityManager {
public:
    static DragSecurityManager& GetInstance();
    int32_t DeliverNonce(const std::string& nonce);
    std::string GetNonce();
    void ResetNonce();
    void DragSecurityUpdatePointerEvent(std::shared_ptr<PointerEvent> pointerEvent);
private:
    DragSecurityManager();
    ~DragSecurityManager() = default;

#ifdef OHOS_BUILD_ENABLE_DRAG_SECURITY
    std::vector<uint8_t> GenerateSignature(const std::vector<uint8_t>& nonce,
        const DragSecurityData& dragEventData);
    std::string SerializeDragEventData(const DragSecurityData& data);
    std::string Base64Encode(const uint8_t* data, size_t len);
    std::string Base64Encode(const std::vector<uint8_t>& vec);
    std::vector<uint8_t> Base64Decode(const std::string& b64);
#endif // OHOS_BUILD_ENABLE_DRAG_SECURITY

    std::string nonce_;

    uint64_t GetCurrentTimesTampMs() const;
};
} // namespace MMI
} // namespace OHOS

#endif // DRAG_SECURITY_MANAGER_H