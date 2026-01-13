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

#include "drag_security_manager.h"
#include <algorithm>
#include <chrono>
#include "mmi_log.h"
#include "define_multimodal.h"
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DragSecurityManager"

namespace OHOS {
namespace MMI {
namespace {
    const int32_t MAX_BASE64_LENGTH { 1024 };
    const int32_t SECURITY_DATA_LEN { 17 };
}

DragSecurityManager& DragSecurityManager::GetInstance()
{
    static DragSecurityManager instance;
    return instance;
}

DragSecurityManager::DragSecurityManager() = default;

uint64_t DragSecurityManager::GetCurrentTimesTampMs() const
{
    auto now = std::chrono::steady_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

int32_t DragSecurityManager::DeliverNonce(const std::string& nonce)
{
    CALL_INFO_TRACE;
    if (nonce.empty()) {
        MMI_HILOGE("nonce is empty");
        return RET_ERR;
    }
    nonce_ = nonce;
    return RET_OK;
}

std::string DragSecurityManager::GetNonce()
{
    return nonce_;
}

void DragSecurityManager::ResetNonce()
{
    nonce_ = "";
}

#ifdef OHOS_BUILD_ENABLE_DRAG_SECURITY
void DragSecurityManager::DragSecurityUpdatePointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_INFO_TRACE;
    auto now = std::chrono::steady_clock::now();
    auto duration = now.time_since_epoch();
    uint64_t distributeEventTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(duration).count());
    pointerEvent->SetDistributeEventTime(distributeEventTime);
    std::vector<uint8_t> nonceBin = Base64Decode(nonce_);
    std::string signature;
    PointerEvent::PointerItem pointerItem {};
    if (pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem)) {
        DragSecurityData dragEventData = {
            .timestampMs = distributeEventTime,
            .coordinateX = pointerItem.GetDisplayXPos(),
            .coordinateY = pointerItem.GetDisplayYPos(),
        };
        signature = Base64Encode(GenerateSignature(nonceBin, dragEventData));
    }
    if (signature.empty()) {
        MMI_HILOGE("Signature is empty");
        return;
    }
    pointerEvent->SetSignature(signature);
    ResetNonce();
}

std::vector<uint8_t> DragSecurityManager::GenerateSignature(const std::vector<uint8_t>& nonce,
    const DragSecurityData& dragSecurityData)
{
    CALL_INFO_TRACE;
    if (nonce.empty()) {
        MMI_HILOGE("Empty nonce provided");
        return {};
    }
    auto dataStr = SerializeDragEventData(dragSecurityData);
    if (dataStr.empty()) {
        MMI_HILOGE("Failed to serialize event data");
        return {};
    }
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int len = 0;
    HMAC(EVP_sha384(),
        nonce.data(),
        static_cast<int>(nonce.size()),
        reinterpret_cast<const unsigned char*>(dataStr.data()), dataStr.size(),
        digest,
        &len);
    return std::vector<uint8_t>(digest, digest + len);
}

std::string DragSecurityManager::SerializeDragEventData(const DragSecurityData& data)
{
    std::ostringstream oss;
    oss.precision(SECURITY_DATA_LEN);
    oss << data.timestampMs << '|' << data.coordinateX << '|' << data.coordinateY;
    return oss.str();
}

std::string DragSecurityManager::Base64Encode(const uint8_t* data, size_t len)
{
    if (!data || (len == 0)) {
        MMI_HILOGE("data or len error");
        return "";
    }
    // CHECK Base64encode formula for calculating length
    if (len > (SIZE_MAX - 2) / 4 * 3) {
        MMI_HILOGE("Len too large");
        return "";
    }
    // Base64encode formula for calculating length
    size_t outLen = 4 * ((len + 2) / 3);
    std::vector<unsigned char> outBuf(outLen + 1);
    int encodedLen = EVP_EncodeBlock(outBuf.data(), data, static_cast<int>(len));
    if (encodedLen <= 0) {
        MMI_HILOGE("Base64Encode error");
        return "";
    }
    return std::string(reinterpret_cast<char*>(outBuf.data()), encodedLen);
}
 
std::string DragSecurityManager::Base64Encode(const std::vector<uint8_t>& vec)
{
    return Base64Encode(vec.data(), vec.size());
}
 
std::vector<uint8_t> DragSecurityManager::Base64Decode(const std::string& b64)
{
    if (b64.empty() || (b64.length() > MAX_BASE64_LENGTH)) {
        MMI_HILOGE("B64 is empty or too long");
        return {};
    }
    
    BIO* b64Bio = BIO_new(BIO_f_base64());
    if (!b64Bio) {
        MMI_HILOGE("Failed to create base64 BIO");
        return {};
    }
    
    BIO* memBio = BIO_new_mem_buf(b64.data(), static_cast<int>(b64.size()));
    if (!memBio) {
        BIO_free(b64Bio);
        MMI_HILOGE("Failed to create memory BIO");
        return {};
    }
    BIO_push(b64Bio, memBio);
    BIO_set_flags(b64Bio, BIO_FLAGS_BASE64_NO_NL);
 
    std::vector<uint8_t> result;
    uint8_t buf[256];
    int bytesRead = 0;
 
    while ((bytesRead = BIO_read(b64Bio, buf, sizeof(buf))) > 0) {
        result.insert(result.end(), buf, buf + bytesRead);
    }
 
    BIO_free_all(b64Bio);
    return result;
}
#endif // OHOS_BUILD_ENABLE_DRAG_SECURITY
} // namespace MMI
} // namespace OHOS