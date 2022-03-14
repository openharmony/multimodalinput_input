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

#include "stream_buffer.h"

#include <vector>

#include "define_multimodal.h"

namespace OHOS {
namespace MMI {
StreamBuffer::StreamBuffer(const StreamBuffer &buf)
{
    Clone(buf);
}

StreamBuffer &StreamBuffer::operator=(const StreamBuffer &other)
{
    Clone(other);
    return *this;
}

void StreamBuffer::Clean()
{
    rIdx_ = 0;
    wIdx_ = 0;
    rCount_ = 0;
    wCount_ = 0;
    rwErrorStatus_ = ErrorStatus::ERROR_STATUS_OK;
    errno_t ret = memset_sp(&szBuff_, sizeof(szBuff_), 0, sizeof(szBuff_));
    if (ret != EOK) {
        MMI_LOGE("call memset_s fail");
        return;
    }
}

bool StreamBuffer::SetReadIdx(int32_t idx)
{
    if (idx > wIdx_) {
        MMI_LOGE("Invalid parameter input");
        return false;
    }
    rIdx_ = idx;
    return true;
}

bool StreamBuffer::Read(std::string &buf)
{
    if (rIdx_ == wIdx_) {
        MMI_LOGE("Not enough memory to read, errCode:%{public}d", MEM_NOT_ENOUGH);
        rwErrorStatus_ = ErrorStatus::ERROR_STATUS_READ;
        return false;
    }
    buf = ReadBuf();
    rIdx_ += static_cast<int32_t>(buf.size()) + 1;
    return (buf.size() > 0);
}

bool StreamBuffer::Write(const std::string &buf)
{
    return Write(buf.c_str(), buf.size() + 1);
}

bool StreamBuffer::Read(StreamBuffer &buf)
{
    return buf.Write(Data(), Size());
}

bool StreamBuffer::Write(const StreamBuffer &buf)
{
    return Write(buf.Data(), buf.Size());
}

bool StreamBuffer::Read(char *buf, size_t size)
{
    if (ChkRWError()) {
        return false;
    }
    if (buf == nullptr) {
        MMI_LOGE("Invalid input parameter buf=nullptr errCode:%{public}d", ERROR_NULL_POINTER);
        rwErrorStatus_ = ErrorStatus::ERROR_STATUS_READ;
        return false;
    }
    if (size == 0) {
        MMI_LOGE("Invalid input parameter size=%{public}zu errCode:%{public}d", size, PARAM_INPUT_INVALID);
        rwErrorStatus_ = ErrorStatus::ERROR_STATUS_READ;
        return false;
    }
    if (rIdx_ + static_cast<int32_t>(size) > wIdx_) {
        MMI_LOGE("Memory out of bounds on read... errCode:%{public}d", MEM_OUT_OF_BOUNDS);
        rwErrorStatus_ = ErrorStatus::ERROR_STATUS_READ;
        return false;
    }
    errno_t ret = memcpy_sp(buf, size, ReadBuf(), size);
    if (ret != EOK) {
        MMI_LOGE("memcpy_sp call fail. errCode:%{public}d", MEMCPY_SEC_FUN_FAIL);
        rwErrorStatus_ = ErrorStatus::ERROR_STATUS_READ;
        return false;
    }
    rIdx_ += static_cast<int32_t>(size);
    rCount_ += 1;
    return true;
}

bool StreamBuffer::Write(const char *buf, size_t size)
{
    if (ChkRWError()) {
        return false;
    }
    if (buf == nullptr) {
        MMI_LOGE("Invalid input parameter buf=nullptr errCode:%{public}d", ERROR_NULL_POINTER);
        rwErrorStatus_ = ErrorStatus::ERROR_STATUS_WRITE;
        return false;
    }
    if (size == 0) {
        MMI_LOGE("Invalid input parameter size=%{public}zu errCode:%{public}d", size, PARAM_INPUT_INVALID);
        rwErrorStatus_ = ErrorStatus::ERROR_STATUS_WRITE;
        return false;
    }
    if (wIdx_ + static_cast<int32_t>(size) >= MAX_STREAM_BUF_SIZE) {
        MMI_LOGE("The write length exceeds buffer. errCode:%{public}d", MEM_OUT_OF_BOUNDS);
        rwErrorStatus_ = ErrorStatus::ERROR_STATUS_WRITE;
        return false;
    }
    errno_t ret = memcpy_sp(&szBuff_[wIdx_], static_cast<size_t>(MAX_STREAM_BUF_SIZE - wIdx_), buf, size);
    if (ret != EOK) {
        MMI_LOGE("memcpy_sp call fail. errCode:%{public}d", MEMCPY_SEC_FUN_FAIL);
        rwErrorStatus_ = ErrorStatus::ERROR_STATUS_WRITE;
        return false;
    }
    wIdx_ += static_cast<int32_t>(size);
    wCount_ += 1;
    return true;
}

bool StreamBuffer::IsEmpty()
{
    if ((rIdx_ == wIdx_) && (wIdx_ == 0)) {
        return true;
    }
    return false;
}

size_t StreamBuffer::Size() const
{
    return static_cast<size_t>(wIdx_);
}

size_t StreamBuffer::UnreadSize() const
{
    if (wIdx_ < rIdx_) {
        MMI_LOGW("Widx_ less than ridx_, wIdx_:%{public}d,rIdx_:%{public}d", wIdx_, rIdx_);
        return 0;
    }
    return static_cast<size_t>(wIdx_ - rIdx_);
}

bool StreamBuffer::ChkRWError() const
{
    return (rwErrorStatus_ != ErrorStatus::ERROR_STATUS_OK);
}

const std::string& StreamBuffer::GetErrorStatusRemark() const
{
    static const std::vector<std::pair<ErrorStatus, std::string>> remark {
        {ErrorStatus::ERROR_STATUS_OK, "OK"},
        {ErrorStatus::ERROR_STATUS_READ, "READ_ERROR"},
        {ErrorStatus::ERROR_STATUS_WRITE, "WRITE_ERROR"},
    };
    for (const auto& it : remark) {
        if (it.first == rwErrorStatus_) {
            return it.second;
        }
    }
    static const std::string invalidStatus = "UNKNOWN";
    return invalidStatus;
}

const char *StreamBuffer::Data() const
{
    return &szBuff_[0];
}

const char *StreamBuffer::ReadBuf() const
{
    return &szBuff_[rIdx_];
}

const char *StreamBuffer::WriteBuf() const
{
    return &szBuff_[wIdx_];
}

bool StreamBuffer::Clone(const StreamBuffer &buf)
{
    Clean();
    return Write(buf.Data(), buf.Size());
}
} // namespace MMI
} // namespace OHOS
