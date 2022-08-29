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

void StreamBuffer::Reset()
{
    rPos_ = 0;
    wPos_ = 0;
    rCount_ = 0;
    wCount_ = 0;
    rwErrorStatus_ = ErrorStatus::ERROR_STATUS_OK;
}

void StreamBuffer::Clean()
{
    Reset();
    errno_t ret = memset_sp(&szBuff_, sizeof(szBuff_), 0, sizeof(szBuff_));
    if (ret != EOK) {
        MMI_HILOGE("Call memset_s fail");
        return;
    }
}

bool StreamBuffer::SeekReadPos(int32_t n)
{
    int32_t pos = rPos_ + n;
    if (pos < 0 || pos > wPos_) {
        MMI_HILOGE("The position in the calculation is not as expected. pos:%{public}d [0, %{public}d]",
            pos, wPos_);
        return false;
    }
    rPos_ = pos;
    return true;
}

bool StreamBuffer::Read(std::string &buf)
{
    if (rPos_ == wPos_) {
        MMI_HILOGE("Not enough memory to read, errCode:%{public}d", MEM_NOT_ENOUGH);
        rwErrorStatus_ = ErrorStatus::ERROR_STATUS_READ;
        return false;
    }
    buf = ReadBuf();
    rPos_ += static_cast<int32_t>(buf.length()) + 1;
    return (buf.length() > 0);
}

bool StreamBuffer::Write(const std::string &buf)
{
    return Write(buf.c_str(), buf.length()+1);
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
        MMI_HILOGE("Invalid input parameter buf=nullptr errCode:%{public}d", ERROR_NULL_POINTER);
        rwErrorStatus_ = ErrorStatus::ERROR_STATUS_READ;
        return false;
    }
    if (size == 0) {
        MMI_HILOGE("Invalid input parameter size=%{public}zu errCode:%{public}d", size, PARAM_INPUT_INVALID);
        rwErrorStatus_ = ErrorStatus::ERROR_STATUS_READ;
        return false;
    }
    if (rPos_ + static_cast<int32_t>(size) > wPos_) {
        MMI_HILOGE("Memory out of bounds on read... errCode:%{public}d", MEM_OUT_OF_BOUNDS);
        rwErrorStatus_ = ErrorStatus::ERROR_STATUS_READ;
        return false;
    }
    errno_t ret = memcpy_sp(buf, size, ReadBuf(), size);
    if (ret != EOK) {
        MMI_HILOGE("Failed to call memcpy_sp. errCode:%{public}d", MEMCPY_SEC_FUN_FAIL);
        rwErrorStatus_ = ErrorStatus::ERROR_STATUS_READ;
        return false;
    }
    rPos_ += static_cast<int32_t>(size);
    rCount_ += 1;
    return true;
}

bool StreamBuffer::Write(const char *buf, size_t size)
{
    if (ChkRWError()) {
        return false;
    }
    if (buf == nullptr) {
        MMI_HILOGE("Invalid input parameter buf=nullptr errCode:%{public}d", ERROR_NULL_POINTER);
        rwErrorStatus_ = ErrorStatus::ERROR_STATUS_WRITE;
        return false;
    }
    if (size == 0) {
        MMI_HILOGE("Invalid input parameter size=%{public}zu errCode:%{public}d", size, PARAM_INPUT_INVALID);
        rwErrorStatus_ = ErrorStatus::ERROR_STATUS_WRITE;
        return false;
    }
    if (wPos_ + static_cast<int32_t>(size) > MAX_STREAM_BUF_SIZE) {
        MMI_HILOGE("The write length exceeds buffer. wIdx:%{public}d size:%{public}zu maxBufSize:%{public}d "
            "errCode:%{public}d", wPos_, size, MAX_STREAM_BUF_SIZE, MEM_OUT_OF_BOUNDS);
        rwErrorStatus_ = ErrorStatus::ERROR_STATUS_WRITE;
        return false;
    }
    errno_t ret = memcpy_sp(&szBuff_[wPos_], GetAvailableBufSize(), buf, size);
    if (ret != EOK) {
        MMI_HILOGE("Failed to call memcpy_sp. errCode:%{public}d", MEMCPY_SEC_FUN_FAIL);
        rwErrorStatus_ = ErrorStatus::ERROR_STATUS_WRITE;
        return false;
    }
    wPos_ += static_cast<int32_t>(size);
    wCount_ += 1;
    return true;
}

bool StreamBuffer::IsEmpty() const
{
    return (rPos_ == wPos_);
}

size_t StreamBuffer::Size() const
{
    return static_cast<size_t>(wPos_);
}

int32_t StreamBuffer::UnreadSize() const
{
    return ((wPos_ <= rPos_) ? 0 : (wPos_ - rPos_));
}

int32_t StreamBuffer::GetAvailableBufSize() const
{
    return ((wPos_ >= MAX_STREAM_BUF_SIZE) ? 0 : (MAX_STREAM_BUF_SIZE - wPos_));
}

bool StreamBuffer::ChkRWError() const
{
    return (rwErrorStatus_ != ErrorStatus::ERROR_STATUS_OK);
}

const std::string &StreamBuffer::GetErrorStatusRemark() const
{
    static const std::vector<std::pair<ErrorStatus, std::string>> remark {
        {ErrorStatus::ERROR_STATUS_OK, "OK"},
        {ErrorStatus::ERROR_STATUS_READ, "READ_ERROR"},
        {ErrorStatus::ERROR_STATUS_WRITE, "WRITE_ERROR"},
    };
    for (const auto &it : remark) {
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
    return &szBuff_[rPos_];
}

const char *StreamBuffer::WriteBuf() const
{
    return &szBuff_[wPos_];
}

bool StreamBuffer::Clone(const StreamBuffer &buf)
{
    Clean();
    return Write(buf.Data(), buf.Size());
}
} // namespace MMI
} // namespace OHOS
