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

#ifndef INPUT_TABLE_DUMP_H
#define INPUT_TABLE_DUMP_H

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

namespace OHOS {
namespace MMI {
constexpr size_t EXTRA_CHARACTERS_COUNT { 3 };
constexpr int32_t ELEMENT_SPACE_COUNT { 2 };

inline size_t GetElementLength(const std::string &element)
{
    return element.size();
}

inline std::vector<size_t> CalculateColumnWidths(const std::vector<std::string> &titles,
                                                 const std::vector<std::vector<std::string>> &rows,
                                                 size_t &lineWidth)
{
    std::vector<size_t> widths(titles.size(), 0);
    for (size_t i = 0; i < titles.size(); ++i) {
        widths[i] = std::max(widths[i], GetElementLength(titles[i]));
    }

    for (const auto &row : rows) {
        for (size_t i = 0; i < row.size(); ++i) {
            widths[i] = std::max(widths[i], GetElementLength(row[i]));
        }
    }

    for (size_t width : widths) {
        lineWidth += width + EXTRA_CHARACTERS_COUNT;
    }
    lineWidth += 1;
    return widths;
}

inline void PrintLine(std::ostream &os, const std::vector<size_t> &widths)
{
    os << "+";
    for (size_t width : widths) {
        os << std::setw(static_cast<int32_t>(width) + ELEMENT_SPACE_COUNT) << std::left << std::setfill('-')
           << "" << "+";
    }
    os << std::setfill(' ') << std::endl;
}

inline void PrintCentered(std::ostream &os, const std::string &value, size_t width)
{
    size_t padding_left = (width - value.size()) / 2;
    size_t padding_right = width - value.size() - padding_left;
    os << std::string(padding_left, ' ') << value << std::string(padding_right, ' ');
}

inline void PrintHeader(std::ostream &os, const std::vector<size_t> &widths, const std::vector<std::string> &titles)
{
    os << "|";
    for (size_t i = 0; i < titles.size(); ++i) {
        os << " ";
        PrintCentered(os, titles[i], widths[i]);
        os << " |";
    }
    os << std::endl;
}

inline void PrintRow(std::ostream &os, const std::vector<size_t> &widths, const std::vector<std::string> &row)
{
    os << "|";
    for (size_t i = 0; i < row.size(); ++i) {
        os << " ";
        PrintCentered(os, row[i], widths[i]);
        os << " |";
    }
    os << std::endl;
}

inline void DumpFullTable(std::ostream &os, const std::string &tableName,
                          const std::vector<std::string> &titles,
                          const std::vector<std::vector<std::string>> &rows)
{
    size_t lineWidth = 0;
    std::vector<size_t> widths = CalculateColumnWidths(titles, rows, lineWidth);

    PrintCentered(os, tableName, lineWidth);
    os << std::endl;

    PrintLine(os, widths);
    PrintHeader(os, widths, titles);
    PrintLine(os, widths);

    for (const auto &row : rows) {
        PrintRow(os, widths, row);
        PrintLine(os, widths);
    }
}
} // namespace MMI
} // namespace OHOS
#endif //INPUT_TABLE_DUMP_H
