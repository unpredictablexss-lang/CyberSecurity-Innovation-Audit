/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef LIBPANDAFILE_SOURCE_LANG_ENUM_H
#define LIBPANDAFILE_SOURCE_LANG_ENUM_H

namespace panda::panda_file {

enum class SourceLang : uint8_t {
    ECMASCRIPT = 0,
    PANDA_ASSEMBLY = 1,
    JAVASCRIPT = 2,
    TYPESCRIPT = 3,
    ARKTS = 4
};

constexpr SourceLang DEFUALT_SOURCE_LANG = SourceLang::ECMASCRIPT;

constexpr uint8_t LANG_COUNT = 1;

constexpr std::array<SourceLang, panda::panda_file::LANG_COUNT> LANG_ITERATOR = {
    panda::panda_file::SourceLang::PANDA_ASSEMBLY
};

static constexpr size_t GetLangArrIndex(panda_file::SourceLang lang)
{
    for (size_t index = 0; index < panda::panda_file::LANG_ITERATOR.size(); ++index) {
        if (panda::panda_file::LANG_ITERATOR[index] == lang) {
            return index;
        }
    }

    UNREACHABLE();
    return 0;
}

inline std::ostream &operator<<(std::ostream &stream, SourceLang lang)
{
    switch (lang) {
        case panda::panda_file::SourceLang::ECMASCRIPT:
            stream << "ECMAScript";
            break;
        case panda::panda_file::SourceLang::PANDA_ASSEMBLY:
            stream << "Panda Assembly";
            break;
        case panda::panda_file::SourceLang::JAVASCRIPT:
            stream << "JavaScript";
            break;
        case panda::panda_file::SourceLang::TYPESCRIPT:
            stream << "TypeScript";
            break;
        case panda::panda_file::SourceLang::ARKTS:
            stream << "ArkTS";
            break;
        default:
            UNREACHABLE();
    }
    return stream;
}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define LANG_ENUM_LIST   \
    panda::panda_file::SourceLang::PANDA_ASSEMBLY

}  // namespace panda::panda_file

#endif  // LIBPANDAFILE_SOURCE_LANG_ENUM_H
