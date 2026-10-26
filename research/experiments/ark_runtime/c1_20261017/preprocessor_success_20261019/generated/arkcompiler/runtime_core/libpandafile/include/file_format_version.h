/**
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef LIBPANDAFILE_FILE_FORMAT_VERSION_H
#define LIBPANDAFILE_FILE_FORMAT_VERSION_H

#include <array>
#include <string>
#include <sstream>
#include <iomanip>
#include <set>

#include "file.h"
#include "utils/const_value.h"

namespace panda::panda_file {
constexpr uint8_t API_12 = 12;
const std::string SUB_API_VERSION_1 = "beta1";
const std::string SUB_API_VERSION_2 = "beta2";
const std::string DEFAULT_SUB_API_VERSION = SUB_API_VERSION_1;

constexpr std::array<uint8_t, File::VERSION_SIZE> version {24, 0, 0, 0};
constexpr std::array<uint8_t, File::VERSION_SIZE> minVersion {0, 0, 0, 2};
const std::set<std::array<uint8_t, File::VERSION_SIZE>> incompatibleVersion {
    {11, 0, 0, 0},
    {11, 0, 1, 0},
};

std::string GetVersion(const std::array<uint8_t, File::VERSION_SIZE> &version);

PANDA_PUBLIC_API bool IsVersionLessOrEqual(const std::array<uint8_t, File::VERSION_SIZE> &currrent_version,
                                           const std::array<uint8_t, File::VERSION_SIZE> &target_version);

inline void PrintBytecodeVersion()
{
    std::stringstream ss;

    ss << "Bytecode version " << GetVersion(version) << '\n';
    ss << "Minimum supported bytecode version " << GetVersion(minVersion) << '\n';

    std::cout << ss.str() << std::endl;
}

const std::map<uint8_t, std::array<uint8_t, File::VERSION_SIZE>> api_version_map {
    {0, {24, 0, 0, 0}},
    {0, {24, 0, 0, 0}},
    {9, {9, 0, 0, 0}},
    {10, {9, 0, 0, 0}},
    {11, {11, 0, 2, 0}},
    {12, {12, 0, 6, 0}},
    {13, {12, 0, 6, 0}},
    {14, {12, 0, 6, 0}},
    {15, {12, 0, 6, 0}},
    {16, {12, 0, 6, 0}},
    {17, {12, 0, 6, 0}},
    {18, {13, 0, 1, 0}},
    {19, {13, 0, 1, 0}},
    {20, {13, 0, 1, 0}},
    {21, {13, 0, 1, 0}},
    {22, {13, 0, 1, 0}},
    {23, {13, 0, 1, 0}},
    {24, {24, 0, 0, 0}},
    {24, {24, 0, 0, 0}}
};

inline void PrintSupportedApi() {
    static constexpr size_t WIDTH = 20;  // set output width
    std::cout << "Supported apis and corresponding file versions:" << std::endl;
    std::cout << std::setw(WIDTH) << "api" << std::setw(WIDTH) << "file version" << std::endl;
    for (const auto &[legal_api, file_version] : api_version_map) {
        if (legal_api == 0) {
            continue;
        } else {
            std::cout << std::setw(WIDTH) << static_cast<uint32_t>(legal_api);
        }
        std::cout << std::setw(WIDTH) << GetVersion(file_version) << std::endl;
    }
}

inline std::optional<const std::array<uint8_t, File::VERSION_SIZE>> GetVersionByApi(uint8_t api, std::string subApi)
{
    if (api == API_12 && (subApi == SUB_API_VERSION_1 || subApi == SUB_API_VERSION_2)) {
        return std::array<uint8_t, File::VERSION_SIZE> {12, 0, 2, 0};
    }

    const auto iter = api_version_map.find(api);
    if (iter == api_version_map.end()) {
        // if there is no corresponding api version, the default branch is current version.
        return version;
    }
    return iter->second;
}

}  // namespace panda::panda_file

#endif
