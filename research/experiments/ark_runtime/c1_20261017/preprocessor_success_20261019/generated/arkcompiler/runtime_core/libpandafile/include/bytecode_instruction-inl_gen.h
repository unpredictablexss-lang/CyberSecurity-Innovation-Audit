/*
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

/* static */
template<const BytecodeInstMode Mode>
constexpr bool BytecodeInst<Mode>::HasId(Format format, size_t idx) {
    switch (format) {
    case Format::ID16:
        return idx < 1;
    case Format::IMM16_ID16:
        return idx < 1;
    case Format::IMM16_ID16_ID16_IMM16_V8:
        return idx < 2;
    case Format::IMM16_ID16_IMM8:
        return idx < 1;
    case Format::IMM16_ID16_V8:
        return idx < 1;
    case Format::IMM8_ID16:
        return idx < 1;
    case Format::IMM8_ID16_ID16_IMM16_V8:
        return idx < 2;
    case Format::IMM8_ID16_IMM8:
        return idx < 1;
    case Format::IMM8_ID16_V8:
        return idx < 1;
    case Format::IMM8_ID16_V8_V8:
        return idx < 1;
    case Format::IMM8_ID16_V8_V8_V8:
        return idx < 1;
    case Format::IMM8_ID16_V8_V8_V8_V8:
        return idx < 1;
    case Format::IMM8_IMM8_ID16_V8:
        return idx < 1;
    case Format::PREF_ID16:
        return idx < 1;
    case Format::PREF_ID16_IMM16_IMM16_V8_V8:
        return idx < 1;
    case Format::PREF_ID32:
        return idx < 1;
    case Format::PREF_ID32_IMM8:
        return idx < 1;
    case Format::PREF_ID32_V8:
        return idx < 1;
    case Format::PREF_IMM16_ID16:
        return idx < 1;
    case Format::PREF_IMM16_ID16_ID16_IMM16_V8:
        return idx < 2;
    case Format::PREF_IMM16_ID16_V8:
        return idx < 1;
    default: {
        return false;
    }
    }

    UNREACHABLE_CONSTEXPR();
}

/* static */
template<const BytecodeInstMode Mode>
constexpr bool BytecodeInst<Mode>::HasVReg(Format format, size_t idx) {
    switch (format) {
    case Format::IMM16_ID16_ID16_IMM16_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::IMM16_ID16_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::IMM16_IMM8_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::IMM16_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::IMM16_V8_IMM16:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::IMM16_V8_V8:
        return idx < 2;  // NOLINT(readability-magic-numbers)
    case Format::IMM8_ID16_ID16_IMM16_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::IMM8_ID16_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::IMM8_ID16_V8_V8:
        return idx < 2;  // NOLINT(readability-magic-numbers)
    case Format::IMM8_ID16_V8_V8_V8:
        return idx < 3;  // NOLINT(readability-magic-numbers)
    case Format::IMM8_ID16_V8_V8_V8_V8:
        return idx < 4;  // NOLINT(readability-magic-numbers)
    case Format::IMM8_IMM16_IMM16_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::IMM8_IMM8_ID16_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::IMM8_IMM8_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::IMM8_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::IMM8_V8_IMM16:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::IMM8_V8_V8:
        return idx < 2;  // NOLINT(readability-magic-numbers)
    case Format::IMM8_V8_V8_V8:
        return idx < 3;  // NOLINT(readability-magic-numbers)
    case Format::IMM8_V8_V8_V8_V8:
        return idx < 4;  // NOLINT(readability-magic-numbers)
    case Format::PREF_ID16_IMM16_IMM16_V8_V8:
        return idx < 2;  // NOLINT(readability-magic-numbers)
    case Format::PREF_ID32_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::PREF_IMM16_ID16_ID16_IMM16_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::PREF_IMM16_ID16_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::PREF_IMM16_IMM16_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::PREF_IMM16_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::PREF_IMM16_V8_V8:
        return idx < 2;  // NOLINT(readability-magic-numbers)
    case Format::PREF_IMM4_IMM4_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::PREF_IMM8_IMM16_IMM16_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::PREF_IMM8_IMM32_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::PREF_IMM8_IMM8_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::PREF_IMM8_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::PREF_IMM8_V8_V8:
        return idx < 2;  // NOLINT(readability-magic-numbers)
    case Format::PREF_V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::PREF_V8_IMM32:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::PREF_V8_V8:
        return idx < 2;  // NOLINT(readability-magic-numbers)
    case Format::PREF_V8_V8_V8:
        return idx < 3;  // NOLINT(readability-magic-numbers)
    case Format::PREF_V8_V8_V8_V8:
        return idx < 4;  // NOLINT(readability-magic-numbers)
    case Format::V16_V16:
        return idx < 2;  // NOLINT(readability-magic-numbers)
    case Format::V4_V4:
        return idx < 2;  // NOLINT(readability-magic-numbers)
    case Format::V8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::V8_IMM16:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::V8_IMM8:
        return idx < 1;  // NOLINT(readability-magic-numbers)
    case Format::V8_V8:
        return idx < 2;  // NOLINT(readability-magic-numbers)
    case Format::V8_V8_V8:
        return idx < 3;  // NOLINT(readability-magic-numbers)
    case Format::V8_V8_V8_V8:
        return idx < 4;  // NOLINT(readability-magic-numbers)
    default: {
        return false;
    }
    }

    UNREACHABLE_CONSTEXPR();
}

/* static */
template<const BytecodeInstMode Mode>
constexpr bool BytecodeInst<Mode>::HasImm(Format format, size_t idx) {
    switch (format) {
    case Format::IMM16:
        return idx < 1;
    case Format::IMM16_ID16:
        return idx < 1;
    case Format::IMM16_ID16_ID16_IMM16_V8:
        return idx < 2;
    case Format::IMM16_ID16_IMM8:
        return idx < 2;
    case Format::IMM16_ID16_V8:
        return idx < 1;
    case Format::IMM16_IMM16:
        return idx < 2;
    case Format::IMM16_IMM8_V8:
        return idx < 2;
    case Format::IMM16_V8:
        return idx < 1;
    case Format::IMM16_V8_IMM16:
        return idx < 2;
    case Format::IMM16_V8_V8:
        return idx < 1;
    case Format::IMM32:
        return idx < 1;
    case Format::IMM4_IMM4:
        return idx < 2;
    case Format::IMM64:
        return idx < 1;
    case Format::IMM8:
        return idx < 1;
    case Format::IMM8_ID16:
        return idx < 1;
    case Format::IMM8_ID16_ID16_IMM16_V8:
        return idx < 2;
    case Format::IMM8_ID16_IMM8:
        return idx < 2;
    case Format::IMM8_ID16_V8:
        return idx < 1;
    case Format::IMM8_ID16_V8_V8:
        return idx < 1;
    case Format::IMM8_ID16_V8_V8_V8:
        return idx < 1;
    case Format::IMM8_ID16_V8_V8_V8_V8:
        return idx < 1;
    case Format::IMM8_IMM16:
        return idx < 2;
    case Format::IMM8_IMM16_IMM16:
        return idx < 3;
    case Format::IMM8_IMM16_IMM16_V8:
        return idx < 3;
    case Format::IMM8_IMM8:
        return idx < 2;
    case Format::IMM8_IMM8_ID16_V8:
        return idx < 2;
    case Format::IMM8_IMM8_V8:
        return idx < 2;
    case Format::IMM8_V8:
        return idx < 1;
    case Format::IMM8_V8_IMM16:
        return idx < 2;
    case Format::IMM8_V8_V8:
        return idx < 1;
    case Format::IMM8_V8_V8_V8:
        return idx < 1;
    case Format::IMM8_V8_V8_V8_V8:
        return idx < 1;
    case Format::PREF_ID16_IMM16_IMM16_V8_V8:
        return idx < 2;
    case Format::PREF_ID32_IMM8:
        return idx < 1;
    case Format::PREF_IMM16:
        return idx < 1;
    case Format::PREF_IMM16_ID16:
        return idx < 1;
    case Format::PREF_IMM16_ID16_ID16_IMM16_V8:
        return idx < 2;
    case Format::PREF_IMM16_ID16_V8:
        return idx < 1;
    case Format::PREF_IMM16_IMM16:
        return idx < 2;
    case Format::PREF_IMM16_IMM16_V8:
        return idx < 2;
    case Format::PREF_IMM16_V8:
        return idx < 1;
    case Format::PREF_IMM16_V8_V8:
        return idx < 1;
    case Format::PREF_IMM32:
        return idx < 1;
    case Format::PREF_IMM4_IMM4:
        return idx < 2;
    case Format::PREF_IMM4_IMM4_V8:
        return idx < 2;
    case Format::PREF_IMM8:
        return idx < 1;
    case Format::PREF_IMM8_IMM16_IMM16_V8:
        return idx < 3;
    case Format::PREF_IMM8_IMM32_V8:
        return idx < 2;
    case Format::PREF_IMM8_IMM8:
        return idx < 2;
    case Format::PREF_IMM8_IMM8_V8:
        return idx < 2;
    case Format::PREF_IMM8_V8:
        return idx < 1;
    case Format::PREF_IMM8_V8_V8:
        return idx < 1;
    case Format::PREF_V8_IMM32:
        return idx < 1;
    case Format::V8_IMM16:
        return idx < 1;
    case Format::V8_IMM8:
        return idx < 1;
    default: {
        return false;
    }
    }

    UNREACHABLE_CONSTEXPR();
}

/* static */
template<const BytecodeInstMode Mode>
constexpr size_t BytecodeInst<Mode>::Size(Format format) {  // NOLINTNEXTLINE(readability-function-size)
    switch (format) {
    case Format::ID16: {
        constexpr size_t SIZE = 3;
        return SIZE;
    }
    case Format::IMM16: {
        constexpr size_t SIZE = 3;
        return SIZE;
    }
    case Format::IMM16_ID16: {
        constexpr size_t SIZE = 5;
        return SIZE;
    }
    case Format::IMM16_ID16_ID16_IMM16_V8: {
        constexpr size_t SIZE = 10;
        return SIZE;
    }
    case Format::IMM16_ID16_IMM8: {
        constexpr size_t SIZE = 6;
        return SIZE;
    }
    case Format::IMM16_ID16_V8: {
        constexpr size_t SIZE = 6;
        return SIZE;
    }
    case Format::IMM16_IMM16: {
        constexpr size_t SIZE = 5;
        return SIZE;
    }
    case Format::IMM16_IMM8_V8: {
        constexpr size_t SIZE = 5;
        return SIZE;
    }
    case Format::IMM16_V8: {
        constexpr size_t SIZE = 4;
        return SIZE;
    }
    case Format::IMM16_V8_IMM16: {
        constexpr size_t SIZE = 6;
        return SIZE;
    }
    case Format::IMM16_V8_V8: {
        constexpr size_t SIZE = 5;
        return SIZE;
    }
    case Format::IMM32: {
        constexpr size_t SIZE = 5;
        return SIZE;
    }
    case Format::IMM4_IMM4: {
        constexpr size_t SIZE = 2;
        return SIZE;
    }
    case Format::IMM64: {
        constexpr size_t SIZE = 9;
        return SIZE;
    }
    case Format::IMM8: {
        constexpr size_t SIZE = 2;
        return SIZE;
    }
    case Format::IMM8_ID16: {
        constexpr size_t SIZE = 4;
        return SIZE;
    }
    case Format::IMM8_ID16_ID16_IMM16_V8: {
        constexpr size_t SIZE = 9;
        return SIZE;
    }
    case Format::IMM8_ID16_IMM8: {
        constexpr size_t SIZE = 5;
        return SIZE;
    }
    case Format::IMM8_ID16_V8: {
        constexpr size_t SIZE = 5;
        return SIZE;
    }
    case Format::IMM8_ID16_V8_V8: {
        constexpr size_t SIZE = 6;
        return SIZE;
    }
    case Format::IMM8_ID16_V8_V8_V8: {
        constexpr size_t SIZE = 7;
        return SIZE;
    }
    case Format::IMM8_ID16_V8_V8_V8_V8: {
        constexpr size_t SIZE = 8;
        return SIZE;
    }
    case Format::IMM8_IMM16: {
        constexpr size_t SIZE = 4;
        return SIZE;
    }
    case Format::IMM8_IMM16_IMM16: {
        constexpr size_t SIZE = 6;
        return SIZE;
    }
    case Format::IMM8_IMM16_IMM16_V8: {
        constexpr size_t SIZE = 7;
        return SIZE;
    }
    case Format::IMM8_IMM8: {
        constexpr size_t SIZE = 3;
        return SIZE;
    }
    case Format::IMM8_IMM8_ID16_V8: {
        constexpr size_t SIZE = 6;
        return SIZE;
    }
    case Format::IMM8_IMM8_V8: {
        constexpr size_t SIZE = 4;
        return SIZE;
    }
    case Format::IMM8_V8: {
        constexpr size_t SIZE = 3;
        return SIZE;
    }
    case Format::IMM8_V8_IMM16: {
        constexpr size_t SIZE = 5;
        return SIZE;
    }
    case Format::IMM8_V8_V8: {
        constexpr size_t SIZE = 4;
        return SIZE;
    }
    case Format::IMM8_V8_V8_V8: {
        constexpr size_t SIZE = 5;
        return SIZE;
    }
    case Format::IMM8_V8_V8_V8_V8: {
        constexpr size_t SIZE = 6;
        return SIZE;
    }
    case Format::NONE: {
        constexpr size_t SIZE = 1;
        return SIZE;
    }
    case Format::PREF_ID16: {
        constexpr size_t SIZE = 4;
        return SIZE;
    }
    case Format::PREF_ID16_IMM16_IMM16_V8_V8: {
        constexpr size_t SIZE = 10;
        return SIZE;
    }
    case Format::PREF_ID32: {
        constexpr size_t SIZE = 6;
        return SIZE;
    }
    case Format::PREF_ID32_IMM8: {
        constexpr size_t SIZE = 7;
        return SIZE;
    }
    case Format::PREF_ID32_V8: {
        constexpr size_t SIZE = 7;
        return SIZE;
    }
    case Format::PREF_IMM16: {
        constexpr size_t SIZE = 4;
        return SIZE;
    }
    case Format::PREF_IMM16_ID16: {
        constexpr size_t SIZE = 6;
        return SIZE;
    }
    case Format::PREF_IMM16_ID16_ID16_IMM16_V8: {
        constexpr size_t SIZE = 11;
        return SIZE;
    }
    case Format::PREF_IMM16_ID16_V8: {
        constexpr size_t SIZE = 7;
        return SIZE;
    }
    case Format::PREF_IMM16_IMM16: {
        constexpr size_t SIZE = 6;
        return SIZE;
    }
    case Format::PREF_IMM16_IMM16_V8: {
        constexpr size_t SIZE = 7;
        return SIZE;
    }
    case Format::PREF_IMM16_V8: {
        constexpr size_t SIZE = 5;
        return SIZE;
    }
    case Format::PREF_IMM16_V8_V8: {
        constexpr size_t SIZE = 6;
        return SIZE;
    }
    case Format::PREF_IMM32: {
        constexpr size_t SIZE = 6;
        return SIZE;
    }
    case Format::PREF_IMM4_IMM4: {
        constexpr size_t SIZE = 3;
        return SIZE;
    }
    case Format::PREF_IMM4_IMM4_V8: {
        constexpr size_t SIZE = 4;
        return SIZE;
    }
    case Format::PREF_IMM8: {
        constexpr size_t SIZE = 3;
        return SIZE;
    }
    case Format::PREF_IMM8_IMM16_IMM16_V8: {
        constexpr size_t SIZE = 8;
        return SIZE;
    }
    case Format::PREF_IMM8_IMM32_V8: {
        constexpr size_t SIZE = 8;
        return SIZE;
    }
    case Format::PREF_IMM8_IMM8: {
        constexpr size_t SIZE = 4;
        return SIZE;
    }
    case Format::PREF_IMM8_IMM8_V8: {
        constexpr size_t SIZE = 5;
        return SIZE;
    }
    case Format::PREF_IMM8_V8: {
        constexpr size_t SIZE = 4;
        return SIZE;
    }
    case Format::PREF_IMM8_V8_V8: {
        constexpr size_t SIZE = 5;
        return SIZE;
    }
    case Format::PREF_NONE: {
        constexpr size_t SIZE = 2;
        return SIZE;
    }
    case Format::PREF_V8: {
        constexpr size_t SIZE = 3;
        return SIZE;
    }
    case Format::PREF_V8_IMM32: {
        constexpr size_t SIZE = 7;
        return SIZE;
    }
    case Format::PREF_V8_V8: {
        constexpr size_t SIZE = 4;
        return SIZE;
    }
    case Format::PREF_V8_V8_V8: {
        constexpr size_t SIZE = 5;
        return SIZE;
    }
    case Format::PREF_V8_V8_V8_V8: {
        constexpr size_t SIZE = 6;
        return SIZE;
    }
    case Format::V16_V16: {
        constexpr size_t SIZE = 5;
        return SIZE;
    }
    case Format::V4_V4: {
        constexpr size_t SIZE = 2;
        return SIZE;
    }
    case Format::V8: {
        constexpr size_t SIZE = 2;
        return SIZE;
    }
    case Format::V8_IMM16: {
        constexpr size_t SIZE = 4;
        return SIZE;
    }
    case Format::V8_IMM8: {
        constexpr size_t SIZE = 3;
        return SIZE;
    }
    case Format::V8_V8: {
        constexpr size_t SIZE = 3;
        return SIZE;
    }
    case Format::V8_V8_V8: {
        constexpr size_t SIZE = 4;
        return SIZE;
    }
    case Format::V8_V8_V8_V8: {
        constexpr size_t SIZE = 5;
        return SIZE;
    }
    }

    UNREACHABLE_CONSTEXPR();
}

template <const BytecodeInstMode Mode>
template <typename BytecodeInst<Mode>::Format format, size_t idx /* = 0 */>
inline BytecodeId BytecodeInst<Mode>::GetId() const {
    static_assert(HasId(format, idx), "Instruction doesn't have id operand with such index");

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::ID16) {
        return BytecodeId(static_cast<uint32_t>(Read<8, 16>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM16_ID16) {
        return BytecodeId(static_cast<uint32_t>(Read<24, 16>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM16_ID16_ID16_IMM16_V8) {
        constexpr std::array<size_t, 2> OFFSETS{24, 40};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return BytecodeId(static_cast<uint32_t>(Read<OFFSETS[idx], WIDTHS[idx]>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM16_ID16_IMM8) {
        return BytecodeId(static_cast<uint32_t>(Read<24, 16>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM16_ID16_V8) {
        return BytecodeId(static_cast<uint32_t>(Read<24, 16>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM8_ID16) {
        return BytecodeId(static_cast<uint32_t>(Read<16, 16>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM8_ID16_ID16_IMM16_V8) {
        constexpr std::array<size_t, 2> OFFSETS{16, 32};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return BytecodeId(static_cast<uint32_t>(Read<OFFSETS[idx], WIDTHS[idx]>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM8_ID16_IMM8) {
        return BytecodeId(static_cast<uint32_t>(Read<16, 16>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM8_ID16_V8) {
        return BytecodeId(static_cast<uint32_t>(Read<16, 16>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM8_ID16_V8_V8) {
        return BytecodeId(static_cast<uint32_t>(Read<16, 16>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM8_ID16_V8_V8_V8) {
        return BytecodeId(static_cast<uint32_t>(Read<16, 16>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM8_ID16_V8_V8_V8_V8) {
        return BytecodeId(static_cast<uint32_t>(Read<16, 16>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM8_IMM8_ID16_V8) {
        return BytecodeId(static_cast<uint32_t>(Read<24, 16>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::PREF_ID16) {
        return BytecodeId(static_cast<uint32_t>(Read<16, 16>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::PREF_ID16_IMM16_IMM16_V8_V8) {
        return BytecodeId(static_cast<uint32_t>(Read<16, 16>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::PREF_ID32) {
        return BytecodeId(static_cast<uint32_t>(Read<16, 32>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::PREF_ID32_IMM8) {
        return BytecodeId(static_cast<uint32_t>(Read<16, 32>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::PREF_ID32_V8) {
        return BytecodeId(static_cast<uint32_t>(Read<16, 32>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::PREF_IMM16_ID16) {
        return BytecodeId(static_cast<uint32_t>(Read<32, 16>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::PREF_IMM16_ID16_ID16_IMM16_V8) {
        constexpr std::array<size_t, 2> OFFSETS{32, 48};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return BytecodeId(static_cast<uint32_t>(Read<OFFSETS[idx], WIDTHS[idx]>()));
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::PREF_IMM16_ID16_V8) {
        return BytecodeId(static_cast<uint32_t>(Read<32, 16>()));
    }

    UNREACHABLE();
}

template <const BytecodeInstMode Mode>
inline void BytecodeInst<Mode>::UpdateId(BytecodeId new_id, uint32_t idx /* = 0 */) {
    Format format = GetFormat();
    ASSERT_PRINT(HasId(format, idx), "Instruction doesn't have imm operand with such index");

    if (!HasId(format, idx)) {
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::ID16) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{16};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM16_ID16) {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{16};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM16_ID16_ID16_IMM16_V8) {
        constexpr std::array<size_t, 2> OFFSETS{24, 40};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM16_ID16_IMM8) {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{16};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM16_ID16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{16};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM8_ID16) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM8_ID16_ID16_IMM16_V8) {
        constexpr std::array<size_t, 2> OFFSETS{16, 32};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM8_ID16_IMM8) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM8_ID16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM8_ID16_V8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM8_ID16_V8_V8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM8_ID16_V8_V8_V8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::IMM8_IMM8_ID16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{16};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::PREF_ID16) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::PREF_ID16_IMM16_IMM16_V8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::PREF_ID32) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{32};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::PREF_ID32_IMM8) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{32};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::PREF_ID32_V8) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{32};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::PREF_IMM16_ID16) {
        constexpr std::array<size_t, 1> OFFSETS{32};
        constexpr std::array<size_t, 1> WIDTHS{16};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::PREF_IMM16_ID16_ID16_IMM16_V8) {
        constexpr std::array<size_t, 2> OFFSETS{32, 48};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if (format == Format::PREF_IMM16_ID16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{32};
        constexpr std::array<size_t, 1> WIDTHS{16};
        this->Write(new_id.AsRawValue(), OFFSETS[idx] / 8, WIDTHS[idx] / 8);
        return;
    }

    UNREACHABLE();
}

template<const BytecodeInstMode Mode>
inline BytecodeId BytecodeInst<Mode>::GetId(size_t idx /* = 0 */) const {
    Format format = GetFormat();
    ASSERT_PRINT(HasId(format, idx), "Instruction doesn't have id operand with such index");

    if (!HasId(format, idx)) {
        return {};
    }

    switch (format) {
    case Format::ID16: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::IMM16_ID16: {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::IMM16_ID16_ID16_IMM16_V8: {
        constexpr std::array<size_t, 2> OFFSETS{24, 40};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::IMM16_ID16_IMM8: {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::IMM16_ID16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::IMM8_ID16: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::IMM8_ID16_ID16_IMM16_V8: {
        constexpr std::array<size_t, 2> OFFSETS{16, 32};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::IMM8_ID16_IMM8: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::IMM8_ID16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::IMM8_ID16_V8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::IMM8_ID16_V8_V8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::IMM8_ID16_V8_V8_V8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::IMM8_IMM8_ID16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::PREF_ID16: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::PREF_ID16_IMM16_IMM16_V8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::PREF_ID32: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{32};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::PREF_ID32_IMM8: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{32};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::PREF_ID32_V8: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{32};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::PREF_IMM16_ID16: {
        constexpr std::array<size_t, 1> OFFSETS{32};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::PREF_IMM16_ID16_ID16_IMM16_V8: {
        constexpr std::array<size_t, 2> OFFSETS{32, 48};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    case Format::PREF_IMM16_ID16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{32};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return BytecodeId(static_cast<uint32_t>(Read64(OFFSETS[idx], WIDTHS[idx])));
    }
    default: {
        break;
    }
    }

    UNREACHABLE();
}

template <const BytecodeInstMode Mode>
template <typename BytecodeInst<Mode>::Format format, size_t idx /* = 0 */>
__attribute__ ((visibility("hidden")))
ALWAYS_INLINE inline uint16_t BytecodeInst<Mode>::GetVReg() const {  // NOLINTNEXTLINE(readability-function-size)
    static_assert(HasVReg(format, idx), "Instruction doesn't have vreg operand with such index");

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM16_ID16_ID16_IMM16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{72};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM16_ID16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{40};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM16_IMM8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{32};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM16_V8_IMM16) {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM16_V8_V8) {
        constexpr std::array<size_t, 2> OFFSETS{24, 32};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_ID16_ID16_IMM16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{64};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_ID16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{32};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_ID16_V8_V8) {
        constexpr std::array<size_t, 2> OFFSETS{32, 40};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_ID16_V8_V8_V8) {
        constexpr std::array<size_t, 3> OFFSETS{32, 40, 48};
        constexpr std::array<size_t, 3> WIDTHS{8, 8, 8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_ID16_V8_V8_V8_V8) {
        constexpr std::array<size_t, 4> OFFSETS{32, 40, 48, 56};
        constexpr std::array<size_t, 4> WIDTHS{8, 8, 8, 8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_IMM16_IMM16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{48};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_IMM8_ID16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{40};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_IMM8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_V8_IMM16) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_V8_V8) {
        constexpr std::array<size_t, 2> OFFSETS{16, 24};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_V8_V8_V8) {
        constexpr std::array<size_t, 3> OFFSETS{16, 24, 32};
        constexpr std::array<size_t, 3> WIDTHS{8, 8, 8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_V8_V8_V8_V8) {
        constexpr std::array<size_t, 4> OFFSETS{16, 24, 32, 40};
        constexpr std::array<size_t, 4> WIDTHS{8, 8, 8, 8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_ID16_IMM16_IMM16_V8_V8) {
        constexpr std::array<size_t, 2> OFFSETS{64, 72};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_ID32_V8) {
        constexpr std::array<size_t, 1> OFFSETS{48};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM16_ID16_ID16_IMM16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{80};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM16_ID16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{48};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM16_IMM16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{48};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{32};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM16_V8_V8) {
        constexpr std::array<size_t, 2> OFFSETS{32, 40};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM4_IMM4_V8) {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM8_IMM16_IMM16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{56};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM8_IMM32_V8) {
        constexpr std::array<size_t, 1> OFFSETS{56};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM8_IMM8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{32};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM8_V8_V8) {
        constexpr std::array<size_t, 2> OFFSETS{24, 32};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_V8) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_V8_IMM32) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_V8_V8) {
        constexpr std::array<size_t, 2> OFFSETS{16, 24};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_V8_V8_V8) {
        constexpr std::array<size_t, 3> OFFSETS{16, 24, 32};
        constexpr std::array<size_t, 3> WIDTHS{8, 8, 8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_V8_V8_V8_V8) {
        constexpr std::array<size_t, 4> OFFSETS{16, 24, 32, 40};
        constexpr std::array<size_t, 4> WIDTHS{8, 8, 8, 8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::V16_V16) {
        constexpr std::array<size_t, 2> OFFSETS{8, 24};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::V4_V4) {
        constexpr std::array<size_t, 2> OFFSETS{8, 12};
        constexpr std::array<size_t, 2> WIDTHS{4, 4};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::V8) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::V8_IMM16) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::V8_IMM8) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::V8_V8) {
        constexpr std::array<size_t, 2> OFFSETS{8, 16};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::V8_V8_V8) {
        constexpr std::array<size_t, 3> OFFSETS{8, 16, 24};
        constexpr std::array<size_t, 3> WIDTHS{8, 8, 8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::V8_V8_V8_V8) {
        constexpr std::array<size_t, 4> OFFSETS{8, 16, 24, 32};
        constexpr std::array<size_t, 4> WIDTHS{8, 8, 8, 8};
        return static_cast<uint16_t>(Read<OFFSETS[idx], WIDTHS[idx]>());
    }

    UNREACHABLE();
}

template<const BytecodeInstMode Mode>
__attribute__ ((visibility("hidden")))
ALWAYS_INLINE inline uint16_t BytecodeInst<Mode>::GetVReg(size_t idx /* = 0 */) const {  // NOLINTNEXTLINE(readability-function-size)
    Format format = GetFormat();
    ASSERT_PRINT(HasVReg(format, idx), "Instruction doesn't have vreg operand with such index");

    if (!HasVReg(format, idx)) {
        return 0;
    }

    switch (format) {
    case Format::IMM16_ID16_ID16_IMM16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{72};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::IMM16_ID16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{40};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::IMM16_IMM8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{32};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::IMM16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::IMM16_V8_IMM16: {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::IMM16_V8_V8: {
        constexpr std::array<size_t, 2> OFFSETS{24, 32};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        if (idx > 1) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::IMM8_ID16_ID16_IMM16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{64};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::IMM8_ID16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{32};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::IMM8_ID16_V8_V8: {
        constexpr std::array<size_t, 2> OFFSETS{32, 40};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        if (idx > 1) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::IMM8_ID16_V8_V8_V8: {
        constexpr std::array<size_t, 3> OFFSETS{32, 40, 48};
        constexpr std::array<size_t, 3> WIDTHS{8, 8, 8};
        if (idx > 2) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::IMM8_ID16_V8_V8_V8_V8: {
        constexpr std::array<size_t, 4> OFFSETS{32, 40, 48, 56};
        constexpr std::array<size_t, 4> WIDTHS{8, 8, 8, 8};
        if (idx > 3) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::IMM8_IMM16_IMM16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{48};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::IMM8_IMM8_ID16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{40};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::IMM8_IMM8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::IMM8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::IMM8_V8_IMM16: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::IMM8_V8_V8: {
        constexpr std::array<size_t, 2> OFFSETS{16, 24};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        if (idx > 1) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::IMM8_V8_V8_V8: {
        constexpr std::array<size_t, 3> OFFSETS{16, 24, 32};
        constexpr std::array<size_t, 3> WIDTHS{8, 8, 8};
        if (idx > 2) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::IMM8_V8_V8_V8_V8: {
        constexpr std::array<size_t, 4> OFFSETS{16, 24, 32, 40};
        constexpr std::array<size_t, 4> WIDTHS{8, 8, 8, 8};
        if (idx > 3) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::PREF_ID16_IMM16_IMM16_V8_V8: {
        constexpr std::array<size_t, 2> OFFSETS{64, 72};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        if (idx > 1) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::PREF_ID32_V8: {
        constexpr std::array<size_t, 1> OFFSETS{48};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::PREF_IMM16_ID16_ID16_IMM16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{80};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::PREF_IMM16_ID16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{48};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::PREF_IMM16_IMM16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{48};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::PREF_IMM16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{32};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::PREF_IMM16_V8_V8: {
        constexpr std::array<size_t, 2> OFFSETS{32, 40};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        if (idx > 1) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::PREF_IMM4_IMM4_V8: {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::PREF_IMM8_IMM16_IMM16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{56};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::PREF_IMM8_IMM32_V8: {
        constexpr std::array<size_t, 1> OFFSETS{56};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::PREF_IMM8_IMM8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{32};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::PREF_IMM8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::PREF_IMM8_V8_V8: {
        constexpr std::array<size_t, 2> OFFSETS{24, 32};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        if (idx > 1) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::PREF_V8: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::PREF_V8_IMM32: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::PREF_V8_V8: {
        constexpr std::array<size_t, 2> OFFSETS{16, 24};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        if (idx > 1) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::PREF_V8_V8_V8: {
        constexpr std::array<size_t, 3> OFFSETS{16, 24, 32};
        constexpr std::array<size_t, 3> WIDTHS{8, 8, 8};
        if (idx > 2) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::PREF_V8_V8_V8_V8: {
        constexpr std::array<size_t, 4> OFFSETS{16, 24, 32, 40};
        constexpr std::array<size_t, 4> WIDTHS{8, 8, 8, 8};
        if (idx > 3) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::V16_V16: {
        constexpr std::array<size_t, 2> OFFSETS{8, 24};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        if (idx > 1) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::V4_V4: {
        constexpr std::array<size_t, 2> OFFSETS{8, 12};
        constexpr std::array<size_t, 2> WIDTHS{4, 4};
        if (idx > 1) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::V8: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::V8_IMM16: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::V8_IMM8: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        if (idx > 0) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::V8_V8: {
        constexpr std::array<size_t, 2> OFFSETS{8, 16};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        if (idx > 1) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::V8_V8_V8: {
        constexpr std::array<size_t, 3> OFFSETS{8, 16, 24};
        constexpr std::array<size_t, 3> WIDTHS{8, 8, 8};
        if (idx > 2) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    case Format::V8_V8_V8_V8: {
        constexpr std::array<size_t, 4> OFFSETS{8, 16, 24, 32};
        constexpr std::array<size_t, 4> WIDTHS{8, 8, 8, 8};
        if (idx > 3) {
            break;
        }
        return static_cast<uint16_t>(Read64(OFFSETS[idx], WIDTHS[idx]));
    }
    default: {
        break;
    }
    }

    UNREACHABLE();
}

template <const BytecodeInstMode Mode>
template <typename BytecodeInst<Mode>::Format format, size_t idx /* = 0 */, bool is_signed /* = true */>
inline auto BytecodeInst<Mode>::GetImm() const {  // NOLINTNEXTLINE(readability-function-size)
    static_assert(HasImm(format, idx), "Instruction doesn't have imm operand with such index");

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM16) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM16_ID16) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM16_ID16_ID16_IMM16_V8) {
        constexpr std::array<size_t, 2> OFFSETS{8, 56};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM16_ID16_IMM8) {
        constexpr std::array<size_t, 2> OFFSETS{8, 40};
        constexpr std::array<size_t, 2> WIDTHS{16, 8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM16_ID16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM16_IMM16) {
        constexpr std::array<size_t, 2> OFFSETS{8, 24};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM16_IMM8_V8) {
        constexpr std::array<size_t, 2> OFFSETS{8, 24};
        constexpr std::array<size_t, 2> WIDTHS{16, 8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM16_V8_IMM16) {
        constexpr std::array<size_t, 2> OFFSETS{8, 32};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM16_V8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM32) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{32};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM4_IMM4) {
        constexpr std::array<size_t, 2> OFFSETS{8, 12};
        constexpr std::array<size_t, 2> WIDTHS{4, 4};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM64) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{64};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_ID16) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_ID16_ID16_IMM16_V8) {
        constexpr std::array<size_t, 2> OFFSETS{8, 48};
        constexpr std::array<size_t, 2> WIDTHS{8, 16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_ID16_IMM8) {
        constexpr std::array<size_t, 2> OFFSETS{8, 32};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_ID16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_ID16_V8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_ID16_V8_V8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_ID16_V8_V8_V8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_IMM16) {
        constexpr std::array<size_t, 2> OFFSETS{8, 16};
        constexpr std::array<size_t, 2> WIDTHS{8, 16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_IMM16_IMM16) {
        constexpr std::array<size_t, 3> OFFSETS{8, 16, 32};
        constexpr std::array<size_t, 3> WIDTHS{8, 16, 16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_IMM16_IMM16_V8) {
        constexpr std::array<size_t, 3> OFFSETS{8, 16, 32};
        constexpr std::array<size_t, 3> WIDTHS{8, 16, 16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_IMM8) {
        constexpr std::array<size_t, 2> OFFSETS{8, 16};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_IMM8_ID16_V8) {
        constexpr std::array<size_t, 2> OFFSETS{8, 16};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_IMM8_V8) {
        constexpr std::array<size_t, 2> OFFSETS{8, 16};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_V8_IMM16) {
        constexpr std::array<size_t, 2> OFFSETS{8, 24};
        constexpr std::array<size_t, 2> WIDTHS{8, 16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_V8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_V8_V8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::IMM8_V8_V8_V8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_ID16_IMM16_IMM16_V8_V8) {
        constexpr std::array<size_t, 2> OFFSETS{32, 48};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_ID32_IMM8) {
        constexpr std::array<size_t, 1> OFFSETS{48};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM16) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM16_ID16) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM16_ID16_ID16_IMM16_V8) {
        constexpr std::array<size_t, 2> OFFSETS{16, 64};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM16_ID16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM16_IMM16) {
        constexpr std::array<size_t, 2> OFFSETS{16, 32};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM16_IMM16_V8) {
        constexpr std::array<size_t, 2> OFFSETS{16, 32};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM16_V8) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM16_V8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM32) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{32};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM4_IMM4) {
        constexpr std::array<size_t, 2> OFFSETS{16, 20};
        constexpr std::array<size_t, 2> WIDTHS{4, 4};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM4_IMM4_V8) {
        constexpr std::array<size_t, 2> OFFSETS{16, 20};
        constexpr std::array<size_t, 2> WIDTHS{4, 4};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM8) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM8_IMM16_IMM16_V8) {
        constexpr std::array<size_t, 3> OFFSETS{16, 24, 40};
        constexpr std::array<size_t, 3> WIDTHS{8, 16, 16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM8_IMM32_V8) {
        constexpr std::array<size_t, 2> OFFSETS{16, 24};
        constexpr std::array<size_t, 2> WIDTHS{8, 32};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM8_IMM8) {
        constexpr std::array<size_t, 2> OFFSETS{16, 24};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM8_IMM8_V8) {
        constexpr std::array<size_t, 2> OFFSETS{16, 24};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_IMM8_V8_V8) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::PREF_V8_IMM32) {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{32};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::V8_IMM16) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    // Disable check due to clang-tidy bug https://bugs.llvm.org/show_bug.cgi?id=32203
    // NOLINTNEXTLINE(readability-braces-around-statements, bugprone-suspicious-semicolon)
    if constexpr (format == Format::V8_IMM8) {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read<OFFSETS[idx], WIDTHS[idx], is_signed>();
    }

    UNREACHABLE();
}

template <const BytecodeInstMode Mode>
inline auto BytecodeInst<Mode>::GetImmCount() const {
    Format format = GetFormat();
    auto idx = 0;
    ASSERT_PRINT(HasImm(format, idx), "Instruction has no imm operand");

    if (!HasImm(format, idx)) {
        return static_cast<size_t>(0);
    }

    switch (format) {

    case Format::IMM16: {
        return static_cast<size_t>(1);
    }

    case Format::IMM16_ID16: {
        return static_cast<size_t>(1);
    }

    case Format::IMM16_ID16_ID16_IMM16_V8: {
        return static_cast<size_t>(2);
    }

    case Format::IMM16_ID16_IMM8: {
        return static_cast<size_t>(2);
    }

    case Format::IMM16_ID16_V8: {
        return static_cast<size_t>(1);
    }

    case Format::IMM16_IMM16: {
        return static_cast<size_t>(2);
    }

    case Format::IMM16_IMM8_V8: {
        return static_cast<size_t>(2);
    }

    case Format::IMM16_V8: {
        return static_cast<size_t>(1);
    }

    case Format::IMM16_V8_IMM16: {
        return static_cast<size_t>(2);
    }

    case Format::IMM16_V8_V8: {
        return static_cast<size_t>(1);
    }

    case Format::IMM32: {
        return static_cast<size_t>(1);
    }

    case Format::IMM4_IMM4: {
        return static_cast<size_t>(2);
    }

    case Format::IMM64: {
        return static_cast<size_t>(1);
    }

    case Format::IMM8: {
        return static_cast<size_t>(1);
    }

    case Format::IMM8_ID16: {
        return static_cast<size_t>(1);
    }

    case Format::IMM8_ID16_ID16_IMM16_V8: {
        return static_cast<size_t>(2);
    }

    case Format::IMM8_ID16_IMM8: {
        return static_cast<size_t>(2);
    }

    case Format::IMM8_ID16_V8: {
        return static_cast<size_t>(1);
    }

    case Format::IMM8_ID16_V8_V8: {
        return static_cast<size_t>(1);
    }

    case Format::IMM8_ID16_V8_V8_V8: {
        return static_cast<size_t>(1);
    }

    case Format::IMM8_ID16_V8_V8_V8_V8: {
        return static_cast<size_t>(1);
    }

    case Format::IMM8_IMM16: {
        return static_cast<size_t>(2);
    }

    case Format::IMM8_IMM16_IMM16: {
        return static_cast<size_t>(3);
    }

    case Format::IMM8_IMM16_IMM16_V8: {
        return static_cast<size_t>(3);
    }

    case Format::IMM8_IMM8: {
        return static_cast<size_t>(2);
    }

    case Format::IMM8_IMM8_ID16_V8: {
        return static_cast<size_t>(2);
    }

    case Format::IMM8_IMM8_V8: {
        return static_cast<size_t>(2);
    }

    case Format::IMM8_V8: {
        return static_cast<size_t>(1);
    }

    case Format::IMM8_V8_IMM16: {
        return static_cast<size_t>(2);
    }

    case Format::IMM8_V8_V8: {
        return static_cast<size_t>(1);
    }

    case Format::IMM8_V8_V8_V8: {
        return static_cast<size_t>(1);
    }

    case Format::IMM8_V8_V8_V8_V8: {
        return static_cast<size_t>(1);
    }

    case Format::PREF_ID16_IMM16_IMM16_V8_V8: {
        return static_cast<size_t>(2);
    }

    case Format::PREF_ID32_IMM8: {
        return static_cast<size_t>(1);
    }

    case Format::PREF_IMM16: {
        return static_cast<size_t>(1);
    }

    case Format::PREF_IMM16_ID16: {
        return static_cast<size_t>(1);
    }

    case Format::PREF_IMM16_ID16_ID16_IMM16_V8: {
        return static_cast<size_t>(2);
    }

    case Format::PREF_IMM16_ID16_V8: {
        return static_cast<size_t>(1);
    }

    case Format::PREF_IMM16_IMM16: {
        return static_cast<size_t>(2);
    }

    case Format::PREF_IMM16_IMM16_V8: {
        return static_cast<size_t>(2);
    }

    case Format::PREF_IMM16_V8: {
        return static_cast<size_t>(1);
    }

    case Format::PREF_IMM16_V8_V8: {
        return static_cast<size_t>(1);
    }

    case Format::PREF_IMM32: {
        return static_cast<size_t>(1);
    }

    case Format::PREF_IMM4_IMM4: {
        return static_cast<size_t>(2);
    }

    case Format::PREF_IMM4_IMM4_V8: {
        return static_cast<size_t>(2);
    }

    case Format::PREF_IMM8: {
        return static_cast<size_t>(1);
    }

    case Format::PREF_IMM8_IMM16_IMM16_V8: {
        return static_cast<size_t>(3);
    }

    case Format::PREF_IMM8_IMM32_V8: {
        return static_cast<size_t>(2);
    }

    case Format::PREF_IMM8_IMM8: {
        return static_cast<size_t>(2);
    }

    case Format::PREF_IMM8_IMM8_V8: {
        return static_cast<size_t>(2);
    }

    case Format::PREF_IMM8_V8: {
        return static_cast<size_t>(1);
    }

    case Format::PREF_IMM8_V8_V8: {
        return static_cast<size_t>(1);
    }

    case Format::PREF_V8_IMM32: {
        return static_cast<size_t>(1);
    }

    case Format::V8_IMM16: {
        return static_cast<size_t>(1);
    }

    case Format::V8_IMM8: {
        return static_cast<size_t>(1);
    }
    default: {
        break;
    }
    }

    UNREACHABLE();
}

template<const BytecodeInstMode Mode>
inline auto BytecodeInst<Mode>::GetImm64(size_t idx /* = 0 */) const {
    Format format = GetFormat();
    ASSERT_PRINT(HasImm(format, idx), "Instruction doesn't have imm operand with such index");

    if (!HasImm(format, idx)) {
        return static_cast<int64_t>(0);
    }

    switch (format) {
    case Format::IMM16: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM16_ID16: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM16_ID16_ID16_IMM16_V8: {
        constexpr std::array<size_t, 2> OFFSETS{8, 56};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM16_ID16_IMM8: {
        constexpr std::array<size_t, 2> OFFSETS{8, 40};
        constexpr std::array<size_t, 2> WIDTHS{16, 8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM16_ID16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM16_IMM16: {
        constexpr std::array<size_t, 2> OFFSETS{8, 24};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM16_IMM8_V8: {
        constexpr std::array<size_t, 2> OFFSETS{8, 24};
        constexpr std::array<size_t, 2> WIDTHS{16, 8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM16_V8_IMM16: {
        constexpr std::array<size_t, 2> OFFSETS{8, 32};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM16_V8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM32: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{32};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM4_IMM4: {
        constexpr std::array<size_t, 2> OFFSETS{8, 12};
        constexpr std::array<size_t, 2> WIDTHS{4, 4};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM64: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{64};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8_ID16: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8_ID16_ID16_IMM16_V8: {
        constexpr std::array<size_t, 2> OFFSETS{8, 48};
        constexpr std::array<size_t, 2> WIDTHS{8, 16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8_ID16_IMM8: {
        constexpr std::array<size_t, 2> OFFSETS{8, 32};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8_ID16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8_ID16_V8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8_ID16_V8_V8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8_ID16_V8_V8_V8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8_IMM16: {
        constexpr std::array<size_t, 2> OFFSETS{8, 16};
        constexpr std::array<size_t, 2> WIDTHS{8, 16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8_IMM16_IMM16: {
        constexpr std::array<size_t, 3> OFFSETS{8, 16, 32};
        constexpr std::array<size_t, 3> WIDTHS{8, 16, 16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8_IMM16_IMM16_V8: {
        constexpr std::array<size_t, 3> OFFSETS{8, 16, 32};
        constexpr std::array<size_t, 3> WIDTHS{8, 16, 16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8_IMM8: {
        constexpr std::array<size_t, 2> OFFSETS{8, 16};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8_IMM8_ID16_V8: {
        constexpr std::array<size_t, 2> OFFSETS{8, 16};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8_IMM8_V8: {
        constexpr std::array<size_t, 2> OFFSETS{8, 16};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8_V8_IMM16: {
        constexpr std::array<size_t, 2> OFFSETS{8, 24};
        constexpr std::array<size_t, 2> WIDTHS{8, 16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8_V8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8_V8_V8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::IMM8_V8_V8_V8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{8};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_ID16_IMM16_IMM16_V8_V8: {
        constexpr std::array<size_t, 2> OFFSETS{32, 48};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_ID32_IMM8: {
        constexpr std::array<size_t, 1> OFFSETS{48};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_IMM16: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_IMM16_ID16: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_IMM16_ID16_ID16_IMM16_V8: {
        constexpr std::array<size_t, 2> OFFSETS{16, 64};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_IMM16_ID16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_IMM16_IMM16: {
        constexpr std::array<size_t, 2> OFFSETS{16, 32};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_IMM16_IMM16_V8: {
        constexpr std::array<size_t, 2> OFFSETS{16, 32};
        constexpr std::array<size_t, 2> WIDTHS{16, 16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_IMM16_V8: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_IMM16_V8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_IMM32: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{32};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_IMM4_IMM4: {
        constexpr std::array<size_t, 2> OFFSETS{16, 20};
        constexpr std::array<size_t, 2> WIDTHS{4, 4};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_IMM4_IMM4_V8: {
        constexpr std::array<size_t, 2> OFFSETS{16, 20};
        constexpr std::array<size_t, 2> WIDTHS{4, 4};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_IMM8: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_IMM8_IMM16_IMM16_V8: {
        constexpr std::array<size_t, 3> OFFSETS{16, 24, 40};
        constexpr std::array<size_t, 3> WIDTHS{8, 16, 16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_IMM8_IMM32_V8: {
        constexpr std::array<size_t, 2> OFFSETS{16, 24};
        constexpr std::array<size_t, 2> WIDTHS{8, 32};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_IMM8_IMM8: {
        constexpr std::array<size_t, 2> OFFSETS{16, 24};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_IMM8_IMM8_V8: {
        constexpr std::array<size_t, 2> OFFSETS{16, 24};
        constexpr std::array<size_t, 2> WIDTHS{8, 8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_IMM8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_IMM8_V8_V8: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::PREF_V8_IMM32: {
        constexpr std::array<size_t, 1> OFFSETS{24};
        constexpr std::array<size_t, 1> WIDTHS{32};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::V8_IMM16: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{16};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    case Format::V8_IMM8: {
        constexpr std::array<size_t, 1> OFFSETS{16};
        constexpr std::array<size_t, 1> WIDTHS{8};
        return Read64<true>(OFFSETS[idx], WIDTHS[idx]);
    }
    default: {
        break;
    }
    }

    UNREACHABLE();
}

template<const BytecodeInstMode Mode>
inline auto BytecodeInst<Mode>::GetImmData(size_t idx /* = 0 */) const {
    Format format = GetFormat();
    ASSERT_PRINT(HasImm(format, idx), "Instruction doesn't have imm operand with such index");

    if (!HasImm(format, idx)) {
        return static_cast<int64_t>(0);
    }

    int64_t imm = 0;

    switch (GetOpcode()) {
    case BytecodeInst<Mode>::Opcode::LDUNDEFINED:
        break;
    case BytecodeInst<Mode>::Opcode::LDNULL:
        break;
    case BytecodeInst<Mode>::Opcode::LDTRUE:
        break;
    case BytecodeInst<Mode>::Opcode::LDFALSE:
        break;
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYOBJECT:
        break;
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYARRAY_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CREATEARRAYWITHBUFFER_IMM8_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHBUFFER_IMM8_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM8_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM8_V8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM8_V8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::NEWLEXENV_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::ADD2_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::SUB2_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::MUL2_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DIV2_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::MOD2_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::EQ_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::NOTEQ_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LESS_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LESSEQ_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::GREATER_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::GREATEREQ_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::SHL2_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::SHR2_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::ASHR2_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::AND2_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::OR2_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::XOR2_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::EXP_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::TYPEOF_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::TONUMBER_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::TONUMERIC_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::NEG_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::NOT_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::INC_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEC_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::ISTRUE:
        break;
    case BytecodeInst<Mode>::Opcode::ISFALSE:
        break;
    case BytecodeInst<Mode>::Opcode::ISIN_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::INSTANCEOF_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STRICTNOTEQ_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STRICTEQ_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLARG0_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLARG1_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLARGS2_IMM8_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLARGS3_IMM8_V8_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS0_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS1_IMM8_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS2_IMM8_V8_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS3_IMM8_V8_V8_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8_V8_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGE_IMM8_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM8_V8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM8_V8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::SUPERCALLTHISRANGE_IMM8_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM8_V8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM8_V8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEFUNC_IMM8_ID16_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16_IMM8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16_IMM8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEMETHOD_IMM8_ID16_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16_IMM8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16_IMM8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEFINECLASSWITHBUFFER_IMM8_ID16_ID16_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16_ID16_IMM16_V8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16_ID16_IMM16_V8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::GETNEXTPROPNAME_V8:
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYVALUE_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYVALUE_IMM8_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYVALUE_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYINDEX_IMM8_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM16, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM16, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYINDEX_IMM8_V8_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8_IMM16, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8_IMM16, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDLEXVAR_IMM4_IMM4:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM4_IMM4, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM4_IMM4, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STLEXVAR_IMM4_IMM4:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM4_IMM4, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM4_IMM4, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDA_STR_ID16:
        break;
    case BytecodeInst<Mode>::Opcode::TRYLDGLOBALBYNAME_IMM8_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::TRYSTGLOBALBYNAME_IMM8_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDGLOBALVAR_IMM16_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYNAME_IMM8_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYNAME_IMM8_ID16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::MOV_V4_V4:
        break;
    case BytecodeInst<Mode>::Opcode::MOV_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYNAME_IMM8_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STCONSTTOGLOBALRECORD_IMM16_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STTOGLOBALRECORD_IMM16_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDTHISBYNAME_IMM8_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STTHISBYNAME_IMM8_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDTHISBYVALUE_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STTHISBYVALUE_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JMP_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JMP_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::V8_IMM8, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::V8_IMM8, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::V8_IMM8, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::V8_IMM8, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDA_V8:
        break;
    case BytecodeInst<Mode>::Opcode::STA_V8:
        break;
    case BytecodeInst<Mode>::Opcode::LDAI_IMM32:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM32, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::FLDAI_IMM64:
        if (idx == 0) {
            // Note: If the immediate value is a floating-point number,
            // converting it to int64_t may result in precision loss.
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM64, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::RETURN:
        break;
    case BytecodeInst<Mode>::Opcode::RETURNUNDEFINED:
        break;
    case BytecodeInst<Mode>::Opcode::GETPROPITERATOR:
        break;
    case BytecodeInst<Mode>::Opcode::GETITERATOR_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CLOSEITERATOR_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::POPLEXENV:
        break;
    case BytecodeInst<Mode>::Opcode::LDNAN:
        break;
    case BytecodeInst<Mode>::Opcode::LDINFINITY:
        break;
    case BytecodeInst<Mode>::Opcode::GETUNMAPPEDARGS:
        break;
    case BytecodeInst<Mode>::Opcode::LDGLOBAL:
        break;
    case BytecodeInst<Mode>::Opcode::LDNEWTARGET:
        break;
    case BytecodeInst<Mode>::Opcode::LDTHIS:
        break;
    case BytecodeInst<Mode>::Opcode::LDHOLE:
        break;
    case BytecodeInst<Mode>::Opcode::CREATEREGEXPWITHLITERAL_IMM8_ID16_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16_IMM8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16_IMM8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CREATEREGEXPWITHLITERAL_IMM16_ID16_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16_IMM8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16_IMM8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLRANGE_IMM8_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM8_V8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM8_V8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEFUNC_IMM16_ID16_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16_IMM8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16_IMM8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEFINECLASSWITHBUFFER_IMM16_ID16_ID16_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16_ID16_IMM16_V8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16_ID16_IMM16_V8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::GETTEMPLATEOBJECT_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::SETOBJECTWITHPROTO_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUE_IMM8_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYINDEX_IMM8_V8_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8_IMM16, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8_IMM16, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAME_IMM8_ID16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::GETMODULENAMESPACE_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STMODULEVAR_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDLOCALMODULEVAR_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDEXTERNALMODULEVAR_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STGLOBALVAR_IMM16_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYARRAY_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CREATEARRAYWITHBUFFER_IMM16_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHBUFFER_IMM16_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM16_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_IMM8_V8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_IMM8_V8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::TYPEOF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYVALUE_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYVALUE_IMM16_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYVALUE_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYINDEX_IMM16_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_IMM16, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_IMM16, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYINDEX_IMM16_V8_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_V8_IMM16, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_V8_IMM16, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDLEXVAR_IMM8_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STLEXVAR_IMM8_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::TRYLDGLOBALBYNAME_IMM16_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::TRYSTGLOBALBYNAME_IMM16_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAMEWITHNAMESET_IMM8_ID16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::MOV_V16_V16:
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYNAME_IMM16_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYNAME_IMM16_ID16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYNAME_IMM16_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDTHISBYNAME_IMM16_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STTHISBYNAME_IMM16_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDTHISBYVALUE_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STTHISBYVALUE_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCGENERATORREJECT_V8:
        break;
    case BytecodeInst<Mode>::Opcode::JMP_IMM32:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM32, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUEWITHNAMESET_IMM8_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM32:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM32, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM32:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM32, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::V8_IMM16, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::V8_IMM16, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::V8_IMM16, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::V8_IMM16, 0, true>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::GETITERATOR_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CLOSEITERATOR_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDSYMBOL:
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONENTER:
        break;
    case BytecodeInst<Mode>::Opcode::LDFUNCTION:
        break;
    case BytecodeInst<Mode>::Opcode::DEBUGGER:
        break;
    case BytecodeInst<Mode>::Opcode::CREATEGENERATOROBJ_V8:
        break;
    case BytecodeInst<Mode>::Opcode::CREATEITERRESULTOBJ_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHEXCLUDEDKEYS_IMM8_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::NEWOBJAPPLY_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::NEWOBJAPPLY_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::NEWLEXENVWITHNAME_IMM8_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CREATEASYNCGENERATOROBJ_V8:
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCGENERATORRESOLVE_V8_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::SUPERCALLSPREAD_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::APPLY_IMM8_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::SUPERCALLARROWRANGE_IMM8_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM8_V8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM8_V8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEGETTERSETTERBYVALUE_V8_V8_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::DYNAMICIMPORT:
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEMETHOD_IMM16_ID16_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16_IMM8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16_IMM8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::RESUMEGENERATOR:
        break;
    case BytecodeInst<Mode>::Opcode::GETRESUMEMODE:
        break;
    case BytecodeInst<Mode>::Opcode::GETTEMPLATEOBJECT_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DELOBJPROP_V8:
        break;
    case BytecodeInst<Mode>::Opcode::SUSPENDGENERATOR_V8:
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONAWAITUNCAUGHT_V8:
        break;
    case BytecodeInst<Mode>::Opcode::COPYDATAPROPERTIES_V8:
        break;
    case BytecodeInst<Mode>::Opcode::STARRAYSPREAD_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::SETOBJECTWITHPROTO_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUE_IMM16_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STSUPERBYVALUE_IMM8_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STSUPERBYVALUE_IMM16_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYINDEX_IMM16_V8_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_V8_IMM16, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_V8_IMM16, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAME_IMM16_ID16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONRESOLVE_V8:
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONREJECT_V8:
        break;
    case BytecodeInst<Mode>::Opcode::COPYRESTARGS_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STSUPERBYNAME_IMM8_ID16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STSUPERBYNAME_IMM16_ID16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUEWITHNAMESET_IMM16_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDBIGINT_ID16:
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAMEWITHNAMESET_IMM16_ID16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM16_ID16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::NOP:
        break;
    case BytecodeInst<Mode>::Opcode::SETGENERATORSTATE_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::GETASYNCITERATOR_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::LDPRIVATEPROPERTY_IMM8_IMM16_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM16_IMM16, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM16_IMM16, 1, false>());
        }
        if (idx == 2) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM16_IMM16, 2, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::STPRIVATEPROPERTY_IMM8_IMM16_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM16_IMM16_V8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM16_IMM16_V8, 1, false>());
        }
        if (idx == 2) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM16_IMM16_V8, 2, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::TESTIN_IMM8_IMM16_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM16_IMM16, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM16_IMM16, 1, false>());
        }
        if (idx == 2) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM16_IMM16, 2, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEFIELDBYNAME_IMM8_ID16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEPROPERTYBYNAME_IMM8_ID16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS0WITHNAME_IMM8_ID16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS1WITHNAME_IMM8_ID16_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS2WITHNAME_IMM8_ID16_V8_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16_V8_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS3WITHNAME_IMM8_ID16_V8_V8_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_ID16_V8_V8_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGEWITHNAME_IMM8_IMM8_ID16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM8_ID16_V8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::IMM8_IMM8_ID16_V8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_NOTIFYCONCURRENTRESULT_PREF_NONE:
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDLEXENV_PREF_NONE:
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_CREATEOBJECTWITHEXCLUDEDKEYS_PREF_IMM16_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::THROW_PREF_NONE:
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEFIELDBYVALUE_PREF_IMM8_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8_V8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_POPLEXENV_PREF_NONE:
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWOBJRANGE_PREF_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::THROW_NOTEXISTS_PREF_NONE:
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEFIELDBYINDEX_PREF_IMM8_IMM32_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8_IMM32_V8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8_IMM32_V8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETITERATORNEXT_PREF_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWLEXENV_PREF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::THROW_PATTERNNONCOERCIBLE_PREF_NONE:
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_TOPROPERTYKEY_PREF_NONE:
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEARRAYWITHBUFFER_PREF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWLEXENVWITHNAME_PREF_IMM16_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::THROW_DELETESUPERPROPERTY_PREF_NONE:
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_CREATEPRIVATEPROPERTY_PREF_IMM16_ID16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_ID16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEOBJECTWITHBUFFER_PREF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLRANGE_PREF_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::THROW_CONSTASSIGNMENT_PREF_V8:
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEPRIVATEPROPERTY_PREF_IMM8_IMM16_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8_IMM16_IMM16_V8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8_IMM16_IMM16_V8, 1, false>());
        }
        if (idx == 2) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8_IMM16_IMM16_V8, 2, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_TONUMBER_PREF_V8:
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGE_PREF_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::THROW_IFNOTOBJECT_PREF_V8:
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_CALLINIT_PREF_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_TONUMERIC_PREF_V8:
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLTHISRANGE_PREF_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::THROW_UNDEFINEDIFHOLE_PREF_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINESENDABLECLASS_PREF_IMM16_ID16_ID16_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_ID16_ID16_IMM16_V8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_ID16_ID16_IMM16_V8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_NEG_PREF_V8:
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLARROWRANGE_PREF_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::THROW_IFSUPERNOTCORRECTCALL_PREF_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLECLASS_PREF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_NOT_PREF_V8:
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDOBJBYINDEX_PREF_IMM32:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM32, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::THROW_IFSUPERNOTCORRECTCALL_PREF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEEXTERNALMODULEVAR_PREF_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_INC_PREF_V8:
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STOBJBYINDEX_PREF_V8_IMM32:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_V8_IMM32, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::THROW_UNDEFINEDIFHOLEWITHNAME_PREF_ID16:
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLEEXTERNALMODULEVAR_PREF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DEC_PREF_V8:
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STOWNBYINDEX_PREF_V8_IMM32:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_V8_IMM32, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_NEWSENDABLEENV_PREF_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARG0_PREF_V8:
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_COPYRESTARGS_PREF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDENEWSENDABLEENV_PREF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARG1_PREF_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDLEXVAR_PREF_IMM16_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_IMM16, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_IMM16, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_STSENDABLEVAR_PREF_IMM4_IMM4:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM4_IMM4, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM4_IMM4, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARGS2_PREF_V8_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STLEXVAR_PREF_IMM16_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_IMM16, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_IMM16, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_STSENDABLEVAR_PREF_IMM8_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8_IMM8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8_IMM8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARGS3_PREF_V8_V8_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_GETMODULENAMESPACE_PREF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDESTSENDABLEVAR_PREF_IMM16_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_IMM16, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_IMM16, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLRANGE_PREF_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STMODULEVAR_PREF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEVAR_PREF_IMM4_IMM4:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM4_IMM4, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM4_IMM4, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLSPREAD_PREF_V8_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDLOCALMODULEVAR_PREF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEVAR_PREF_IMM8_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8_IMM8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8_IMM8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLTHISRANGE_PREF_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDEXTERNALMODULEVAR_PREF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLEVAR_PREF_IMM16_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_IMM16, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_IMM16, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DEFINECLASSWITHBUFFER_PREF_ID16_IMM16_IMM16_V8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_ID16_IMM16_IMM16_V8_V8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_ID16_IMM16_IMM16_V8_V8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDPATCHVAR_PREF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_ISTRUE_PREF_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_RESUMEGENERATOR_PREF_V8:
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STPATCHVAR_PREF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_ISFALSE_PREF_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETRESUMEMODE_PREF_V8:
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGEWITHNAME_PREF_IMM16_ID16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_ID16_V8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDLAZYMODULEVAR_PREF_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETTEMPLATEOBJECT_PREF_V8:
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDLAZYMODULEVAR_PREF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DELOBJPROP_PREF_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDLAZYSENDABLEMODULEVAR_PREF_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_SUSPENDGENERATOR_PREF_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDLAZYSENDABLEMODULEVAR_PREF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONAWAITUNCAUGHT_PREF_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_SUPERCALLFORWARDALLARGS_PREF_V8:
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_COPYDATAPROPERTIES_PREF_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLELOCALMODULEVAR_PREF_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_SETOBJECTWITHPROTO_PREF_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLELOCALMODULEVAR_PREF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYVALUE_PREF_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDSUPERBYVALUE_PREF_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYINDEX_PREF_V8_IMM32:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_V8_IMM32, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONRESOLVE_PREF_V8_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONREJECT_PREF_V8_V8_V8:
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM4_IMM4_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM4_IMM4_V8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM4_IMM4_V8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM8_IMM8_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8_IMM8_V8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM8_IMM8_V8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM16_IMM16_V8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_IMM16_V8, 0, false>());
        }
        if (idx == 1) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16_IMM16_V8, 1, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETMODULENAMESPACE_PREF_ID32:
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STMODULEVAR_PREF_ID32:
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYNAME_PREF_ID32_V8:
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDSUPERBYNAME_PREF_ID32_V8:
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDMODULEVAR_PREF_ID32_IMM8:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_ID32_IMM8, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STCONSTTOGLOBALRECORD_PREF_ID32:
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLETTOGLOBALRECORD_PREF_ID32:
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STCLASSTOGLOBALRECORD_PREF_ID32:
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDHOMEOBJECT_PREF_NONE:
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEOBJECTHAVINGMETHOD_PREF_IMM16:
        if (idx == 0) {
            imm = static_cast<int64_t>(GetImm<BytecodeInstruction::Format::PREF_IMM16, 0, false>());
        }
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DYNAMICIMPORT_PREF_V8:
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCGENERATORREJECT_PREF_V8_V8:
        break;
    default:
        break;
    }

    return imm;
}

template <const BytecodeInstMode Mode>
inline typename BytecodeInst<Mode>::Opcode BytecodeInst<Mode>::GetOpcode() const {
    uint8_t primary = GetPrimaryOpcode();
    if (primary >= 251) {  // NOLINT(readability-magic-numbers)
        uint8_t secondary = GetSecondaryOpcode();
        return static_cast<BytecodeInst::Opcode>((secondary << 8U) | primary);  // NOLINT(hicpp-signed-bitwise)
    }
    return static_cast<BytecodeInst::Opcode>(primary);
}

template <const BytecodeInstMode Mode>
inline uint8_t BytecodeInst<Mode>::GetSecondaryOpcode() const {
    ASSERT(GetPrimaryOpcode() >= 251);  // NOLINT(readability-magic-numbers)
    return ReadByte(1);
}

/* static */
template <const BytecodeInstMode Mode>
constexpr uint8_t BytecodeInst<Mode>::GetMinPrefixOpcodeIndex() {
    return 251;  // NOLINT(readability-magic-numbers)
}

template <const BytecodeInstMode Mode>
inline bool BytecodeInst<Mode>::IsPrefixed() const {
    return GetPrimaryOpcode() >= 251;  // NOLINT(readability-magic-numbers)
}

template <const BytecodeInstMode Mode>
inline typename BytecodeInst<Mode>::Format BytecodeInst<Mode>::GetFormat() const {  // NOLINT(readability-function-size)
    return GetFormat(GetOpcode());
}

/* static */
template <const BytecodeInstMode Mode>
constexpr typename BytecodeInst<Mode>::Format BytecodeInst<Mode>::GetFormat(Opcode opcode) {  // NOLINT(readability-function-size)
    switch(opcode) {
    case BytecodeInst<Mode>::Opcode::LDUNDEFINED:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::LDNULL:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::LDTRUE:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::LDFALSE:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYOBJECT:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYARRAY_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::CREATEARRAYWITHBUFFER_IMM8_ID16:
        return BytecodeInst<Mode>::Format::IMM8_ID16;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHBUFFER_IMM8_ID16:
        return BytecodeInst<Mode>::Format::IMM8_ID16;
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM8_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_IMM8_V8;
    case BytecodeInst<Mode>::Opcode::NEWLEXENV_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::ADD2_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::SUB2_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::MUL2_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::DIV2_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::MOD2_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::EQ_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::NOTEQ_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::LESS_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::LESSEQ_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::GREATER_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::GREATEREQ_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::SHL2_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::SHR2_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::ASHR2_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::AND2_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::OR2_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::XOR2_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::EXP_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::TYPEOF_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::TONUMBER_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::TONUMERIC_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::NEG_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::NOT_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::INC_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::DEC_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::ISTRUE:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::ISFALSE:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::ISIN_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::INSTANCEOF_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::STRICTNOTEQ_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::STRICTEQ_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::CALLARG0_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::CALLARG1_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::CALLARGS2_IMM8_V8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8_V8;
    case BytecodeInst<Mode>::Opcode::CALLARGS3_IMM8_V8_V8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8_V8_V8;
    case BytecodeInst<Mode>::Opcode::CALLTHIS0_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::CALLTHIS1_IMM8_V8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8_V8;
    case BytecodeInst<Mode>::Opcode::CALLTHIS2_IMM8_V8_V8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8_V8_V8;
    case BytecodeInst<Mode>::Opcode::CALLTHIS3_IMM8_V8_V8_V8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8_V8_V8_V8;
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGE_IMM8_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_IMM8_V8;
    case BytecodeInst<Mode>::Opcode::SUPERCALLTHISRANGE_IMM8_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_IMM8_V8;
    case BytecodeInst<Mode>::Opcode::DEFINEFUNC_IMM8_ID16_IMM8:
        return BytecodeInst<Mode>::Format::IMM8_ID16_IMM8;
    case BytecodeInst<Mode>::Opcode::DEFINEMETHOD_IMM8_ID16_IMM8:
        return BytecodeInst<Mode>::Format::IMM8_ID16_IMM8;
    case BytecodeInst<Mode>::Opcode::DEFINECLASSWITHBUFFER_IMM8_ID16_ID16_IMM16_V8:
        return BytecodeInst<Mode>::Format::IMM8_ID16_ID16_IMM16_V8;
    case BytecodeInst<Mode>::Opcode::GETNEXTPROPNAME_V8:
        return BytecodeInst<Mode>::Format::V8;
    case BytecodeInst<Mode>::Opcode::LDOBJBYVALUE_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::STOBJBYVALUE_IMM8_V8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8_V8;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYVALUE_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::LDOBJBYINDEX_IMM8_IMM16:
        return BytecodeInst<Mode>::Format::IMM8_IMM16;
    case BytecodeInst<Mode>::Opcode::STOBJBYINDEX_IMM8_V8_IMM16:
        return BytecodeInst<Mode>::Format::IMM8_V8_IMM16;
    case BytecodeInst<Mode>::Opcode::LDLEXVAR_IMM4_IMM4:
        return BytecodeInst<Mode>::Format::IMM4_IMM4;
    case BytecodeInst<Mode>::Opcode::STLEXVAR_IMM4_IMM4:
        return BytecodeInst<Mode>::Format::IMM4_IMM4;
    case BytecodeInst<Mode>::Opcode::LDA_STR_ID16:
        return BytecodeInst<Mode>::Format::ID16;
    case BytecodeInst<Mode>::Opcode::TRYLDGLOBALBYNAME_IMM8_ID16:
        return BytecodeInst<Mode>::Format::IMM8_ID16;
    case BytecodeInst<Mode>::Opcode::TRYSTGLOBALBYNAME_IMM8_ID16:
        return BytecodeInst<Mode>::Format::IMM8_ID16;
    case BytecodeInst<Mode>::Opcode::LDGLOBALVAR_IMM16_ID16:
        return BytecodeInst<Mode>::Format::IMM16_ID16;
    case BytecodeInst<Mode>::Opcode::LDOBJBYNAME_IMM8_ID16:
        return BytecodeInst<Mode>::Format::IMM8_ID16;
    case BytecodeInst<Mode>::Opcode::STOBJBYNAME_IMM8_ID16_V8:
        return BytecodeInst<Mode>::Format::IMM8_ID16_V8;
    case BytecodeInst<Mode>::Opcode::MOV_V4_V4:
        return BytecodeInst<Mode>::Format::V4_V4;
    case BytecodeInst<Mode>::Opcode::MOV_V8_V8:
        return BytecodeInst<Mode>::Format::V8_V8;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYNAME_IMM8_ID16:
        return BytecodeInst<Mode>::Format::IMM8_ID16;
    case BytecodeInst<Mode>::Opcode::STCONSTTOGLOBALRECORD_IMM16_ID16:
        return BytecodeInst<Mode>::Format::IMM16_ID16;
    case BytecodeInst<Mode>::Opcode::STTOGLOBALRECORD_IMM16_ID16:
        return BytecodeInst<Mode>::Format::IMM16_ID16;
    case BytecodeInst<Mode>::Opcode::LDTHISBYNAME_IMM8_ID16:
        return BytecodeInst<Mode>::Format::IMM8_ID16;
    case BytecodeInst<Mode>::Opcode::STTHISBYNAME_IMM8_ID16:
        return BytecodeInst<Mode>::Format::IMM8_ID16;
    case BytecodeInst<Mode>::Opcode::LDTHISBYVALUE_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::STTHISBYVALUE_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::JMP_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::JMP_IMM16:
        return BytecodeInst<Mode>::Format::IMM16;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM16:
        return BytecodeInst<Mode>::Format::IMM16;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM8:
        return BytecodeInst<Mode>::Format::V8_IMM8;
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM8:
        return BytecodeInst<Mode>::Format::V8_IMM8;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM8:
        return BytecodeInst<Mode>::Format::V8_IMM8;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM8:
        return BytecodeInst<Mode>::Format::V8_IMM8;
    case BytecodeInst<Mode>::Opcode::LDA_V8:
        return BytecodeInst<Mode>::Format::V8;
    case BytecodeInst<Mode>::Opcode::STA_V8:
        return BytecodeInst<Mode>::Format::V8;
    case BytecodeInst<Mode>::Opcode::LDAI_IMM32:
        return BytecodeInst<Mode>::Format::IMM32;
    case BytecodeInst<Mode>::Opcode::FLDAI_IMM64:
        return BytecodeInst<Mode>::Format::IMM64;
    case BytecodeInst<Mode>::Opcode::RETURN:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::RETURNUNDEFINED:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::GETPROPITERATOR:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::GETITERATOR_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::CLOSEITERATOR_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::POPLEXENV:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::LDNAN:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::LDINFINITY:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::GETUNMAPPEDARGS:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::LDGLOBAL:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::LDNEWTARGET:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::LDTHIS:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::LDHOLE:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::CREATEREGEXPWITHLITERAL_IMM8_ID16_IMM8:
        return BytecodeInst<Mode>::Format::IMM8_ID16_IMM8;
    case BytecodeInst<Mode>::Opcode::CREATEREGEXPWITHLITERAL_IMM16_ID16_IMM8:
        return BytecodeInst<Mode>::Format::IMM16_ID16_IMM8;
    case BytecodeInst<Mode>::Opcode::CALLRANGE_IMM8_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_IMM8_V8;
    case BytecodeInst<Mode>::Opcode::DEFINEFUNC_IMM16_ID16_IMM8:
        return BytecodeInst<Mode>::Format::IMM16_ID16_IMM8;
    case BytecodeInst<Mode>::Opcode::DEFINECLASSWITHBUFFER_IMM16_ID16_ID16_IMM16_V8:
        return BytecodeInst<Mode>::Format::IMM16_ID16_ID16_IMM16_V8;
    case BytecodeInst<Mode>::Opcode::GETTEMPLATEOBJECT_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::SETOBJECTWITHPROTO_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUE_IMM8_V8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8_V8;
    case BytecodeInst<Mode>::Opcode::STOWNBYINDEX_IMM8_V8_IMM16:
        return BytecodeInst<Mode>::Format::IMM8_V8_IMM16;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAME_IMM8_ID16_V8:
        return BytecodeInst<Mode>::Format::IMM8_ID16_V8;
    case BytecodeInst<Mode>::Opcode::GETMODULENAMESPACE_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::STMODULEVAR_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::LDLOCALMODULEVAR_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::LDEXTERNALMODULEVAR_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::STGLOBALVAR_IMM16_ID16:
        return BytecodeInst<Mode>::Format::IMM16_ID16;
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYARRAY_IMM16:
        return BytecodeInst<Mode>::Format::IMM16;
    case BytecodeInst<Mode>::Opcode::CREATEARRAYWITHBUFFER_IMM16_ID16:
        return BytecodeInst<Mode>::Format::IMM16_ID16;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHBUFFER_IMM16_ID16:
        return BytecodeInst<Mode>::Format::IMM16_ID16;
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM16_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM16_IMM8_V8;
    case BytecodeInst<Mode>::Opcode::TYPEOF_IMM16:
        return BytecodeInst<Mode>::Format::IMM16;
    case BytecodeInst<Mode>::Opcode::LDOBJBYVALUE_IMM16_V8:
        return BytecodeInst<Mode>::Format::IMM16_V8;
    case BytecodeInst<Mode>::Opcode::STOBJBYVALUE_IMM16_V8_V8:
        return BytecodeInst<Mode>::Format::IMM16_V8_V8;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYVALUE_IMM16_V8:
        return BytecodeInst<Mode>::Format::IMM16_V8;
    case BytecodeInst<Mode>::Opcode::LDOBJBYINDEX_IMM16_IMM16:
        return BytecodeInst<Mode>::Format::IMM16_IMM16;
    case BytecodeInst<Mode>::Opcode::STOBJBYINDEX_IMM16_V8_IMM16:
        return BytecodeInst<Mode>::Format::IMM16_V8_IMM16;
    case BytecodeInst<Mode>::Opcode::LDLEXVAR_IMM8_IMM8:
        return BytecodeInst<Mode>::Format::IMM8_IMM8;
    case BytecodeInst<Mode>::Opcode::STLEXVAR_IMM8_IMM8:
        return BytecodeInst<Mode>::Format::IMM8_IMM8;
    case BytecodeInst<Mode>::Opcode::TRYLDGLOBALBYNAME_IMM16_ID16:
        return BytecodeInst<Mode>::Format::IMM16_ID16;
    case BytecodeInst<Mode>::Opcode::TRYSTGLOBALBYNAME_IMM16_ID16:
        return BytecodeInst<Mode>::Format::IMM16_ID16;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAMEWITHNAMESET_IMM8_ID16_V8:
        return BytecodeInst<Mode>::Format::IMM8_ID16_V8;
    case BytecodeInst<Mode>::Opcode::MOV_V16_V16:
        return BytecodeInst<Mode>::Format::V16_V16;
    case BytecodeInst<Mode>::Opcode::LDOBJBYNAME_IMM16_ID16:
        return BytecodeInst<Mode>::Format::IMM16_ID16;
    case BytecodeInst<Mode>::Opcode::STOBJBYNAME_IMM16_ID16_V8:
        return BytecodeInst<Mode>::Format::IMM16_ID16_V8;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYNAME_IMM16_ID16:
        return BytecodeInst<Mode>::Format::IMM16_ID16;
    case BytecodeInst<Mode>::Opcode::LDTHISBYNAME_IMM16_ID16:
        return BytecodeInst<Mode>::Format::IMM16_ID16;
    case BytecodeInst<Mode>::Opcode::STTHISBYNAME_IMM16_ID16:
        return BytecodeInst<Mode>::Format::IMM16_ID16;
    case BytecodeInst<Mode>::Opcode::LDTHISBYVALUE_IMM16:
        return BytecodeInst<Mode>::Format::IMM16;
    case BytecodeInst<Mode>::Opcode::STTHISBYVALUE_IMM16_V8:
        return BytecodeInst<Mode>::Format::IMM16_V8;
    case BytecodeInst<Mode>::Opcode::ASYNCGENERATORREJECT_V8:
        return BytecodeInst<Mode>::Format::V8;
    case BytecodeInst<Mode>::Opcode::JMP_IMM32:
        return BytecodeInst<Mode>::Format::IMM32;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUEWITHNAMESET_IMM8_V8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8_V8;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM32:
        return BytecodeInst<Mode>::Format::IMM32;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM16:
        return BytecodeInst<Mode>::Format::IMM16;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM32:
        return BytecodeInst<Mode>::Format::IMM32;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM16:
        return BytecodeInst<Mode>::Format::IMM16;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM16:
        return BytecodeInst<Mode>::Format::IMM16;
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM16:
        return BytecodeInst<Mode>::Format::IMM16;
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM16:
        return BytecodeInst<Mode>::Format::IMM16;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM16:
        return BytecodeInst<Mode>::Format::IMM16;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM16:
        return BytecodeInst<Mode>::Format::IMM16;
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM16:
        return BytecodeInst<Mode>::Format::IMM16;
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM16:
        return BytecodeInst<Mode>::Format::IMM16;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM16:
        return BytecodeInst<Mode>::Format::IMM16;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM16:
        return BytecodeInst<Mode>::Format::IMM16;
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM16:
        return BytecodeInst<Mode>::Format::V8_IMM16;
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM16:
        return BytecodeInst<Mode>::Format::V8_IMM16;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM16:
        return BytecodeInst<Mode>::Format::V8_IMM16;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM16:
        return BytecodeInst<Mode>::Format::V8_IMM16;
    case BytecodeInst<Mode>::Opcode::GETITERATOR_IMM16:
        return BytecodeInst<Mode>::Format::IMM16;
    case BytecodeInst<Mode>::Opcode::CLOSEITERATOR_IMM16_V8:
        return BytecodeInst<Mode>::Format::IMM16_V8;
    case BytecodeInst<Mode>::Opcode::LDSYMBOL:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONENTER:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::LDFUNCTION:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::DEBUGGER:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::CREATEGENERATOROBJ_V8:
        return BytecodeInst<Mode>::Format::V8;
    case BytecodeInst<Mode>::Opcode::CREATEITERRESULTOBJ_V8_V8:
        return BytecodeInst<Mode>::Format::V8_V8;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHEXCLUDEDKEYS_IMM8_V8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8_V8;
    case BytecodeInst<Mode>::Opcode::NEWOBJAPPLY_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::NEWOBJAPPLY_IMM16_V8:
        return BytecodeInst<Mode>::Format::IMM16_V8;
    case BytecodeInst<Mode>::Opcode::NEWLEXENVWITHNAME_IMM8_ID16:
        return BytecodeInst<Mode>::Format::IMM8_ID16;
    case BytecodeInst<Mode>::Opcode::CREATEASYNCGENERATOROBJ_V8:
        return BytecodeInst<Mode>::Format::V8;
    case BytecodeInst<Mode>::Opcode::ASYNCGENERATORRESOLVE_V8_V8_V8:
        return BytecodeInst<Mode>::Format::V8_V8_V8;
    case BytecodeInst<Mode>::Opcode::SUPERCALLSPREAD_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8;
    case BytecodeInst<Mode>::Opcode::APPLY_IMM8_V8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8_V8;
    case BytecodeInst<Mode>::Opcode::SUPERCALLARROWRANGE_IMM8_IMM8_V8:
        return BytecodeInst<Mode>::Format::IMM8_IMM8_V8;
    case BytecodeInst<Mode>::Opcode::DEFINEGETTERSETTERBYVALUE_V8_V8_V8_V8:
        return BytecodeInst<Mode>::Format::V8_V8_V8_V8;
    case BytecodeInst<Mode>::Opcode::DYNAMICIMPORT:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::DEFINEMETHOD_IMM16_ID16_IMM8:
        return BytecodeInst<Mode>::Format::IMM16_ID16_IMM8;
    case BytecodeInst<Mode>::Opcode::RESUMEGENERATOR:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::GETRESUMEMODE:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::GETTEMPLATEOBJECT_IMM16:
        return BytecodeInst<Mode>::Format::IMM16;
    case BytecodeInst<Mode>::Opcode::DELOBJPROP_V8:
        return BytecodeInst<Mode>::Format::V8;
    case BytecodeInst<Mode>::Opcode::SUSPENDGENERATOR_V8:
        return BytecodeInst<Mode>::Format::V8;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONAWAITUNCAUGHT_V8:
        return BytecodeInst<Mode>::Format::V8;
    case BytecodeInst<Mode>::Opcode::COPYDATAPROPERTIES_V8:
        return BytecodeInst<Mode>::Format::V8;
    case BytecodeInst<Mode>::Opcode::STARRAYSPREAD_V8_V8:
        return BytecodeInst<Mode>::Format::V8_V8;
    case BytecodeInst<Mode>::Opcode::SETOBJECTWITHPROTO_IMM16_V8:
        return BytecodeInst<Mode>::Format::IMM16_V8;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUE_IMM16_V8_V8:
        return BytecodeInst<Mode>::Format::IMM16_V8_V8;
    case BytecodeInst<Mode>::Opcode::STSUPERBYVALUE_IMM8_V8_V8:
        return BytecodeInst<Mode>::Format::IMM8_V8_V8;
    case BytecodeInst<Mode>::Opcode::STSUPERBYVALUE_IMM16_V8_V8:
        return BytecodeInst<Mode>::Format::IMM16_V8_V8;
    case BytecodeInst<Mode>::Opcode::STOWNBYINDEX_IMM16_V8_IMM16:
        return BytecodeInst<Mode>::Format::IMM16_V8_IMM16;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAME_IMM16_ID16_V8:
        return BytecodeInst<Mode>::Format::IMM16_ID16_V8;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONRESOLVE_V8:
        return BytecodeInst<Mode>::Format::V8;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONREJECT_V8:
        return BytecodeInst<Mode>::Format::V8;
    case BytecodeInst<Mode>::Opcode::COPYRESTARGS_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::STSUPERBYNAME_IMM8_ID16_V8:
        return BytecodeInst<Mode>::Format::IMM8_ID16_V8;
    case BytecodeInst<Mode>::Opcode::STSUPERBYNAME_IMM16_ID16_V8:
        return BytecodeInst<Mode>::Format::IMM16_ID16_V8;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUEWITHNAMESET_IMM16_V8_V8:
        return BytecodeInst<Mode>::Format::IMM16_V8_V8;
    case BytecodeInst<Mode>::Opcode::LDBIGINT_ID16:
        return BytecodeInst<Mode>::Format::ID16;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAMEWITHNAMESET_IMM16_ID16_V8:
        return BytecodeInst<Mode>::Format::IMM16_ID16_V8;
    case BytecodeInst<Mode>::Opcode::NOP:
        return BytecodeInst<Mode>::Format::NONE;
    case BytecodeInst<Mode>::Opcode::SETGENERATORSTATE_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::GETASYNCITERATOR_IMM8:
        return BytecodeInst<Mode>::Format::IMM8;
    case BytecodeInst<Mode>::Opcode::LDPRIVATEPROPERTY_IMM8_IMM16_IMM16:
        return BytecodeInst<Mode>::Format::IMM8_IMM16_IMM16;
    case BytecodeInst<Mode>::Opcode::STPRIVATEPROPERTY_IMM8_IMM16_IMM16_V8:
        return BytecodeInst<Mode>::Format::IMM8_IMM16_IMM16_V8;
    case BytecodeInst<Mode>::Opcode::TESTIN_IMM8_IMM16_IMM16:
        return BytecodeInst<Mode>::Format::IMM8_IMM16_IMM16;
    case BytecodeInst<Mode>::Opcode::DEFINEFIELDBYNAME_IMM8_ID16_V8:
        return BytecodeInst<Mode>::Format::IMM8_ID16_V8;
    case BytecodeInst<Mode>::Opcode::DEFINEPROPERTYBYNAME_IMM8_ID16_V8:
        return BytecodeInst<Mode>::Format::IMM8_ID16_V8;
    case BytecodeInst<Mode>::Opcode::CALLTHIS0WITHNAME_IMM8_ID16_V8:
        return BytecodeInst<Mode>::Format::IMM8_ID16_V8;
    case BytecodeInst<Mode>::Opcode::CALLTHIS1WITHNAME_IMM8_ID16_V8_V8:
        return BytecodeInst<Mode>::Format::IMM8_ID16_V8_V8;
    case BytecodeInst<Mode>::Opcode::CALLTHIS2WITHNAME_IMM8_ID16_V8_V8_V8:
        return BytecodeInst<Mode>::Format::IMM8_ID16_V8_V8_V8;
    case BytecodeInst<Mode>::Opcode::CALLTHIS3WITHNAME_IMM8_ID16_V8_V8_V8_V8:
        return BytecodeInst<Mode>::Format::IMM8_ID16_V8_V8_V8_V8;
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGEWITHNAME_IMM8_IMM8_ID16_V8:
        return BytecodeInst<Mode>::Format::IMM8_IMM8_ID16_V8;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_NOTIFYCONCURRENTRESULT_PREF_NONE:
        return BytecodeInst<Mode>::Format::PREF_NONE;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDLEXENV_PREF_NONE:
        return BytecodeInst<Mode>::Format::PREF_NONE;
    case BytecodeInst<Mode>::Opcode::WIDE_CREATEOBJECTWITHEXCLUDEDKEYS_PREF_IMM16_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_IMM16_V8_V8;
    case BytecodeInst<Mode>::Opcode::THROW_PREF_NONE:
        return BytecodeInst<Mode>::Format::PREF_NONE;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEFIELDBYVALUE_PREF_IMM8_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_IMM8_V8_V8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_POPLEXENV_PREF_NONE:
        return BytecodeInst<Mode>::Format::PREF_NONE;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWOBJRANGE_PREF_IMM16_V8:
        return BytecodeInst<Mode>::Format::PREF_IMM16_V8;
    case BytecodeInst<Mode>::Opcode::THROW_NOTEXISTS_PREF_NONE:
        return BytecodeInst<Mode>::Format::PREF_NONE;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEFIELDBYINDEX_PREF_IMM8_IMM32_V8:
        return BytecodeInst<Mode>::Format::PREF_IMM8_IMM32_V8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETITERATORNEXT_PREF_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_V8_V8;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWLEXENV_PREF_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16;
    case BytecodeInst<Mode>::Opcode::THROW_PATTERNNONCOERCIBLE_PREF_NONE:
        return BytecodeInst<Mode>::Format::PREF_NONE;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_TOPROPERTYKEY_PREF_NONE:
        return BytecodeInst<Mode>::Format::PREF_NONE;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEARRAYWITHBUFFER_PREF_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWLEXENVWITHNAME_PREF_IMM16_ID16:
        return BytecodeInst<Mode>::Format::PREF_IMM16_ID16;
    case BytecodeInst<Mode>::Opcode::THROW_DELETESUPERPROPERTY_PREF_NONE:
        return BytecodeInst<Mode>::Format::PREF_NONE;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_CREATEPRIVATEPROPERTY_PREF_IMM16_ID16:
        return BytecodeInst<Mode>::Format::PREF_IMM16_ID16;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEOBJECTWITHBUFFER_PREF_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLRANGE_PREF_IMM16_V8:
        return BytecodeInst<Mode>::Format::PREF_IMM16_V8;
    case BytecodeInst<Mode>::Opcode::THROW_CONSTASSIGNMENT_PREF_V8:
        return BytecodeInst<Mode>::Format::PREF_V8;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEPRIVATEPROPERTY_PREF_IMM8_IMM16_IMM16_V8:
        return BytecodeInst<Mode>::Format::PREF_IMM8_IMM16_IMM16_V8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_TONUMBER_PREF_V8:
        return BytecodeInst<Mode>::Format::PREF_V8;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGE_PREF_IMM16_V8:
        return BytecodeInst<Mode>::Format::PREF_IMM16_V8;
    case BytecodeInst<Mode>::Opcode::THROW_IFNOTOBJECT_PREF_V8:
        return BytecodeInst<Mode>::Format::PREF_V8;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_CALLINIT_PREF_IMM8_V8:
        return BytecodeInst<Mode>::Format::PREF_IMM8_V8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_TONUMERIC_PREF_V8:
        return BytecodeInst<Mode>::Format::PREF_V8;
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLTHISRANGE_PREF_IMM16_V8:
        return BytecodeInst<Mode>::Format::PREF_IMM16_V8;
    case BytecodeInst<Mode>::Opcode::THROW_UNDEFINEDIFHOLE_PREF_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_V8_V8;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINESENDABLECLASS_PREF_IMM16_ID16_ID16_IMM16_V8:
        return BytecodeInst<Mode>::Format::PREF_IMM16_ID16_ID16_IMM16_V8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_NEG_PREF_V8:
        return BytecodeInst<Mode>::Format::PREF_V8;
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLARROWRANGE_PREF_IMM16_V8:
        return BytecodeInst<Mode>::Format::PREF_IMM16_V8;
    case BytecodeInst<Mode>::Opcode::THROW_IFSUPERNOTCORRECTCALL_PREF_IMM8:
        return BytecodeInst<Mode>::Format::PREF_IMM8;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLECLASS_PREF_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_NOT_PREF_V8:
        return BytecodeInst<Mode>::Format::PREF_V8;
    case BytecodeInst<Mode>::Opcode::WIDE_LDOBJBYINDEX_PREF_IMM32:
        return BytecodeInst<Mode>::Format::PREF_IMM32;
    case BytecodeInst<Mode>::Opcode::THROW_IFSUPERNOTCORRECTCALL_PREF_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEEXTERNALMODULEVAR_PREF_IMM8:
        return BytecodeInst<Mode>::Format::PREF_IMM8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_INC_PREF_V8:
        return BytecodeInst<Mode>::Format::PREF_V8;
    case BytecodeInst<Mode>::Opcode::WIDE_STOBJBYINDEX_PREF_V8_IMM32:
        return BytecodeInst<Mode>::Format::PREF_V8_IMM32;
    case BytecodeInst<Mode>::Opcode::THROW_UNDEFINEDIFHOLEWITHNAME_PREF_ID16:
        return BytecodeInst<Mode>::Format::PREF_ID16;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLEEXTERNALMODULEVAR_PREF_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DEC_PREF_V8:
        return BytecodeInst<Mode>::Format::PREF_V8;
    case BytecodeInst<Mode>::Opcode::WIDE_STOWNBYINDEX_PREF_V8_IMM32:
        return BytecodeInst<Mode>::Format::PREF_V8_IMM32;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_NEWSENDABLEENV_PREF_IMM8:
        return BytecodeInst<Mode>::Format::PREF_IMM8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARG0_PREF_V8:
        return BytecodeInst<Mode>::Format::PREF_V8;
    case BytecodeInst<Mode>::Opcode::WIDE_COPYRESTARGS_PREF_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDENEWSENDABLEENV_PREF_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARG1_PREF_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_V8_V8;
    case BytecodeInst<Mode>::Opcode::WIDE_LDLEXVAR_PREF_IMM16_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16_IMM16;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_STSENDABLEVAR_PREF_IMM4_IMM4:
        return BytecodeInst<Mode>::Format::PREF_IMM4_IMM4;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARGS2_PREF_V8_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_V8_V8_V8;
    case BytecodeInst<Mode>::Opcode::WIDE_STLEXVAR_PREF_IMM16_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16_IMM16;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_STSENDABLEVAR_PREF_IMM8_IMM8:
        return BytecodeInst<Mode>::Format::PREF_IMM8_IMM8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARGS3_PREF_V8_V8_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_V8_V8_V8_V8;
    case BytecodeInst<Mode>::Opcode::WIDE_GETMODULENAMESPACE_PREF_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDESTSENDABLEVAR_PREF_IMM16_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16_IMM16;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLRANGE_PREF_IMM16_V8:
        return BytecodeInst<Mode>::Format::PREF_IMM16_V8;
    case BytecodeInst<Mode>::Opcode::WIDE_STMODULEVAR_PREF_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEVAR_PREF_IMM4_IMM4:
        return BytecodeInst<Mode>::Format::PREF_IMM4_IMM4;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLSPREAD_PREF_V8_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_V8_V8_V8;
    case BytecodeInst<Mode>::Opcode::WIDE_LDLOCALMODULEVAR_PREF_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEVAR_PREF_IMM8_IMM8:
        return BytecodeInst<Mode>::Format::PREF_IMM8_IMM8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLTHISRANGE_PREF_IMM16_V8:
        return BytecodeInst<Mode>::Format::PREF_IMM16_V8;
    case BytecodeInst<Mode>::Opcode::WIDE_LDEXTERNALMODULEVAR_PREF_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLEVAR_PREF_IMM16_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16_IMM16;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DEFINECLASSWITHBUFFER_PREF_ID16_IMM16_IMM16_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_ID16_IMM16_IMM16_V8_V8;
    case BytecodeInst<Mode>::Opcode::WIDE_LDPATCHVAR_PREF_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_ISTRUE_PREF_IMM8:
        return BytecodeInst<Mode>::Format::PREF_IMM8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_RESUMEGENERATOR_PREF_V8:
        return BytecodeInst<Mode>::Format::PREF_V8;
    case BytecodeInst<Mode>::Opcode::WIDE_STPATCHVAR_PREF_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_ISFALSE_PREF_IMM8:
        return BytecodeInst<Mode>::Format::PREF_IMM8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETRESUMEMODE_PREF_V8:
        return BytecodeInst<Mode>::Format::PREF_V8;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGEWITHNAME_PREF_IMM16_ID16_V8:
        return BytecodeInst<Mode>::Format::PREF_IMM16_ID16_V8;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDLAZYMODULEVAR_PREF_IMM8:
        return BytecodeInst<Mode>::Format::PREF_IMM8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETTEMPLATEOBJECT_PREF_V8:
        return BytecodeInst<Mode>::Format::PREF_V8;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDLAZYMODULEVAR_PREF_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DELOBJPROP_PREF_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_V8_V8;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDLAZYSENDABLEMODULEVAR_PREF_IMM8:
        return BytecodeInst<Mode>::Format::PREF_IMM8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_SUSPENDGENERATOR_PREF_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_V8_V8;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDLAZYSENDABLEMODULEVAR_PREF_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONAWAITUNCAUGHT_PREF_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_V8_V8;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_SUPERCALLFORWARDALLARGS_PREF_V8:
        return BytecodeInst<Mode>::Format::PREF_V8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_COPYDATAPROPERTIES_PREF_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_V8_V8;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLELOCALMODULEVAR_PREF_IMM8:
        return BytecodeInst<Mode>::Format::PREF_IMM8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_SETOBJECTWITHPROTO_PREF_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_V8_V8;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLELOCALMODULEVAR_PREF_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYVALUE_PREF_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_V8_V8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDSUPERBYVALUE_PREF_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_V8_V8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYINDEX_PREF_V8_IMM32:
        return BytecodeInst<Mode>::Format::PREF_V8_IMM32;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONRESOLVE_PREF_V8_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_V8_V8_V8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONREJECT_PREF_V8_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_V8_V8_V8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM4_IMM4_V8:
        return BytecodeInst<Mode>::Format::PREF_IMM4_IMM4_V8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM8_IMM8_V8:
        return BytecodeInst<Mode>::Format::PREF_IMM8_IMM8_V8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM16_IMM16_V8:
        return BytecodeInst<Mode>::Format::PREF_IMM16_IMM16_V8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETMODULENAMESPACE_PREF_ID32:
        return BytecodeInst<Mode>::Format::PREF_ID32;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STMODULEVAR_PREF_ID32:
        return BytecodeInst<Mode>::Format::PREF_ID32;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYNAME_PREF_ID32_V8:
        return BytecodeInst<Mode>::Format::PREF_ID32_V8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDSUPERBYNAME_PREF_ID32_V8:
        return BytecodeInst<Mode>::Format::PREF_ID32_V8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDMODULEVAR_PREF_ID32_IMM8:
        return BytecodeInst<Mode>::Format::PREF_ID32_IMM8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STCONSTTOGLOBALRECORD_PREF_ID32:
        return BytecodeInst<Mode>::Format::PREF_ID32;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLETTOGLOBALRECORD_PREF_ID32:
        return BytecodeInst<Mode>::Format::PREF_ID32;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STCLASSTOGLOBALRECORD_PREF_ID32:
        return BytecodeInst<Mode>::Format::PREF_ID32;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDHOMEOBJECT_PREF_NONE:
        return BytecodeInst<Mode>::Format::PREF_NONE;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEOBJECTHAVINGMETHOD_PREF_IMM16:
        return BytecodeInst<Mode>::Format::PREF_IMM16;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DYNAMICIMPORT_PREF_V8:
        return BytecodeInst<Mode>::Format::PREF_V8;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCGENERATORREJECT_PREF_V8_V8:
        return BytecodeInst<Mode>::Format::PREF_V8_V8;
    default:
        break;
    }

    UNREACHABLE();
}

// NOLINTNEXTLINE(readability-function-size)
template<const BytecodeInstMode Mode> inline bool BytecodeInst<Mode>::HasFlag(Flags flag) const {
    switch(GetOpcode()) {
    case BytecodeInst<Mode>::Opcode::LDUNDEFINED:
        return ((Flags::NO_SIDE_EFFECT | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDNULL:
        return ((Flags::NO_SIDE_EFFECT | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDTRUE:
        return ((Flags::NO_SIDE_EFFECT | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDFALSE:
        return ((Flags::NO_SIDE_EFFECT | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYOBJECT:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYARRAY_IMM8:
        return ((Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEARRAYWITHBUFFER_IMM8_ID16:
        return ((Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::LITERALARRAY_ID | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHBUFFER_IMM8_ID16:
        return ((Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::LITERALARRAY_ID | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM8_IMM8_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::RANGE_0 | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NEWLEXENV_IMM8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ADD2_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SUB2_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::MUL2_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DIV2_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::MOD2_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::EQ_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NOTEQ_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LESS_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LESSEQ_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GREATER_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GREATEREQ_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SHL2_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SHR2_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ASHR2_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::AND2_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::OR2_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::XOR2_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::EXP_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::TYPEOF_IMM8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::TONUMBER_IMM8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::TONUMERIC_IMM8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NEG_IMM8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NOT_IMM8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::INC_IMM8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEC_IMM8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ISTRUE:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ISFALSE:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ISIN_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::INSTANCEOF_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STRICTNOTEQ_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STRICTEQ_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLARG0_IMM8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLARG1_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLARGS2_IMM8_V8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLARGS3_IMM8_V8_V8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHIS0_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHIS1_IMM8_V8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHIS2_IMM8_V8_V8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHIS3_IMM8_V8_V8_V8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGE_IMM8_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::RANGE_0 | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SUPERCALLTHISRANGE_IMM8_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::RANGE_0 | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEFINEFUNC_IMM8_ID16_IMM8:
        return ((Flags::METHOD_ID | Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEFINEMETHOD_IMM8_ID16_IMM8:
        return ((Flags::METHOD_ID | Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEFINECLASSWITHBUFFER_IMM8_ID16_ID16_IMM16_V8:
        return ((Flags::METHOD_ID | Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::LITERALARRAY_ID | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETNEXTPROPNAME_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDOBJBYVALUE_IMM8_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOBJBYVALUE_IMM8_V8_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDSUPERBYVALUE_IMM8_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDOBJBYINDEX_IMM8_IMM16:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOBJBYINDEX_IMM8_V8_IMM16:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDLEXVAR_IMM4_IMM4:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STLEXVAR_IMM4_IMM4:
        return ((Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDA_STR_ID16:
        return ((Flags::STRING_ID | Flags::LANGUAGE_TYPE | Flags::MAYBE_DYNAMIC | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::TRYLDGLOBALBYNAME_IMM8_ID16:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::TRYSTGLOBALBYNAME_IMM8_ID16:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDGLOBALVAR_IMM16_ID16:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::ONE_SLOT | Flags::SIXTEEN_BIT_IC | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDOBJBYNAME_IMM8_ID16:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOBJBYNAME_IMM8_ID16_V8:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::MOV_V4_V4:
        return ((Flags::DYNAMIC | Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::MOV_V8_V8:
        return ((Flags::DYNAMIC | Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDSUPERBYNAME_IMM8_ID16:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STCONSTTOGLOBALRECORD_IMM16_ID16:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::ONE_SLOT | Flags::SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STTOGLOBALRECORD_IMM16_ID16:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::ONE_SLOT | Flags::SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDTHISBYNAME_IMM8_ID16:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STTHISBYNAME_IMM8_ID16:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDTHISBYVALUE_IMM8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STTHISBYVALUE_IMM8_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JMP_IMM8:
        return ((Flags::JUMP | Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JMP_IMM16:
        return ((Flags::JUMP | Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM8:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM16:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM8:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM8:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM8:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM8:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM8:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM8:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM8:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM8:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM8:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM8:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM8:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM8:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM8:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM8:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM8:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDA_V8:
        return ((Flags::DYNAMIC | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STA_V8:
        return ((Flags::DYNAMIC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDAI_IMM32:
        return ((Flags::DYNAMIC | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::FLDAI_IMM64:
        return ((Flags::DYNAMIC | Flags::FLOAT | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::RETURN:
        return ((Flags::DYNAMIC | Flags::RETURN | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::RETURNUNDEFINED:
        return ((Flags::DYNAMIC | Flags::RETURN | Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETPROPITERATOR:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETITERATOR_IMM8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CLOSEITERATOR_IMM8_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::POPLEXENV:
        return ((Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDNAN:
        return ((Flags::NO_SIDE_EFFECT | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDINFINITY:
        return ((Flags::NO_SIDE_EFFECT | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETUNMAPPEDARGS:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDGLOBAL:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDNEWTARGET:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDTHIS:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDHOLE:
        return ((Flags::NO_SIDE_EFFECT | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEREGEXPWITHLITERAL_IMM8_ID16_IMM8:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEREGEXPWITHLITERAL_IMM16_ID16_IMM8:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRANGE_IMM8_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::RANGE_0 | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEFINEFUNC_IMM16_ID16_IMM8:
        return ((Flags::METHOD_ID | Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEFINECLASSWITHBUFFER_IMM16_ID16_ID16_IMM16_V8:
        return ((Flags::METHOD_ID | Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::LITERALARRAY_ID | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETTEMPLATEOBJECT_IMM8:
        return ((Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SETOBJECTWITHPROTO_IMM8_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUE_IMM8_V8_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYINDEX_IMM8_V8_IMM16:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYNAME_IMM8_ID16_V8:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETMODULENAMESPACE_IMM8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STMODULEVAR_IMM8:
        return ((Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDLOCALMODULEVAR_IMM8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDEXTERNALMODULEVAR_IMM8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STGLOBALVAR_IMM16_ID16:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::ONE_SLOT | Flags::SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYARRAY_IMM16:
        return ((Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEARRAYWITHBUFFER_IMM16_ID16:
        return ((Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::LITERALARRAY_ID | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHBUFFER_IMM16_ID16:
        return ((Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::LITERALARRAY_ID | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM16_IMM8_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::RANGE_0 | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::TYPEOF_IMM16:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDOBJBYVALUE_IMM16_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOBJBYVALUE_IMM16_V8_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDSUPERBYVALUE_IMM16_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDOBJBYINDEX_IMM16_IMM16:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOBJBYINDEX_IMM16_V8_IMM16:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDLEXVAR_IMM8_IMM8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STLEXVAR_IMM8_IMM8:
        return ((Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::TRYLDGLOBALBYNAME_IMM16_ID16:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::TRYSTGLOBALBYNAME_IMM16_ID16:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYNAMEWITHNAMESET_IMM8_ID16_V8:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::MOV_V16_V16:
        return ((Flags::DYNAMIC | Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDOBJBYNAME_IMM16_ID16:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOBJBYNAME_IMM16_ID16_V8:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDSUPERBYNAME_IMM16_ID16:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDTHISBYNAME_IMM16_ID16:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STTHISBYNAME_IMM16_ID16:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDTHISBYVALUE_IMM16:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STTHISBYVALUE_IMM16_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ASYNCGENERATORREJECT_V8:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JMP_IMM32:
        return ((Flags::JUMP | Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUEWITHNAMESET_IMM8_V8_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM32:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM16:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM32:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM16:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM16:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM16:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM16:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM16:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM16:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM16:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM16:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM16:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM16:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM16:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM16:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM16:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM16:
        return ((Flags::JUMP | Flags::CONDITIONAL | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETITERATOR_IMM16:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CLOSEITERATOR_IMM16_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDSYMBOL:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONENTER:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDFUNCTION:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEBUGGER:
        return ((Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEGENERATOROBJ_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEITERRESULTOBJ_V8_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHEXCLUDEDKEYS_IMM8_V8_V8:
        return ((Flags::RANGE_1 | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NEWOBJAPPLY_IMM8_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NEWOBJAPPLY_IMM16_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NEWLEXENVWITHNAME_IMM8_ID16:
        return ((Flags::LITERALARRAY_ID | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEASYNCGENERATOROBJ_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ASYNCGENERATORRESOLVE_V8_V8_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SUPERCALLSPREAD_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::APPLY_IMM8_V8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SUPERCALLARROWRANGE_IMM8_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::RANGE_0 | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEFINEGETTERSETTERBYVALUE_V8_V8_V8_V8:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DYNAMICIMPORT:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEFINEMETHOD_IMM16_ID16_IMM8:
        return ((Flags::METHOD_ID | Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::RESUMEGENERATOR:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETRESUMEMODE:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETTEMPLATEOBJECT_IMM16:
        return ((Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DELOBJPROP_V8:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SUSPENDGENERATOR_V8:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONAWAITUNCAUGHT_V8:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::COPYDATAPROPERTIES_V8:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STARRAYSPREAD_V8_V8:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SETOBJECTWITHPROTO_IMM16_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUE_IMM16_V8_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STSUPERBYVALUE_IMM8_V8_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STSUPERBYVALUE_IMM16_V8_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYINDEX_IMM16_V8_IMM16:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYNAME_IMM16_ID16_V8:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONRESOLVE_V8:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONREJECT_V8:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::COPYRESTARGS_IMM8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STSUPERBYNAME_IMM8_ID16_V8:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STSUPERBYNAME_IMM16_ID16_V8:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUEWITHNAMESET_IMM16_V8_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDBIGINT_ID16:
        return ((Flags::STRING_ID | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYNAMEWITHNAMESET_IMM16_ID16_V8:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_SIXTEEN_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NOP:
        return ((Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SETGENERATORSTATE_IMM8:
        return ((Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETASYNCITERATOR_IMM8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDPRIVATEPROPERTY_IMM8_IMM16_IMM16:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STPRIVATEPROPERTY_IMM8_IMM16_IMM16_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::TESTIN_IMM8_IMM16_IMM16:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEFINEFIELDBYNAME_IMM8_ID16_V8:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEFINEPROPERTYBYNAME_IMM8_ID16_V8:
        return ((Flags::STRING_ID | Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHIS0WITHNAME_IMM8_ID16_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::STRING_ID | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHIS1WITHNAME_IMM8_ID16_V8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::STRING_ID | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHIS2WITHNAME_IMM8_ID16_V8_V8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::STRING_ID | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHIS3WITHNAME_IMM8_ID16_V8_V8_V8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::STRING_ID | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGEWITHNAME_IMM8_IMM8_ID16_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::RANGE_0 | Flags::STRING_ID | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_NOTIFYCONCURRENTRESULT_PREF_NONE:
        return ((Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDLEXENV_PREF_NONE:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_CREATEOBJECTWITHEXCLUDEDKEYS_PREF_IMM16_V8_V8:
        return ((Flags::RANGE_1 | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_PREF_NONE:
        return ((Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEFIELDBYVALUE_PREF_IMM8_V8_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_POPLEXENV_PREF_NONE:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_NEWOBJRANGE_PREF_IMM16_V8:
        return ((Flags::RANGE_0 | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_NOTEXISTS_PREF_NONE:
        return ((Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEFIELDBYINDEX_PREF_IMM8_IMM32_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETITERATORNEXT_PREF_V8_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_NEWLEXENV_PREF_IMM16:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_PATTERNNONCOERCIBLE_PREF_NONE:
        return ((Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_TOPROPERTYKEY_PREF_NONE:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEARRAYWITHBUFFER_PREF_IMM16:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_NEWLEXENVWITHNAME_PREF_IMM16_ID16:
        return ((Flags::LITERALARRAY_ID | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_DELETESUPERPROPERTY_PREF_NONE:
        return ((Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_CREATEPRIVATEPROPERTY_PREF_IMM16_ID16:
        return ((Flags::LITERALARRAY_ID | Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEOBJECTWITHBUFFER_PREF_IMM16:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_CALLRANGE_PREF_IMM16_V8:
        return ((Flags::RANGE_0 | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_CONSTASSIGNMENT_PREF_V8:
        return ((Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEPRIVATEPROPERTY_PREF_IMM8_IMM16_IMM16_V8:
        return ((Flags::IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_TONUMBER_PREF_V8:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGE_PREF_IMM16_V8:
        return ((Flags::RANGE_1 | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_IFNOTOBJECT_PREF_V8:
        return ((Flags::CONDITIONAL_THROW | Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_CALLINIT_PREF_IMM8_V8:
        return ((Flags::JIT_IC_SLOT | Flags::TWO_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_TONUMERIC_PREF_V8:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLTHISRANGE_PREF_IMM16_V8:
        return ((Flags::RANGE_0 | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_UNDEFINEDIFHOLE_PREF_V8_V8:
        return ((Flags::CONDITIONAL_THROW | Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINESENDABLECLASS_PREF_IMM16_ID16_ID16_IMM16_V8:
        return ((Flags::METHOD_ID | Flags::IC_SLOT | Flags::ONE_SLOT | Flags::SIXTEEN_BIT_IC | Flags::LITERALARRAY_ID | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_NEG_PREF_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLARROWRANGE_PREF_IMM16_V8:
        return ((Flags::RANGE_0 | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_IFSUPERNOTCORRECTCALL_PREF_IMM8:
        return ((Flags::CONDITIONAL_THROW | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLECLASS_PREF_IMM16:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_NOT_PREF_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_LDOBJBYINDEX_PREF_IMM32:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_IFSUPERNOTCORRECTCALL_PREF_IMM16:
        return ((Flags::CONDITIONAL_THROW | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEEXTERNALMODULEVAR_PREF_IMM8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_INC_PREF_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_STOBJBYINDEX_PREF_V8_IMM32:
        return ((Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_UNDEFINEDIFHOLEWITHNAME_PREF_ID16:
        return ((Flags::STRING_ID | Flags::CONDITIONAL_THROW | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLEEXTERNALMODULEVAR_PREF_IMM16:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DEC_PREF_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_STOWNBYINDEX_PREF_V8_IMM32:
        return ((Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_NEWSENDABLEENV_PREF_IMM8:
        return ((Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARG0_PREF_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_COPYRESTARGS_PREF_IMM16:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDENEWSENDABLEENV_PREF_IMM16:
        return ((Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARG1_PREF_V8_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_LDLEXVAR_PREF_IMM16_IMM16:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_STSENDABLEVAR_PREF_IMM4_IMM4:
        return ((Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARGS2_PREF_V8_V8_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_STLEXVAR_PREF_IMM16_IMM16:
        return ((Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_STSENDABLEVAR_PREF_IMM8_IMM8:
        return ((Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARGS3_PREF_V8_V8_V8_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_GETMODULENAMESPACE_PREF_IMM16:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDESTSENDABLEVAR_PREF_IMM16_IMM16:
        return ((Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLRANGE_PREF_IMM16_V8:
        return ((Flags::RANGE_0 | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_STMODULEVAR_PREF_IMM16:
        return ((Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEVAR_PREF_IMM4_IMM4:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLSPREAD_PREF_V8_V8_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_LDLOCALMODULEVAR_PREF_IMM16:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEVAR_PREF_IMM8_IMM8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLTHISRANGE_PREF_IMM16_V8:
        return ((Flags::RANGE_1 | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_LDEXTERNALMODULEVAR_PREF_IMM16:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLEVAR_PREF_IMM16_IMM16:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DEFINECLASSWITHBUFFER_PREF_ID16_IMM16_IMM16_V8_V8:
        return ((Flags::METHOD_ID | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_LDPATCHVAR_PREF_IMM16:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_ISTRUE_PREF_IMM8:
        return ((Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_RESUMEGENERATOR_PREF_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_STPATCHVAR_PREF_IMM16:
        return ((Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_ISFALSE_PREF_IMM8:
        return ((Flags::IC_SLOT | Flags::ONE_SLOT | Flags::EIGHT_BIT_IC | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETRESUMEMODE_PREF_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGEWITHNAME_PREF_IMM16_ID16_V8:
        return ((Flags::RANGE_1 | Flags::STRING_ID | Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDLAZYMODULEVAR_PREF_IMM8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETTEMPLATEOBJECT_PREF_V8:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDLAZYMODULEVAR_PREF_IMM16:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DELOBJPROP_PREF_V8_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDLAZYSENDABLEMODULEVAR_PREF_IMM8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_SUSPENDGENERATOR_PREF_V8_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDLAZYSENDABLEMODULEVAR_PREF_IMM16:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONAWAITUNCAUGHT_PREF_V8_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_SUPERCALLFORWARDALLARGS_PREF_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_COPYDATAPROPERTIES_PREF_V8_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLELOCALMODULEVAR_PREF_IMM8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_SETOBJECTWITHPROTO_PREF_V8_V8:
        return ((Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLELOCALMODULEVAR_PREF_IMM16:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYVALUE_PREF_V8_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDSUPERBYVALUE_PREF_V8_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYINDEX_PREF_V8_IMM32:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONRESOLVE_PREF_V8_V8_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONREJECT_PREF_V8_V8_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM4_IMM4_V8:
        return ((Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM8_IMM8_V8:
        return ((Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM16_IMM16_V8:
        return ((Flags::ACC_NONE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETMODULENAMESPACE_PREF_ID32:
        return ((Flags::STRING_ID | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STMODULEVAR_PREF_ID32:
        return ((Flags::STRING_ID | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYNAME_PREF_ID32_V8:
        return ((Flags::STRING_ID | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDSUPERBYNAME_PREF_ID32_V8:
        return ((Flags::STRING_ID | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDMODULEVAR_PREF_ID32_IMM8:
        return ((Flags::STRING_ID | Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STCONSTTOGLOBALRECORD_PREF_ID32:
        return ((Flags::STRING_ID | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLETTOGLOBALRECORD_PREF_ID32:
        return ((Flags::STRING_ID | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STCLASSTOGLOBALRECORD_PREF_ID32:
        return ((Flags::STRING_ID | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDHOMEOBJECT_PREF_NONE:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEOBJECTHAVINGMETHOD_PREF_IMM16:
        return ((Flags::ACC_WRITE | Flags::ACC_READ) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DYNAMICIMPORT_PREF_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCGENERATORREJECT_PREF_V8_V8:
        return ((Flags::ACC_WRITE) & flag) == flag;  // NOLINT(hicpp-signed-bitwise)
    default:
        return false;
    }

    UNREACHABLE();
}

// NOLINTNEXTLINE(readability-function-size)
template<const BytecodeInstMode Mode> inline bool BytecodeInst<Mode>::IsIdMatchFlag(size_t idx, Flags flag) const {
    switch(GetOpcode()) {
    case BytecodeInst<Mode>::Opcode::LDUNDEFINED: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDNULL: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDTRUE: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDFALSE: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYOBJECT: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYARRAY_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CREATEARRAYWITHBUFFER_IMM8_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::LITERALARRAY_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHBUFFER_IMM8_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::LITERALARRAY_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM8_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::NEWLEXENV_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::ADD2_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::SUB2_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::MUL2_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DIV2_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::MOD2_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::EQ_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::NOTEQ_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LESS_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LESSEQ_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::GREATER_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::GREATEREQ_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::SHL2_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::SHR2_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::ASHR2_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::AND2_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::OR2_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::XOR2_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::EXP_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::TYPEOF_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::TONUMBER_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::TONUMERIC_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::NEG_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::NOT_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::INC_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEC_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::ISTRUE: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::ISFALSE: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::ISIN_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::INSTANCEOF_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STRICTNOTEQ_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STRICTEQ_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLARG0_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLARG1_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLARGS2_IMM8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLARGS3_IMM8_V8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLTHIS0_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLTHIS1_IMM8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLTHIS2_IMM8_V8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLTHIS3_IMM8_V8_V8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGE_IMM8_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::SUPERCALLTHISRANGE_IMM8_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEFINEFUNC_IMM8_ID16_IMM8: {
        constexpr std::array<Flags, 1> ids_array { Flags::METHOD_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::DEFINEMETHOD_IMM8_ID16_IMM8: {
        constexpr std::array<Flags, 1> ids_array { Flags::METHOD_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::DEFINECLASSWITHBUFFER_IMM8_ID16_ID16_IMM16_V8: {
        constexpr std::array<Flags, 2> ids_array { Flags::METHOD_ID, Flags::LITERALARRAY_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::GETNEXTPROPNAME_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDOBJBYVALUE_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STOBJBYVALUE_IMM8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDSUPERBYVALUE_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDOBJBYINDEX_IMM8_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STOBJBYINDEX_IMM8_V8_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDLEXVAR_IMM4_IMM4: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STLEXVAR_IMM4_IMM4: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDA_STR_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::TRYLDGLOBALBYNAME_IMM8_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::TRYSTGLOBALBYNAME_IMM8_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::LDGLOBALVAR_IMM16_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::LDOBJBYNAME_IMM8_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::STOBJBYNAME_IMM8_ID16_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::MOV_V4_V4: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::MOV_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDSUPERBYNAME_IMM8_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::STCONSTTOGLOBALRECORD_IMM16_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::STTOGLOBALRECORD_IMM16_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::LDTHISBYNAME_IMM8_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::STTHISBYNAME_IMM8_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::LDTHISBYVALUE_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STTHISBYVALUE_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JMP_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JMP_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDA_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STA_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDAI_IMM32: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::FLDAI_IMM64: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::RETURN: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::RETURNUNDEFINED: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::GETPROPITERATOR: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::GETITERATOR_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CLOSEITERATOR_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::POPLEXENV: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDNAN: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDINFINITY: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::GETUNMAPPEDARGS: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDGLOBAL: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDNEWTARGET: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDTHIS: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDHOLE: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CREATEREGEXPWITHLITERAL_IMM8_ID16_IMM8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::CREATEREGEXPWITHLITERAL_IMM16_ID16_IMM8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::CALLRANGE_IMM8_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEFINEFUNC_IMM16_ID16_IMM8: {
        constexpr std::array<Flags, 1> ids_array { Flags::METHOD_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::DEFINECLASSWITHBUFFER_IMM16_ID16_ID16_IMM16_V8: {
        constexpr std::array<Flags, 2> ids_array { Flags::METHOD_ID, Flags::LITERALARRAY_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::GETTEMPLATEOBJECT_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::SETOBJECTWITHPROTO_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUE_IMM8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STOWNBYINDEX_IMM8_V8_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STOWNBYNAME_IMM8_ID16_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::GETMODULENAMESPACE_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STMODULEVAR_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDLOCALMODULEVAR_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDEXTERNALMODULEVAR_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STGLOBALVAR_IMM16_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYARRAY_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CREATEARRAYWITHBUFFER_IMM16_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::LITERALARRAY_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHBUFFER_IMM16_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::LITERALARRAY_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM16_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::TYPEOF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDOBJBYVALUE_IMM16_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STOBJBYVALUE_IMM16_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDSUPERBYVALUE_IMM16_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDOBJBYINDEX_IMM16_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STOBJBYINDEX_IMM16_V8_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDLEXVAR_IMM8_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STLEXVAR_IMM8_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::TRYLDGLOBALBYNAME_IMM16_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::TRYSTGLOBALBYNAME_IMM16_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::STOWNBYNAMEWITHNAMESET_IMM8_ID16_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::MOV_V16_V16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDOBJBYNAME_IMM16_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::STOBJBYNAME_IMM16_ID16_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::LDSUPERBYNAME_IMM16_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::LDTHISBYNAME_IMM16_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::STTHISBYNAME_IMM16_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::LDTHISBYVALUE_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STTHISBYVALUE_IMM16_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::ASYNCGENERATORREJECT_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JMP_IMM32: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUEWITHNAMESET_IMM8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM32: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM32: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::GETITERATOR_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CLOSEITERATOR_IMM16_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDSYMBOL: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONENTER: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDFUNCTION: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEBUGGER: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CREATEGENERATOROBJ_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CREATEITERRESULTOBJ_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHEXCLUDEDKEYS_IMM8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::NEWOBJAPPLY_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::NEWOBJAPPLY_IMM16_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::NEWLEXENVWITHNAME_IMM8_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::LITERALARRAY_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::CREATEASYNCGENERATOROBJ_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::ASYNCGENERATORRESOLVE_V8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::SUPERCALLSPREAD_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::APPLY_IMM8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::SUPERCALLARROWRANGE_IMM8_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEFINEGETTERSETTERBYVALUE_V8_V8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DYNAMICIMPORT: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEFINEMETHOD_IMM16_ID16_IMM8: {
        constexpr std::array<Flags, 1> ids_array { Flags::METHOD_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::RESUMEGENERATOR: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::GETRESUMEMODE: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::GETTEMPLATEOBJECT_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DELOBJPROP_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::SUSPENDGENERATOR_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONAWAITUNCAUGHT_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::COPYDATAPROPERTIES_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STARRAYSPREAD_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::SETOBJECTWITHPROTO_IMM16_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUE_IMM16_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STSUPERBYVALUE_IMM8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STSUPERBYVALUE_IMM16_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STOWNBYINDEX_IMM16_V8_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STOWNBYNAME_IMM16_ID16_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONRESOLVE_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONREJECT_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::COPYRESTARGS_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STSUPERBYNAME_IMM8_ID16_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::STSUPERBYNAME_IMM16_ID16_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUEWITHNAMESET_IMM16_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDBIGINT_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::STOWNBYNAMEWITHNAMESET_IMM16_ID16_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::NOP: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::SETGENERATORSTATE_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::GETASYNCITERATOR_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::LDPRIVATEPROPERTY_IMM8_IMM16_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::STPRIVATEPROPERTY_IMM8_IMM16_IMM16_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::TESTIN_IMM8_IMM16_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEFINEFIELDBYNAME_IMM8_ID16_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::DEFINEPROPERTYBYNAME_IMM8_ID16_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::CALLTHIS0WITHNAME_IMM8_ID16_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::CALLTHIS1WITHNAME_IMM8_ID16_V8_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::CALLTHIS2WITHNAME_IMM8_ID16_V8_V8_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::CALLTHIS3WITHNAME_IMM8_ID16_V8_V8_V8_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGEWITHNAME_IMM8_IMM8_ID16_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_NOTIFYCONCURRENTRESULT_PREF_NONE: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDLEXENV_PREF_NONE: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_CREATEOBJECTWITHEXCLUDEDKEYS_PREF_IMM16_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::THROW_PREF_NONE: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEFIELDBYVALUE_PREF_IMM8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_POPLEXENV_PREF_NONE: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_NEWOBJRANGE_PREF_IMM16_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::THROW_NOTEXISTS_PREF_NONE: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEFIELDBYINDEX_PREF_IMM8_IMM32_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETITERATORNEXT_PREF_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_NEWLEXENV_PREF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::THROW_PATTERNNONCOERCIBLE_PREF_NONE: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_TOPROPERTYKEY_PREF_NONE: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEARRAYWITHBUFFER_PREF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_NEWLEXENVWITHNAME_PREF_IMM16_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::LITERALARRAY_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::THROW_DELETESUPERPROPERTY_PREF_NONE: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_CREATEPRIVATEPROPERTY_PREF_IMM16_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::LITERALARRAY_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEOBJECTWITHBUFFER_PREF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_CALLRANGE_PREF_IMM16_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::THROW_CONSTASSIGNMENT_PREF_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEPRIVATEPROPERTY_PREF_IMM8_IMM16_IMM16_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_TONUMBER_PREF_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGE_PREF_IMM16_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::THROW_IFNOTOBJECT_PREF_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_CALLINIT_PREF_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_TONUMERIC_PREF_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLTHISRANGE_PREF_IMM16_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::THROW_UNDEFINEDIFHOLE_PREF_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINESENDABLECLASS_PREF_IMM16_ID16_ID16_IMM16_V8: {
        constexpr std::array<Flags, 2> ids_array { Flags::METHOD_ID, Flags::LITERALARRAY_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_NEG_PREF_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLARROWRANGE_PREF_IMM16_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::THROW_IFSUPERNOTCORRECTCALL_PREF_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLECLASS_PREF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_NOT_PREF_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_LDOBJBYINDEX_PREF_IMM32: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::THROW_IFSUPERNOTCORRECTCALL_PREF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEEXTERNALMODULEVAR_PREF_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_INC_PREF_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_STOBJBYINDEX_PREF_V8_IMM32: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::THROW_UNDEFINEDIFHOLEWITHNAME_PREF_ID16: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLEEXTERNALMODULEVAR_PREF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DEC_PREF_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_STOWNBYINDEX_PREF_V8_IMM32: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_NEWSENDABLEENV_PREF_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARG0_PREF_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_COPYRESTARGS_PREF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDENEWSENDABLEENV_PREF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARG1_PREF_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_LDLEXVAR_PREF_IMM16_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_STSENDABLEVAR_PREF_IMM4_IMM4: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARGS2_PREF_V8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_STLEXVAR_PREF_IMM16_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_STSENDABLEVAR_PREF_IMM8_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARGS3_PREF_V8_V8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_GETMODULENAMESPACE_PREF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDESTSENDABLEVAR_PREF_IMM16_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLRANGE_PREF_IMM16_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_STMODULEVAR_PREF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEVAR_PREF_IMM4_IMM4: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLSPREAD_PREF_V8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_LDLOCALMODULEVAR_PREF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEVAR_PREF_IMM8_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLTHISRANGE_PREF_IMM16_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_LDEXTERNALMODULEVAR_PREF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLEVAR_PREF_IMM16_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DEFINECLASSWITHBUFFER_PREF_ID16_IMM16_IMM16_V8_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::METHOD_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_LDPATCHVAR_PREF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_ISTRUE_PREF_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_RESUMEGENERATOR_PREF_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_STPATCHVAR_PREF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_ISFALSE_PREF_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETRESUMEMODE_PREF_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGEWITHNAME_PREF_IMM16_ID16_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDLAZYMODULEVAR_PREF_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETTEMPLATEOBJECT_PREF_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDLAZYMODULEVAR_PREF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DELOBJPROP_PREF_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDLAZYSENDABLEMODULEVAR_PREF_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_SUSPENDGENERATOR_PREF_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDLAZYSENDABLEMODULEVAR_PREF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONAWAITUNCAUGHT_PREF_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_SUPERCALLFORWARDALLARGS_PREF_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_COPYDATAPROPERTIES_PREF_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLELOCALMODULEVAR_PREF_IMM8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_SETOBJECTWITHPROTO_PREF_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLELOCALMODULEVAR_PREF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYVALUE_PREF_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDSUPERBYVALUE_PREF_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYINDEX_PREF_V8_IMM32: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONRESOLVE_PREF_V8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONREJECT_PREF_V8_V8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM4_IMM4_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM8_IMM8_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM16_IMM16_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETMODULENAMESPACE_PREF_ID32: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STMODULEVAR_PREF_ID32: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYNAME_PREF_ID32_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDSUPERBYNAME_PREF_ID32_V8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDMODULEVAR_PREF_ID32_IMM8: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STCONSTTOGLOBALRECORD_PREF_ID32: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLETTOGLOBALRECORD_PREF_ID32: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STCLASSTOGLOBALRECORD_PREF_ID32: {
        constexpr std::array<Flags, 1> ids_array { Flags::STRING_ID };
        return ids_array[idx] == flag;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDHOMEOBJECT_PREF_NONE: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEOBJECTHAVINGMETHOD_PREF_IMM16: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DYNAMICIMPORT_PREF_V8: {
        return false;
    }
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCGENERATORREJECT_PREF_V8_V8: {
        return false;
    }
    default:
        return false;
    }
}

// NOLINTNEXTLINE(readability-function-size)
template<const BytecodeInstMode Mode> inline bool BytecodeInst<Mode>::IsThrow(Exceptions exception) const {
    switch(GetOpcode()) {
    case BytecodeInst<Mode>::Opcode::LDUNDEFINED:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDNULL:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDTRUE:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDFALSE:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYOBJECT:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYARRAY_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEARRAYWITHBUFFER_IMM8_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHBUFFER_IMM8_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM8_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NEWLEXENV_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ADD2_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SUB2_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::MUL2_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DIV2_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::MOD2_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::EQ_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NOTEQ_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LESS_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LESSEQ_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GREATER_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GREATEREQ_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SHL2_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SHR2_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ASHR2_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::AND2_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::OR2_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::XOR2_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::EXP_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::TYPEOF_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::TONUMBER_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::TONUMERIC_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NEG_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NOT_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::INC_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEC_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ISTRUE:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ISFALSE:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ISIN_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::INSTANCEOF_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STRICTNOTEQ_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STRICTEQ_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLARG0_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLARG1_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLARGS2_IMM8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLARGS3_IMM8_V8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHIS0_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHIS1_IMM8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHIS2_IMM8_V8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHIS3_IMM8_V8_V8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGE_IMM8_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SUPERCALLTHISRANGE_IMM8_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEFINEFUNC_IMM8_ID16_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEFINEMETHOD_IMM8_ID16_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEFINECLASSWITHBUFFER_IMM8_ID16_ID16_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETNEXTPROPNAME_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDOBJBYVALUE_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOBJBYVALUE_IMM8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDSUPERBYVALUE_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDOBJBYINDEX_IMM8_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOBJBYINDEX_IMM8_V8_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDLEXVAR_IMM4_IMM4:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STLEXVAR_IMM4_IMM4:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDA_STR_ID16:
        return ((Exceptions::X_OOM) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::TRYLDGLOBALBYNAME_IMM8_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::TRYSTGLOBALBYNAME_IMM8_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDGLOBALVAR_IMM16_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDOBJBYNAME_IMM8_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOBJBYNAME_IMM8_ID16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::MOV_V4_V4:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::MOV_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDSUPERBYNAME_IMM8_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STCONSTTOGLOBALRECORD_IMM16_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STTOGLOBALRECORD_IMM16_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDTHISBYNAME_IMM8_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STTHISBYNAME_IMM8_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDTHISBYVALUE_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STTHISBYVALUE_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JMP_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JMP_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDA_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STA_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDAI_IMM32:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::FLDAI_IMM64:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::RETURN:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::RETURNUNDEFINED:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETPROPITERATOR:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETITERATOR_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CLOSEITERATOR_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::POPLEXENV:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDNAN:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDINFINITY:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETUNMAPPEDARGS:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDGLOBAL:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDNEWTARGET:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDTHIS:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDHOLE:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEREGEXPWITHLITERAL_IMM8_ID16_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEREGEXPWITHLITERAL_IMM16_ID16_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRANGE_IMM8_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEFINEFUNC_IMM16_ID16_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEFINECLASSWITHBUFFER_IMM16_ID16_ID16_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETTEMPLATEOBJECT_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SETOBJECTWITHPROTO_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUE_IMM8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYINDEX_IMM8_V8_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYNAME_IMM8_ID16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETMODULENAMESPACE_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STMODULEVAR_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDLOCALMODULEVAR_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDEXTERNALMODULEVAR_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STGLOBALVAR_IMM16_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYARRAY_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEARRAYWITHBUFFER_IMM16_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHBUFFER_IMM16_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM16_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::TYPEOF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDOBJBYVALUE_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOBJBYVALUE_IMM16_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDSUPERBYVALUE_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDOBJBYINDEX_IMM16_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOBJBYINDEX_IMM16_V8_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDLEXVAR_IMM8_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STLEXVAR_IMM8_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::TRYLDGLOBALBYNAME_IMM16_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::TRYSTGLOBALBYNAME_IMM16_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYNAMEWITHNAMESET_IMM8_ID16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::MOV_V16_V16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDOBJBYNAME_IMM16_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOBJBYNAME_IMM16_ID16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDSUPERBYNAME_IMM16_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDTHISBYNAME_IMM16_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STTHISBYNAME_IMM16_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDTHISBYVALUE_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STTHISBYVALUE_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ASYNCGENERATORREJECT_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JMP_IMM32:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUEWITHNAMESET_IMM8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM32:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM32:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETITERATOR_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CLOSEITERATOR_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDSYMBOL:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONENTER:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDFUNCTION:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEBUGGER:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEGENERATOROBJ_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEITERRESULTOBJ_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHEXCLUDEDKEYS_IMM8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NEWOBJAPPLY_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NEWOBJAPPLY_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NEWLEXENVWITHNAME_IMM8_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CREATEASYNCGENERATOROBJ_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ASYNCGENERATORRESOLVE_V8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SUPERCALLSPREAD_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::APPLY_IMM8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SUPERCALLARROWRANGE_IMM8_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEFINEGETTERSETTERBYVALUE_V8_V8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DYNAMICIMPORT:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEFINEMETHOD_IMM16_ID16_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::RESUMEGENERATOR:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETRESUMEMODE:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETTEMPLATEOBJECT_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DELOBJPROP_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SUSPENDGENERATOR_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONAWAITUNCAUGHT_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::COPYDATAPROPERTIES_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STARRAYSPREAD_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SETOBJECTWITHPROTO_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUE_IMM16_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STSUPERBYVALUE_IMM8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STSUPERBYVALUE_IMM16_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYINDEX_IMM16_V8_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYNAME_IMM16_ID16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONRESOLVE_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONREJECT_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::COPYRESTARGS_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STSUPERBYNAME_IMM8_ID16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STSUPERBYNAME_IMM16_ID16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUEWITHNAMESET_IMM16_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDBIGINT_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STOWNBYNAMEWITHNAMESET_IMM16_ID16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::NOP:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::SETGENERATORSTATE_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::GETASYNCITERATOR_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::LDPRIVATEPROPERTY_IMM8_IMM16_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::STPRIVATEPROPERTY_IMM8_IMM16_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::TESTIN_IMM8_IMM16_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEFINEFIELDBYNAME_IMM8_ID16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEFINEPROPERTYBYNAME_IMM8_ID16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHIS0WITHNAME_IMM8_ID16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHIS1WITHNAME_IMM8_ID16_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHIS2WITHNAME_IMM8_ID16_V8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHIS3WITHNAME_IMM8_ID16_V8_V8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGEWITHNAME_IMM8_IMM8_ID16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_NOTIFYCONCURRENTRESULT_PREF_NONE:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDLEXENV_PREF_NONE:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_CREATEOBJECTWITHEXCLUDEDKEYS_PREF_IMM16_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_PREF_NONE:
        return ((Exceptions::X_NONE | Exceptions::X_THROW) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEFIELDBYVALUE_PREF_IMM8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_POPLEXENV_PREF_NONE:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_NEWOBJRANGE_PREF_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_NOTEXISTS_PREF_NONE:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEFIELDBYINDEX_PREF_IMM8_IMM32_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETITERATORNEXT_PREF_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_NEWLEXENV_PREF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_PATTERNNONCOERCIBLE_PREF_NONE:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_TOPROPERTYKEY_PREF_NONE:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEARRAYWITHBUFFER_PREF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_NEWLEXENVWITHNAME_PREF_IMM16_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_DELETESUPERPROPERTY_PREF_NONE:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_CREATEPRIVATEPROPERTY_PREF_IMM16_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEOBJECTWITHBUFFER_PREF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_CALLRANGE_PREF_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_CONSTASSIGNMENT_PREF_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEPRIVATEPROPERTY_PREF_IMM8_IMM16_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_TONUMBER_PREF_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGE_PREF_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_IFNOTOBJECT_PREF_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_CALLINIT_PREF_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_TONUMERIC_PREF_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLTHISRANGE_PREF_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_UNDEFINEDIFHOLE_PREF_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINESENDABLECLASS_PREF_IMM16_ID16_ID16_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_NEG_PREF_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLARROWRANGE_PREF_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_IFSUPERNOTCORRECTCALL_PREF_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLECLASS_PREF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_NOT_PREF_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_LDOBJBYINDEX_PREF_IMM32:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_IFSUPERNOTCORRECTCALL_PREF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEEXTERNALMODULEVAR_PREF_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_INC_PREF_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_STOBJBYINDEX_PREF_V8_IMM32:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::THROW_UNDEFINEDIFHOLEWITHNAME_PREF_ID16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLEEXTERNALMODULEVAR_PREF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DEC_PREF_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_STOWNBYINDEX_PREF_V8_IMM32:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_NEWSENDABLEENV_PREF_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARG0_PREF_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_COPYRESTARGS_PREF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDENEWSENDABLEENV_PREF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARG1_PREF_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_LDLEXVAR_PREF_IMM16_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_STSENDABLEVAR_PREF_IMM4_IMM4:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARGS2_PREF_V8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_STLEXVAR_PREF_IMM16_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_STSENDABLEVAR_PREF_IMM8_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARGS3_PREF_V8_V8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_GETMODULENAMESPACE_PREF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDESTSENDABLEVAR_PREF_IMM16_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLRANGE_PREF_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_STMODULEVAR_PREF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEVAR_PREF_IMM4_IMM4:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLSPREAD_PREF_V8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_LDLOCALMODULEVAR_PREF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEVAR_PREF_IMM8_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLTHISRANGE_PREF_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_LDEXTERNALMODULEVAR_PREF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLEVAR_PREF_IMM16_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DEFINECLASSWITHBUFFER_PREF_ID16_IMM16_IMM16_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_LDPATCHVAR_PREF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_ISTRUE_PREF_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_RESUMEGENERATOR_PREF_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_STPATCHVAR_PREF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_ISFALSE_PREF_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETRESUMEMODE_PREF_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGEWITHNAME_PREF_IMM16_ID16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDLAZYMODULEVAR_PREF_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETTEMPLATEOBJECT_PREF_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDLAZYMODULEVAR_PREF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DELOBJPROP_PREF_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDLAZYSENDABLEMODULEVAR_PREF_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_SUSPENDGENERATOR_PREF_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDLAZYSENDABLEMODULEVAR_PREF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONAWAITUNCAUGHT_PREF_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_SUPERCALLFORWARDALLARGS_PREF_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_COPYDATAPROPERTIES_PREF_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLELOCALMODULEVAR_PREF_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_SETOBJECTWITHPROTO_PREF_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLELOCALMODULEVAR_PREF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYVALUE_PREF_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDSUPERBYVALUE_PREF_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYINDEX_PREF_V8_IMM32:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONRESOLVE_PREF_V8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONREJECT_PREF_V8_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM4_IMM4_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM8_IMM8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM16_IMM16_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETMODULENAMESPACE_PREF_ID32:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STMODULEVAR_PREF_ID32:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYNAME_PREF_ID32_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDSUPERBYNAME_PREF_ID32_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDMODULEVAR_PREF_ID32_IMM8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STCONSTTOGLOBALRECORD_PREF_ID32:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLETTOGLOBALRECORD_PREF_ID32:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STCLASSTOGLOBALRECORD_PREF_ID32:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDHOMEOBJECT_PREF_NONE:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEOBJECTHAVINGMETHOD_PREF_IMM16:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DYNAMICIMPORT_PREF_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCGENERATORREJECT_PREF_V8_V8:
        return ((Exceptions::X_NONE) & exception) == exception;  // NOLINT(hicpp-signed-bitwise)
    default:
        return false;
    }

    UNREACHABLE();
}

// NOLINTNEXTLINE(readability-function-size)
template<const BytecodeInstMode Mode> inline bool BytecodeInst<Mode>::CanThrow() const {
    switch(GetOpcode()) {
    case BytecodeInst<Mode>::Opcode::LDUNDEFINED:
        return false;
    case BytecodeInst<Mode>::Opcode::LDNULL:
        return false;
    case BytecodeInst<Mode>::Opcode::LDTRUE:
        return false;
    case BytecodeInst<Mode>::Opcode::LDFALSE:
        return false;
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYOBJECT:
        return false;
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYARRAY_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::CREATEARRAYWITHBUFFER_IMM8_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHBUFFER_IMM8_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM8_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::NEWLEXENV_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::ADD2_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::SUB2_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::MUL2_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DIV2_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::MOD2_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::EQ_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::NOTEQ_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::LESS_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::LESSEQ_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::GREATER_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::GREATEREQ_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::SHL2_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::SHR2_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::ASHR2_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::AND2_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::OR2_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::XOR2_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::EXP_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::TYPEOF_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::TONUMBER_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::TONUMERIC_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::NEG_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::NOT_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::INC_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEC_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::ISTRUE:
        return false;
    case BytecodeInst<Mode>::Opcode::ISFALSE:
        return false;
    case BytecodeInst<Mode>::Opcode::ISIN_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::INSTANCEOF_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::STRICTNOTEQ_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::STRICTEQ_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLARG0_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLARG1_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLARGS2_IMM8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLARGS3_IMM8_V8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLTHIS0_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLTHIS1_IMM8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLTHIS2_IMM8_V8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLTHIS3_IMM8_V8_V8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGE_IMM8_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::SUPERCALLTHISRANGE_IMM8_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEFINEFUNC_IMM8_ID16_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEFINEMETHOD_IMM8_ID16_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEFINECLASSWITHBUFFER_IMM8_ID16_ID16_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::GETNEXTPROPNAME_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::LDOBJBYVALUE_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::STOBJBYVALUE_IMM8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYVALUE_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::LDOBJBYINDEX_IMM8_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::STOBJBYINDEX_IMM8_V8_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::LDLEXVAR_IMM4_IMM4:
        return false;
    case BytecodeInst<Mode>::Opcode::STLEXVAR_IMM4_IMM4:
        return false;
    case BytecodeInst<Mode>::Opcode::LDA_STR_ID16:
        return true;
    case BytecodeInst<Mode>::Opcode::TRYLDGLOBALBYNAME_IMM8_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::TRYSTGLOBALBYNAME_IMM8_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::LDGLOBALVAR_IMM16_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::LDOBJBYNAME_IMM8_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::STOBJBYNAME_IMM8_ID16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::MOV_V4_V4:
        return false;
    case BytecodeInst<Mode>::Opcode::MOV_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYNAME_IMM8_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::STCONSTTOGLOBALRECORD_IMM16_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::STTOGLOBALRECORD_IMM16_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::LDTHISBYNAME_IMM8_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::STTHISBYNAME_IMM8_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::LDTHISBYVALUE_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::STTHISBYVALUE_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::JMP_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::JMP_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::LDA_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::STA_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::LDAI_IMM32:
        return false;
    case BytecodeInst<Mode>::Opcode::FLDAI_IMM64:
        return false;
    case BytecodeInst<Mode>::Opcode::RETURN:
        return false;
    case BytecodeInst<Mode>::Opcode::RETURNUNDEFINED:
        return false;
    case BytecodeInst<Mode>::Opcode::GETPROPITERATOR:
        return false;
    case BytecodeInst<Mode>::Opcode::GETITERATOR_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::CLOSEITERATOR_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::POPLEXENV:
        return false;
    case BytecodeInst<Mode>::Opcode::LDNAN:
        return false;
    case BytecodeInst<Mode>::Opcode::LDINFINITY:
        return false;
    case BytecodeInst<Mode>::Opcode::GETUNMAPPEDARGS:
        return false;
    case BytecodeInst<Mode>::Opcode::LDGLOBAL:
        return false;
    case BytecodeInst<Mode>::Opcode::LDNEWTARGET:
        return false;
    case BytecodeInst<Mode>::Opcode::LDTHIS:
        return false;
    case BytecodeInst<Mode>::Opcode::LDHOLE:
        return false;
    case BytecodeInst<Mode>::Opcode::CREATEREGEXPWITHLITERAL_IMM8_ID16_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::CREATEREGEXPWITHLITERAL_IMM16_ID16_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRANGE_IMM8_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEFINEFUNC_IMM16_ID16_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEFINECLASSWITHBUFFER_IMM16_ID16_ID16_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::GETTEMPLATEOBJECT_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::SETOBJECTWITHPROTO_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUE_IMM8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::STOWNBYINDEX_IMM8_V8_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAME_IMM8_ID16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::GETMODULENAMESPACE_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::STMODULEVAR_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::LDLOCALMODULEVAR_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::LDEXTERNALMODULEVAR_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::STGLOBALVAR_IMM16_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYARRAY_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::CREATEARRAYWITHBUFFER_IMM16_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHBUFFER_IMM16_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM16_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::TYPEOF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::LDOBJBYVALUE_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::STOBJBYVALUE_IMM16_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYVALUE_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::LDOBJBYINDEX_IMM16_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::STOBJBYINDEX_IMM16_V8_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::LDLEXVAR_IMM8_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::STLEXVAR_IMM8_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::TRYLDGLOBALBYNAME_IMM16_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::TRYSTGLOBALBYNAME_IMM16_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAMEWITHNAMESET_IMM8_ID16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::MOV_V16_V16:
        return false;
    case BytecodeInst<Mode>::Opcode::LDOBJBYNAME_IMM16_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::STOBJBYNAME_IMM16_ID16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYNAME_IMM16_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::LDTHISBYNAME_IMM16_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::STTHISBYNAME_IMM16_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::LDTHISBYVALUE_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::STTHISBYVALUE_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::ASYNCGENERATORREJECT_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::JMP_IMM32:
        return false;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUEWITHNAMESET_IMM8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM32:
        return false;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM32:
        return false;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::GETITERATOR_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::CLOSEITERATOR_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::LDSYMBOL:
        return false;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONENTER:
        return false;
    case BytecodeInst<Mode>::Opcode::LDFUNCTION:
        return false;
    case BytecodeInst<Mode>::Opcode::DEBUGGER:
        return false;
    case BytecodeInst<Mode>::Opcode::CREATEGENERATOROBJ_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CREATEITERRESULTOBJ_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHEXCLUDEDKEYS_IMM8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::NEWOBJAPPLY_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::NEWOBJAPPLY_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::NEWLEXENVWITHNAME_IMM8_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::CREATEASYNCGENERATOROBJ_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::ASYNCGENERATORRESOLVE_V8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::SUPERCALLSPREAD_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::APPLY_IMM8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::SUPERCALLARROWRANGE_IMM8_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEFINEGETTERSETTERBYVALUE_V8_V8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DYNAMICIMPORT:
        return false;
    case BytecodeInst<Mode>::Opcode::DEFINEMETHOD_IMM16_ID16_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::RESUMEGENERATOR:
        return false;
    case BytecodeInst<Mode>::Opcode::GETRESUMEMODE:
        return false;
    case BytecodeInst<Mode>::Opcode::GETTEMPLATEOBJECT_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::DELOBJPROP_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::SUSPENDGENERATOR_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONAWAITUNCAUGHT_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::COPYDATAPROPERTIES_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::STARRAYSPREAD_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::SETOBJECTWITHPROTO_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUE_IMM16_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::STSUPERBYVALUE_IMM8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::STSUPERBYVALUE_IMM16_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::STOWNBYINDEX_IMM16_V8_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAME_IMM16_ID16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONRESOLVE_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONREJECT_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::COPYRESTARGS_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::STSUPERBYNAME_IMM8_ID16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::STSUPERBYNAME_IMM16_ID16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUEWITHNAMESET_IMM16_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::LDBIGINT_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAMEWITHNAMESET_IMM16_ID16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::NOP:
        return false;
    case BytecodeInst<Mode>::Opcode::SETGENERATORSTATE_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::GETASYNCITERATOR_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::LDPRIVATEPROPERTY_IMM8_IMM16_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::STPRIVATEPROPERTY_IMM8_IMM16_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::TESTIN_IMM8_IMM16_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::DEFINEFIELDBYNAME_IMM8_ID16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEFINEPROPERTYBYNAME_IMM8_ID16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLTHIS0WITHNAME_IMM8_ID16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLTHIS1WITHNAME_IMM8_ID16_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLTHIS2WITHNAME_IMM8_ID16_V8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLTHIS3WITHNAME_IMM8_ID16_V8_V8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGEWITHNAME_IMM8_IMM8_ID16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_NOTIFYCONCURRENTRESULT_PREF_NONE:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDLEXENV_PREF_NONE:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_CREATEOBJECTWITHEXCLUDEDKEYS_PREF_IMM16_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::THROW_PREF_NONE:
        return true;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEFIELDBYVALUE_PREF_IMM8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_POPLEXENV_PREF_NONE:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWOBJRANGE_PREF_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::THROW_NOTEXISTS_PREF_NONE:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEFIELDBYINDEX_PREF_IMM8_IMM32_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETITERATORNEXT_PREF_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWLEXENV_PREF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::THROW_PATTERNNONCOERCIBLE_PREF_NONE:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_TOPROPERTYKEY_PREF_NONE:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEARRAYWITHBUFFER_PREF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWLEXENVWITHNAME_PREF_IMM16_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::THROW_DELETESUPERPROPERTY_PREF_NONE:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_CREATEPRIVATEPROPERTY_PREF_IMM16_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEOBJECTWITHBUFFER_PREF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLRANGE_PREF_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::THROW_CONSTASSIGNMENT_PREF_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEPRIVATEPROPERTY_PREF_IMM8_IMM16_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_TONUMBER_PREF_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGE_PREF_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::THROW_IFNOTOBJECT_PREF_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_CALLINIT_PREF_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_TONUMERIC_PREF_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLTHISRANGE_PREF_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::THROW_UNDEFINEDIFHOLE_PREF_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINESENDABLECLASS_PREF_IMM16_ID16_ID16_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_NEG_PREF_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLARROWRANGE_PREF_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::THROW_IFSUPERNOTCORRECTCALL_PREF_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLECLASS_PREF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_NOT_PREF_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_LDOBJBYINDEX_PREF_IMM32:
        return false;
    case BytecodeInst<Mode>::Opcode::THROW_IFSUPERNOTCORRECTCALL_PREF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEEXTERNALMODULEVAR_PREF_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_INC_PREF_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_STOBJBYINDEX_PREF_V8_IMM32:
        return false;
    case BytecodeInst<Mode>::Opcode::THROW_UNDEFINEDIFHOLEWITHNAME_PREF_ID16:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLEEXTERNALMODULEVAR_PREF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DEC_PREF_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_STOWNBYINDEX_PREF_V8_IMM32:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_NEWSENDABLEENV_PREF_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARG0_PREF_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_COPYRESTARGS_PREF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDENEWSENDABLEENV_PREF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARG1_PREF_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_LDLEXVAR_PREF_IMM16_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_STSENDABLEVAR_PREF_IMM4_IMM4:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARGS2_PREF_V8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_STLEXVAR_PREF_IMM16_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_STSENDABLEVAR_PREF_IMM8_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARGS3_PREF_V8_V8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_GETMODULENAMESPACE_PREF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDESTSENDABLEVAR_PREF_IMM16_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLRANGE_PREF_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_STMODULEVAR_PREF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEVAR_PREF_IMM4_IMM4:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLSPREAD_PREF_V8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_LDLOCALMODULEVAR_PREF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEVAR_PREF_IMM8_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLTHISRANGE_PREF_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_LDEXTERNALMODULEVAR_PREF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLEVAR_PREF_IMM16_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DEFINECLASSWITHBUFFER_PREF_ID16_IMM16_IMM16_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_LDPATCHVAR_PREF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_ISTRUE_PREF_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_RESUMEGENERATOR_PREF_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_STPATCHVAR_PREF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_ISFALSE_PREF_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETRESUMEMODE_PREF_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGEWITHNAME_PREF_IMM16_ID16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDLAZYMODULEVAR_PREF_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETTEMPLATEOBJECT_PREF_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDLAZYMODULEVAR_PREF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DELOBJPROP_PREF_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDLAZYSENDABLEMODULEVAR_PREF_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_SUSPENDGENERATOR_PREF_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDLAZYSENDABLEMODULEVAR_PREF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONAWAITUNCAUGHT_PREF_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_SUPERCALLFORWARDALLARGS_PREF_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_COPYDATAPROPERTIES_PREF_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLELOCALMODULEVAR_PREF_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_SETOBJECTWITHPROTO_PREF_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLELOCALMODULEVAR_PREF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYVALUE_PREF_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDSUPERBYVALUE_PREF_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYINDEX_PREF_V8_IMM32:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONRESOLVE_PREF_V8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONREJECT_PREF_V8_V8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM4_IMM4_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM8_IMM8_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM16_IMM16_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETMODULENAMESPACE_PREF_ID32:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STMODULEVAR_PREF_ID32:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYNAME_PREF_ID32_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDSUPERBYNAME_PREF_ID32_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDMODULEVAR_PREF_ID32_IMM8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STCONSTTOGLOBALRECORD_PREF_ID32:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLETTOGLOBALRECORD_PREF_ID32:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STCLASSTOGLOBALRECORD_PREF_ID32:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDHOMEOBJECT_PREF_NONE:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEOBJECTHAVINGMETHOD_PREF_IMM16:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DYNAMICIMPORT_PREF_V8:
        return false;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCGENERATORREJECT_PREF_V8_V8:
        return false;
    default:
        return false;
    }

    UNREACHABLE();
}

// NOLINTNEXTLINE(readability-function-size)
template<const BytecodeInstMode Mode> std::ostream& operator<<(std::ostream& os, const BytecodeInst<Mode>& inst) {
    switch(inst.GetOpcode()) {
    case BytecodeInst<Mode>::Opcode::LDUNDEFINED:
        os << "ldundefined";
        break;
    case BytecodeInst<Mode>::Opcode::LDNULL:
        os << "ldnull";
        break;
    case BytecodeInst<Mode>::Opcode::LDTRUE:
        os << "ldtrue";
        break;
    case BytecodeInst<Mode>::Opcode::LDFALSE:
        os << "ldfalse";
        break;
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYOBJECT:
        os << "createemptyobject";
        break;
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYARRAY_IMM8:
        os << "createemptyarray";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CREATEARRAYWITHBUFFER_IMM8_ID16:
        os << "createarraywithbuffer";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHBUFFER_IMM8_ID16:
        os << "createobjectwithbuffer";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM8_IMM8_V8:
        os << "newobjrange";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM8_V8, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM8_V8, 1, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::NEWLEXENV_IMM8:
        os << "newlexenv";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::ADD2_IMM8_V8:
        os << "add2";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::SUB2_IMM8_V8:
        os << "sub2";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::MUL2_IMM8_V8:
        os << "mul2";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DIV2_IMM8_V8:
        os << "div2";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::MOD2_IMM8_V8:
        os << "mod2";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::EQ_IMM8_V8:
        os << "eq";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::NOTEQ_IMM8_V8:
        os << "noteq";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::LESS_IMM8_V8:
        os << "less";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::LESSEQ_IMM8_V8:
        os << "lesseq";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::GREATER_IMM8_V8:
        os << "greater";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::GREATEREQ_IMM8_V8:
        os << "greatereq";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::SHL2_IMM8_V8:
        os << "shl2";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::SHR2_IMM8_V8:
        os << "shr2";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::ASHR2_IMM8_V8:
        os << "ashr2";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::AND2_IMM8_V8:
        os << "and2";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::OR2_IMM8_V8:
        os << "or2";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::XOR2_IMM8_V8:
        os << "xor2";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::EXP_IMM8_V8:
        os << "exp";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::TYPEOF_IMM8:
        os << "typeof";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::TONUMBER_IMM8:
        os << "tonumber";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::TONUMERIC_IMM8:
        os << "tonumeric";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::NEG_IMM8:
        os << "neg";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::NOT_IMM8:
        os << "not";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::INC_IMM8:
        os << "inc";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEC_IMM8:
        os << "dec";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::ISTRUE:
        os << "istrue";
        break;
    case BytecodeInst<Mode>::Opcode::ISFALSE:
        os << "isfalse";
        break;
    case BytecodeInst<Mode>::Opcode::ISIN_IMM8_V8:
        os << "isin";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::INSTANCEOF_IMM8_V8:
        os << "instanceof";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::STRICTNOTEQ_IMM8_V8:
        os << "strictnoteq";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::STRICTEQ_IMM8_V8:
        os << "stricteq";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLARG0_IMM8:
        os << "callarg0";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLARG1_IMM8_V8:
        os << "callarg1";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLARGS2_IMM8_V8_V8:
        os << "callargs2";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLARGS3_IMM8_V8_V8_V8:
        os << "callargs3";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8_V8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8_V8, 1>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8_V8, 2>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS0_IMM8_V8:
        os << "callthis0";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS1_IMM8_V8_V8:
        os << "callthis1";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS2_IMM8_V8_V8_V8:
        os << "callthis2";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8_V8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8_V8, 1>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8_V8, 2>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS3_IMM8_V8_V8_V8_V8:
        os << "callthis3";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8_V8_V8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8_V8_V8, 1>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8_V8_V8, 2>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8_V8_V8, 3>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGE_IMM8_IMM8_V8:
        os << "callthisrange";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM8_V8, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM8_V8, 1, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::SUPERCALLTHISRANGE_IMM8_IMM8_V8:
        os << "supercallthisrange";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM8_V8, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM8_V8, 1, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEFUNC_IMM8_ID16_IMM8:
        os << "definefunc";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16_IMM8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16_IMM8, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16_IMM8, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEMETHOD_IMM8_ID16_IMM8:
        os << "definemethod";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16_IMM8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16_IMM8, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16_IMM8, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEFINECLASSWITHBUFFER_IMM8_ID16_ID16_IMM16_V8:
        os << "defineclasswithbuffer";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16_ID16_IMM16_V8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16_ID16_IMM16_V8, 0>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16_ID16_IMM16_V8, 1>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16_ID16_IMM16_V8, 1, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_ID16_ID16_IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::GETNEXTPROPNAME_V8:
        os << "getnextpropname";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYVALUE_IMM8_V8:
        os << "ldobjbyvalue";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYVALUE_IMM8_V8_V8:
        os << "stobjbyvalue";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYVALUE_IMM8_V8:
        os << "ldsuperbyvalue";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYINDEX_IMM8_IMM16:
        os << "ldobjbyindex";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM16, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM16, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYINDEX_IMM8_V8_IMM16:
        os << "stobjbyindex";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8_IMM16, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_IMM16, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8_IMM16, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::LDLEXVAR_IMM4_IMM4:
        os << "ldlexvar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM4_IMM4, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM4_IMM4, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::STLEXVAR_IMM4_IMM4:
        os << "stlexvar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM4_IMM4, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM4_IMM4, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::LDA_STR_ID16:
        os << "lda.str";
        os << " id" << inst.template GetId<BytecodeInst<Mode>::Format::ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::TRYLDGLOBALBYNAME_IMM8_ID16:
        os << "tryldglobalbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::TRYSTGLOBALBYNAME_IMM8_ID16:
        os << "trystglobalbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::LDGLOBALVAR_IMM16_ID16:
        os << "ldglobalvar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYNAME_IMM8_ID16:
        os << "ldobjbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYNAME_IMM8_ID16_V8:
        os << "stobjbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::MOV_V4_V4:
        os << "mov";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V4_V4, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V4_V4, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::MOV_V8_V8:
        os << "mov";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYNAME_IMM8_ID16:
        os << "ldsuperbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::STCONSTTOGLOBALRECORD_IMM16_ID16:
        os << "stconsttoglobalrecord";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::STTOGLOBALRECORD_IMM16_ID16:
        os << "sttoglobalrecord";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::LDTHISBYNAME_IMM8_ID16:
        os << "ldthisbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::STTHISBYNAME_IMM8_ID16:
        os << "stthisbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::LDTHISBYVALUE_IMM8:
        os << "ldthisbyvalue";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::STTHISBYVALUE_IMM8_V8:
        os << "stthisbyvalue";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::JMP_IMM8:
        os << "jmp";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JMP_IMM16:
        os << "jmp";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM8:
        os << "jeqz";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM16:
        os << "jeqz";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM8:
        os << "jnez";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM8:
        os << "jstricteqz";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM8:
        os << "jnstricteqz";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM8:
        os << "jeqnull";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM8:
        os << "jnenull";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM8:
        os << "jstricteqnull";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM8:
        os << "jnstricteqnull";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM8:
        os << "jequndefined";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM8:
        os << "jneundefined";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM8:
        os << "jstrictequndefined";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM8:
        os << "jnstrictequndefined";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM8:
        os << "jeq";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_IMM8, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::V8_IMM8, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM8:
        os << "jne";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_IMM8, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::V8_IMM8, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM8:
        os << "jstricteq";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_IMM8, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::V8_IMM8, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM8:
        os << "jnstricteq";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_IMM8, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::V8_IMM8, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::LDA_V8:
        os << "lda";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::STA_V8:
        os << "sta";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::LDAI_IMM32:
        os << "ldai";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM32, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::FLDAI_IMM64:
        os << "fldai";
        os << " " << bit_cast<double>(inst.template GetImm<BytecodeInst<Mode>::Format::IMM64, 0, true>());
        break;
    case BytecodeInst<Mode>::Opcode::RETURN:
        os << "return";
        break;
    case BytecodeInst<Mode>::Opcode::RETURNUNDEFINED:
        os << "returnundefined";
        break;
    case BytecodeInst<Mode>::Opcode::GETPROPITERATOR:
        os << "getpropiterator";
        break;
    case BytecodeInst<Mode>::Opcode::GETITERATOR_IMM8:
        os << "getiterator";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CLOSEITERATOR_IMM8_V8:
        os << "closeiterator";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::POPLEXENV:
        os << "poplexenv";
        break;
    case BytecodeInst<Mode>::Opcode::LDNAN:
        os << "ldnan";
        break;
    case BytecodeInst<Mode>::Opcode::LDINFINITY:
        os << "ldinfinity";
        break;
    case BytecodeInst<Mode>::Opcode::GETUNMAPPEDARGS:
        os << "getunmappedargs";
        break;
    case BytecodeInst<Mode>::Opcode::LDGLOBAL:
        os << "ldglobal";
        break;
    case BytecodeInst<Mode>::Opcode::LDNEWTARGET:
        os << "ldnewtarget";
        break;
    case BytecodeInst<Mode>::Opcode::LDTHIS:
        os << "ldthis";
        break;
    case BytecodeInst<Mode>::Opcode::LDHOLE:
        os << "ldhole";
        break;
    case BytecodeInst<Mode>::Opcode::CREATEREGEXPWITHLITERAL_IMM8_ID16_IMM8:
        os << "createregexpwithliteral";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16_IMM8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16_IMM8, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16_IMM8, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CREATEREGEXPWITHLITERAL_IMM16_ID16_IMM8:
        os << "createregexpwithliteral";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16_IMM8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16_IMM8, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16_IMM8, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRANGE_IMM8_IMM8_V8:
        os << "callrange";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM8_V8, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM8_V8, 1, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEFUNC_IMM16_ID16_IMM8:
        os << "definefunc";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16_IMM8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16_IMM8, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16_IMM8, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEFINECLASSWITHBUFFER_IMM16_ID16_ID16_IMM16_V8:
        os << "defineclasswithbuffer";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16_ID16_IMM16_V8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16_ID16_IMM16_V8, 0>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16_ID16_IMM16_V8, 1>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16_ID16_IMM16_V8, 1, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_ID16_ID16_IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::GETTEMPLATEOBJECT_IMM8:
        os << "gettemplateobject";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::SETOBJECTWITHPROTO_IMM8_V8:
        os << "setobjectwithproto";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUE_IMM8_V8_V8:
        os << "stownbyvalue";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYINDEX_IMM8_V8_IMM16:
        os << "stownbyindex";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8_IMM16, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_IMM16, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8_IMM16, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAME_IMM8_ID16_V8:
        os << "stownbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::GETMODULENAMESPACE_IMM8:
        os << "getmodulenamespace";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::STMODULEVAR_IMM8:
        os << "stmodulevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::LDLOCALMODULEVAR_IMM8:
        os << "ldlocalmodulevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::LDEXTERNALMODULEVAR_IMM8:
        os << "ldexternalmodulevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::STGLOBALVAR_IMM16_ID16:
        os << "stglobalvar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYARRAY_IMM16:
        os << "createemptyarray";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CREATEARRAYWITHBUFFER_IMM16_ID16:
        os << "createarraywithbuffer";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHBUFFER_IMM16_ID16:
        os << "createobjectwithbuffer";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM16_IMM8_V8:
        os << "newobjrange";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_IMM8_V8, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_IMM8_V8, 1, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::TYPEOF_IMM16:
        os << "typeof";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYVALUE_IMM16_V8:
        os << "ldobjbyvalue";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYVALUE_IMM16_V8_V8:
        os << "stobjbyvalue";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_V8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYVALUE_IMM16_V8:
        os << "ldsuperbyvalue";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYINDEX_IMM16_IMM16:
        os << "ldobjbyindex";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_IMM16, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_IMM16, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYINDEX_IMM16_V8_IMM16:
        os << "stobjbyindex";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_V8_IMM16, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_V8_IMM16, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_V8_IMM16, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::LDLEXVAR_IMM8_IMM8:
        os << "ldlexvar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM8, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM8, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::STLEXVAR_IMM8_IMM8:
        os << "stlexvar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM8, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM8, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::TRYLDGLOBALBYNAME_IMM16_ID16:
        os << "tryldglobalbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::TRYSTGLOBALBYNAME_IMM16_ID16:
        os << "trystglobalbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAMEWITHNAMESET_IMM8_ID16_V8:
        os << "stownbynamewithnameset";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::MOV_V16_V16:
        os << "mov";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V16_V16, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V16_V16, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYNAME_IMM16_ID16:
        os << "ldobjbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYNAME_IMM16_ID16_V8:
        os << "stobjbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16_V8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_ID16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYNAME_IMM16_ID16:
        os << "ldsuperbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::LDTHISBYNAME_IMM16_ID16:
        os << "ldthisbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::STTHISBYNAME_IMM16_ID16:
        os << "stthisbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::LDTHISBYVALUE_IMM16:
        os << "ldthisbyvalue";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::STTHISBYVALUE_IMM16_V8:
        os << "stthisbyvalue";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCGENERATORREJECT_V8:
        os << "asyncgeneratorreject";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::JMP_IMM32:
        os << "jmp";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM32, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUEWITHNAMESET_IMM8_V8_V8:
        os << "stownbyvaluewithnameset";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM32:
        os << "jeqz";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM32, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM16:
        os << "jnez";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM32:
        os << "jnez";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM32, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM16:
        os << "jstricteqz";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM16:
        os << "jnstricteqz";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM16:
        os << "jeqnull";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM16:
        os << "jnenull";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM16:
        os << "jstricteqnull";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM16:
        os << "jnstricteqnull";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM16:
        os << "jequndefined";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM16:
        os << "jneundefined";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM16:
        os << "jstrictequndefined";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM16:
        os << "jnstrictequndefined";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM16:
        os << "jeq";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_IMM16, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::V8_IMM16, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM16:
        os << "jne";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_IMM16, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::V8_IMM16, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM16:
        os << "jstricteq";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_IMM16, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::V8_IMM16, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM16:
        os << "jnstricteq";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_IMM16, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::V8_IMM16, 0, true>();
        break;
    case BytecodeInst<Mode>::Opcode::GETITERATOR_IMM16:
        os << "getiterator";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CLOSEITERATOR_IMM16_V8:
        os << "closeiterator";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::LDSYMBOL:
        os << "ldsymbol";
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONENTER:
        os << "asyncfunctionenter";
        break;
    case BytecodeInst<Mode>::Opcode::LDFUNCTION:
        os << "ldfunction";
        break;
    case BytecodeInst<Mode>::Opcode::DEBUGGER:
        os << "debugger";
        break;
    case BytecodeInst<Mode>::Opcode::CREATEGENERATOROBJ_V8:
        os << "creategeneratorobj";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::CREATEITERRESULTOBJ_V8_V8:
        os << "createiterresultobj";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHEXCLUDEDKEYS_IMM8_V8_V8:
        os << "createobjectwithexcludedkeys";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::NEWOBJAPPLY_IMM8_V8:
        os << "newobjapply";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::NEWOBJAPPLY_IMM16_V8:
        os << "newobjapply";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::NEWLEXENVWITHNAME_IMM8_ID16:
        os << "newlexenvwithname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::CREATEASYNCGENERATOROBJ_V8:
        os << "createasyncgeneratorobj";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCGENERATORRESOLVE_V8_V8_V8:
        os << "asyncgeneratorresolve";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_V8_V8, 1>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_V8_V8, 2>();
        break;
    case BytecodeInst<Mode>::Opcode::SUPERCALLSPREAD_IMM8_V8:
        os << "supercallspread";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::APPLY_IMM8_V8_V8:
        os << "apply";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::SUPERCALLARROWRANGE_IMM8_IMM8_V8:
        os << "supercallarrowrange";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM8_V8, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM8_V8, 1, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEGETTERSETTERBYVALUE_V8_V8_V8_V8:
        os << "definegettersetterbyvalue";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_V8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_V8_V8_V8, 1>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_V8_V8_V8, 2>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_V8_V8_V8, 3>();
        break;
    case BytecodeInst<Mode>::Opcode::DYNAMICIMPORT:
        os << "dynamicimport";
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEMETHOD_IMM16_ID16_IMM8:
        os << "definemethod";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16_IMM8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16_IMM8, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16_IMM8, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::RESUMEGENERATOR:
        os << "resumegenerator";
        break;
    case BytecodeInst<Mode>::Opcode::GETRESUMEMODE:
        os << "getresumemode";
        break;
    case BytecodeInst<Mode>::Opcode::GETTEMPLATEOBJECT_IMM16:
        os << "gettemplateobject";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DELOBJPROP_V8:
        os << "delobjprop";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::SUSPENDGENERATOR_V8:
        os << "suspendgenerator";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONAWAITUNCAUGHT_V8:
        os << "asyncfunctionawaituncaught";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::COPYDATAPROPERTIES_V8:
        os << "copydataproperties";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::STARRAYSPREAD_V8_V8:
        os << "starrayspread";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::SETOBJECTWITHPROTO_IMM16_V8:
        os << "setobjectwithproto";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUE_IMM16_V8_V8:
        os << "stownbyvalue";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_V8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::STSUPERBYVALUE_IMM8_V8_V8:
        os << "stsuperbyvalue";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_V8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::STSUPERBYVALUE_IMM16_V8_V8:
        os << "stsuperbyvalue";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_V8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYINDEX_IMM16_V8_IMM16:
        os << "stownbyindex";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_V8_IMM16, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_V8_IMM16, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_V8_IMM16, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAME_IMM16_ID16_V8:
        os << "stownbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16_V8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_ID16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONRESOLVE_V8:
        os << "asyncfunctionresolve";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONREJECT_V8:
        os << "asyncfunctionreject";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::COPYRESTARGS_IMM8:
        os << "copyrestargs";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::STSUPERBYNAME_IMM8_ID16_V8:
        os << "stsuperbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::STSUPERBYNAME_IMM16_ID16_V8:
        os << "stsuperbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16_V8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_ID16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUEWITHNAMESET_IMM16_V8_V8:
        os << "stownbyvaluewithnameset";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_V8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::LDBIGINT_ID16:
        os << "ldbigint";
        os << " id" << inst.template GetId<BytecodeInst<Mode>::Format::ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAMEWITHNAMESET_IMM16_ID16_V8:
        os << "stownbynamewithnameset";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM16_ID16_V8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM16_ID16_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM16_ID16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::NOP:
        os << "nop";
        break;
    case BytecodeInst<Mode>::Opcode::SETGENERATORSTATE_IMM8:
        os << "setgeneratorstate";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::GETASYNCITERATOR_IMM8:
        os << "getasynciterator";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::LDPRIVATEPROPERTY_IMM8_IMM16_IMM16:
        os << "ldprivateproperty";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM16_IMM16, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM16_IMM16, 1, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM16_IMM16, 2, false>();
        break;
    case BytecodeInst<Mode>::Opcode::STPRIVATEPROPERTY_IMM8_IMM16_IMM16_V8:
        os << "stprivateproperty";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM16_IMM16_V8, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM16_IMM16_V8, 1, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM16_IMM16_V8, 2, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_IMM16_IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::TESTIN_IMM8_IMM16_IMM16:
        os << "testin";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM16_IMM16, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM16_IMM16, 1, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM16_IMM16, 2, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEFIELDBYNAME_IMM8_ID16_V8:
        os << "definefieldbyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEPROPERTYBYNAME_IMM8_ID16_V8:
        os << "definepropertybyname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS0WITHNAME_IMM8_ID16_V8:
        os << "callthis0withname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_ID16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS1WITHNAME_IMM8_ID16_V8_V8:
        os << "callthis1withname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16_V8_V8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_ID16_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_ID16_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS2WITHNAME_IMM8_ID16_V8_V8_V8:
        os << "callthis2withname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16_V8_V8_V8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16_V8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_ID16_V8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_ID16_V8_V8_V8, 1>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_ID16_V8_V8_V8, 2>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS3WITHNAME_IMM8_ID16_V8_V8_V8_V8:
        os << "callthis3withname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_ID16_V8_V8_V8_V8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_ID16_V8_V8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_ID16_V8_V8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_ID16_V8_V8_V8_V8, 1>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_ID16_V8_V8_V8_V8, 2>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_ID16_V8_V8_V8_V8, 3>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGEWITHNAME_IMM8_IMM8_ID16_V8:
        os << "callthisrangewithname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM8_ID16_V8, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::IMM8_IMM8_ID16_V8, 1, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::IMM8_IMM8_ID16_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::IMM8_IMM8_ID16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_NOTIFYCONCURRENTRESULT_PREF_NONE:
        os << "callruntime.notifyconcurrentresult";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDLEXENV_PREF_NONE:
        os << "deprecated.ldlexenv";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_CREATEOBJECTWITHEXCLUDEDKEYS_PREF_IMM16_V8_V8:
        os << "wide.createobjectwithexcludedkeys";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_V8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM16_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM16_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::THROW_PREF_NONE:
        os << "throw";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEFIELDBYVALUE_PREF_IMM8_V8_V8:
        os << "callruntime.definefieldbyvalue";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8_V8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM8_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_POPLEXENV_PREF_NONE:
        os << "deprecated.poplexenv";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWOBJRANGE_PREF_IMM16_V8:
        os << "wide.newobjrange";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::THROW_NOTEXISTS_PREF_NONE:
        os << "throw.notexists";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEFIELDBYINDEX_PREF_IMM8_IMM32_V8:
        os << "callruntime.definefieldbyindex";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8_IMM32_V8, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8_IMM32_V8, 1, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM8_IMM32_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETITERATORNEXT_PREF_V8_V8:
        os << "deprecated.getiteratornext";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWLEXENV_PREF_IMM16:
        os << "wide.newlexenv";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::THROW_PATTERNNONCOERCIBLE_PREF_NONE:
        os << "throw.patternnoncoercible";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_TOPROPERTYKEY_PREF_NONE:
        os << "callruntime.topropertykey";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEARRAYWITHBUFFER_PREF_IMM16:
        os << "deprecated.createarraywithbuffer";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWLEXENVWITHNAME_PREF_IMM16_ID16:
        os << "wide.newlexenvwithname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::PREF_IMM16_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::THROW_DELETESUPERPROPERTY_PREF_NONE:
        os << "throw.deletesuperproperty";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_CREATEPRIVATEPROPERTY_PREF_IMM16_ID16:
        os << "callruntime.createprivateproperty";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_ID16, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::PREF_IMM16_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEOBJECTWITHBUFFER_PREF_IMM16:
        os << "deprecated.createobjectwithbuffer";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLRANGE_PREF_IMM16_V8:
        os << "wide.callrange";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::THROW_CONSTASSIGNMENT_PREF_V8:
        os << "throw.constassignment";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEPRIVATEPROPERTY_PREF_IMM8_IMM16_IMM16_V8:
        os << "callruntime.defineprivateproperty";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8_IMM16_IMM16_V8, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8_IMM16_IMM16_V8, 1, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8_IMM16_IMM16_V8, 2, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM8_IMM16_IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_TONUMBER_PREF_V8:
        os << "deprecated.tonumber";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGE_PREF_IMM16_V8:
        os << "wide.callthisrange";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::THROW_IFNOTOBJECT_PREF_V8:
        os << "throw.ifnotobject";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_CALLINIT_PREF_IMM8_V8:
        os << "callruntime.callinit";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_TONUMERIC_PREF_V8:
        os << "deprecated.tonumeric";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLTHISRANGE_PREF_IMM16_V8:
        os << "wide.supercallthisrange";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::THROW_UNDEFINEDIFHOLE_PREF_V8_V8:
        os << "throw.undefinedifhole";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINESENDABLECLASS_PREF_IMM16_ID16_ID16_IMM16_V8:
        os << "callruntime.definesendableclass";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_ID16_ID16_IMM16_V8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::PREF_IMM16_ID16_ID16_IMM16_V8, 0>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::PREF_IMM16_ID16_ID16_IMM16_V8, 1>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_ID16_ID16_IMM16_V8, 1, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM16_ID16_ID16_IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_NEG_PREF_V8:
        os << "deprecated.neg";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLARROWRANGE_PREF_IMM16_V8:
        os << "wide.supercallarrowrange";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::THROW_IFSUPERNOTCORRECTCALL_PREF_IMM8:
        os << "throw.ifsupernotcorrectcall";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLECLASS_PREF_IMM16:
        os << "callruntime.ldsendableclass";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_NOT_PREF_V8:
        os << "deprecated.not";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDOBJBYINDEX_PREF_IMM32:
        os << "wide.ldobjbyindex";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM32, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::THROW_IFSUPERNOTCORRECTCALL_PREF_IMM16:
        os << "throw.ifsupernotcorrectcall";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEEXTERNALMODULEVAR_PREF_IMM8:
        os << "callruntime.ldsendableexternalmodulevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_INC_PREF_V8:
        os << "deprecated.inc";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STOBJBYINDEX_PREF_V8_IMM32:
        os << "wide.stobjbyindex";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_IMM32, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_V8_IMM32, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::THROW_UNDEFINEDIFHOLEWITHNAME_PREF_ID16:
        os << "throw.undefinedifholewithname";
        os << " id" << inst.template GetId<BytecodeInst<Mode>::Format::PREF_ID16, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLEEXTERNALMODULEVAR_PREF_IMM16:
        os << "callruntime.wideldsendableexternalmodulevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DEC_PREF_V8:
        os << "deprecated.dec";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STOWNBYINDEX_PREF_V8_IMM32:
        os << "wide.stownbyindex";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_IMM32, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_V8_IMM32, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_NEWSENDABLEENV_PREF_IMM8:
        os << "callruntime.newsendableenv";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARG0_PREF_V8:
        os << "deprecated.callarg0";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_COPYRESTARGS_PREF_IMM16:
        os << "wide.copyrestargs";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDENEWSENDABLEENV_PREF_IMM16:
        os << "callruntime.widenewsendableenv";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARG1_PREF_V8_V8:
        os << "deprecated.callarg1";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDLEXVAR_PREF_IMM16_IMM16:
        os << "wide.ldlexvar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_IMM16, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_IMM16, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_STSENDABLEVAR_PREF_IMM4_IMM4:
        os << "callruntime.stsendablevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM4_IMM4, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM4_IMM4, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARGS2_PREF_V8_V8_V8:
        os << "deprecated.callargs2";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8_V8, 1>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8_V8, 2>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STLEXVAR_PREF_IMM16_IMM16:
        os << "wide.stlexvar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_IMM16, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_IMM16, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_STSENDABLEVAR_PREF_IMM8_IMM8:
        os << "callruntime.stsendablevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8_IMM8, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8_IMM8, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARGS3_PREF_V8_V8_V8_V8:
        os << "deprecated.callargs3";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8_V8_V8, 1>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8_V8_V8, 2>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8_V8_V8, 3>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_GETMODULENAMESPACE_PREF_IMM16:
        os << "wide.getmodulenamespace";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDESTSENDABLEVAR_PREF_IMM16_IMM16:
        os << "callruntime.widestsendablevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_IMM16, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_IMM16, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLRANGE_PREF_IMM16_V8:
        os << "deprecated.callrange";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STMODULEVAR_PREF_IMM16:
        os << "wide.stmodulevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEVAR_PREF_IMM4_IMM4:
        os << "callruntime.ldsendablevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM4_IMM4, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM4_IMM4, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLSPREAD_PREF_V8_V8_V8:
        os << "deprecated.callspread";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8_V8, 1>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8_V8, 2>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDLOCALMODULEVAR_PREF_IMM16:
        os << "wide.ldlocalmodulevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEVAR_PREF_IMM8_IMM8:
        os << "callruntime.ldsendablevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8_IMM8, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8_IMM8, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLTHISRANGE_PREF_IMM16_V8:
        os << "deprecated.callthisrange";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_V8, 0, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDEXTERNALMODULEVAR_PREF_IMM16:
        os << "wide.ldexternalmodulevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLEVAR_PREF_IMM16_IMM16:
        os << "callruntime.wideldsendablevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_IMM16, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_IMM16, 1, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DEFINECLASSWITHBUFFER_PREF_ID16_IMM16_IMM16_V8_V8:
        os << "deprecated.defineclasswithbuffer";
        os << " id" << inst.template GetId<BytecodeInst<Mode>::Format::PREF_ID16_IMM16_IMM16_V8_V8, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_ID16_IMM16_IMM16_V8_V8, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_ID16_IMM16_IMM16_V8_V8, 1, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_ID16_IMM16_IMM16_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_ID16_IMM16_IMM16_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDPATCHVAR_PREF_IMM16:
        os << "wide.ldpatchvar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_ISTRUE_PREF_IMM8:
        os << "callruntime.istrue";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_RESUMEGENERATOR_PREF_V8:
        os << "deprecated.resumegenerator";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STPATCHVAR_PREF_IMM16:
        os << "wide.stpatchvar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_ISFALSE_PREF_IMM8:
        os << "callruntime.isfalse";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETRESUMEMODE_PREF_V8:
        os << "deprecated.getresumemode";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGEWITHNAME_PREF_IMM16_ID16_V8:
        os << "wide.callthisrangewithname";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_ID16_V8, 0, false>();
        os << ", id" << inst.template GetId<BytecodeInst<Mode>::Format::PREF_IMM16_ID16_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM16_ID16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDLAZYMODULEVAR_PREF_IMM8:
        os << "callruntime.ldlazymodulevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETTEMPLATEOBJECT_PREF_V8:
        os << "deprecated.gettemplateobject";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDLAZYMODULEVAR_PREF_IMM16:
        os << "callruntime.wideldlazymodulevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DELOBJPROP_PREF_V8_V8:
        os << "deprecated.delobjprop";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDLAZYSENDABLEMODULEVAR_PREF_IMM8:
        os << "callruntime.ldlazysendablemodulevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_SUSPENDGENERATOR_PREF_V8_V8:
        os << "deprecated.suspendgenerator";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDLAZYSENDABLEMODULEVAR_PREF_IMM16:
        os << "callruntime.wideldlazysendablemodulevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONAWAITUNCAUGHT_PREF_V8_V8:
        os << "deprecated.asyncfunctionawaituncaught";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_SUPERCALLFORWARDALLARGS_PREF_V8:
        os << "callruntime.supercallforwardallargs";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_COPYDATAPROPERTIES_PREF_V8_V8:
        os << "deprecated.copydataproperties";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLELOCALMODULEVAR_PREF_IMM8:
        os << "callruntime.ldsendablelocalmodulevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_SETOBJECTWITHPROTO_PREF_V8_V8:
        os << "deprecated.setobjectwithproto";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLELOCALMODULEVAR_PREF_IMM16:
        os << "callruntime.wideldsendablelocalmodulevar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYVALUE_PREF_V8_V8:
        os << "deprecated.ldobjbyvalue";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDSUPERBYVALUE_PREF_V8_V8:
        os << "deprecated.ldsuperbyvalue";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 1>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYINDEX_PREF_V8_IMM32:
        os << "deprecated.ldobjbyindex";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_IMM32, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_V8_IMM32, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONRESOLVE_PREF_V8_V8_V8:
        os << "deprecated.asyncfunctionresolve";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8_V8, 1>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8_V8, 2>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONREJECT_PREF_V8_V8_V8:
        os << "deprecated.asyncfunctionreject";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8_V8, 1>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8_V8, 2>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM4_IMM4_V8:
        os << "deprecated.stlexvar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM4_IMM4_V8, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM4_IMM4_V8, 1, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM4_IMM4_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM8_IMM8_V8:
        os << "deprecated.stlexvar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8_IMM8_V8, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM8_IMM8_V8, 1, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM8_IMM8_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM16_IMM16_V8:
        os << "deprecated.stlexvar";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_IMM16_V8, 0, false>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16_IMM16_V8, 1, false>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_IMM16_IMM16_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETMODULENAMESPACE_PREF_ID32:
        os << "deprecated.getmodulenamespace";
        os << " id" << inst.template GetId<BytecodeInst<Mode>::Format::PREF_ID32, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STMODULEVAR_PREF_ID32:
        os << "deprecated.stmodulevar";
        os << " id" << inst.template GetId<BytecodeInst<Mode>::Format::PREF_ID32, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYNAME_PREF_ID32_V8:
        os << "deprecated.ldobjbyname";
        os << " id" << inst.template GetId<BytecodeInst<Mode>::Format::PREF_ID32_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_ID32_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDSUPERBYNAME_PREF_ID32_V8:
        os << "deprecated.ldsuperbyname";
        os << " id" << inst.template GetId<BytecodeInst<Mode>::Format::PREF_ID32_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_ID32_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDMODULEVAR_PREF_ID32_IMM8:
        os << "deprecated.ldmodulevar";
        os << " id" << inst.template GetId<BytecodeInst<Mode>::Format::PREF_ID32_IMM8, 0>();
        os << ", " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_ID32_IMM8, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STCONSTTOGLOBALRECORD_PREF_ID32:
        os << "deprecated.stconsttoglobalrecord";
        os << " id" << inst.template GetId<BytecodeInst<Mode>::Format::PREF_ID32, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLETTOGLOBALRECORD_PREF_ID32:
        os << "deprecated.stlettoglobalrecord";
        os << " id" << inst.template GetId<BytecodeInst<Mode>::Format::PREF_ID32, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STCLASSTOGLOBALRECORD_PREF_ID32:
        os << "deprecated.stclasstoglobalrecord";
        os << " id" << inst.template GetId<BytecodeInst<Mode>::Format::PREF_ID32, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDHOMEOBJECT_PREF_NONE:
        os << "deprecated.ldhomeobject";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEOBJECTHAVINGMETHOD_PREF_IMM16:
        os << "deprecated.createobjecthavingmethod";
        os << " " << inst.template GetImm<BytecodeInst<Mode>::Format::PREF_IMM16, 0, false>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DYNAMICIMPORT_PREF_V8:
        os << "deprecated.dynamicimport";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8, 0>();
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCGENERATORREJECT_PREF_V8_V8:
        os << "deprecated.asyncgeneratorreject";
        os << " v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 0>();
        os << ", v" << inst.template GetVReg<BytecodeInst<Mode>::Format::PREF_V8_V8, 1>();
        break;
    }
    return os;
}

template<const BytecodeInstMode Mode> // NOLINTNEXTLINE(readability-function-size)
std::ostream& operator<<(std::ostream& os, const typename BytecodeInst<Mode>::Opcode& op)
{
    switch(op) {
    case BytecodeInst<Mode>::Opcode::LDUNDEFINED:
        os << "LDUNDEFINED";
        break;
    case BytecodeInst<Mode>::Opcode::LDNULL:
        os << "LDNULL";
        break;
    case BytecodeInst<Mode>::Opcode::LDTRUE:
        os << "LDTRUE";
        break;
    case BytecodeInst<Mode>::Opcode::LDFALSE:
        os << "LDFALSE";
        break;
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYOBJECT:
        os << "CREATEEMPTYOBJECT";
        break;
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYARRAY_IMM8:
        os << "CREATEEMPTYARRAY_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::CREATEARRAYWITHBUFFER_IMM8_ID16:
        os << "CREATEARRAYWITHBUFFER_IMM8_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHBUFFER_IMM8_ID16:
        os << "CREATEOBJECTWITHBUFFER_IMM8_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM8_IMM8_V8:
        os << "NEWOBJRANGE_IMM8_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::NEWLEXENV_IMM8:
        os << "NEWLEXENV_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::ADD2_IMM8_V8:
        os << "ADD2_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::SUB2_IMM8_V8:
        os << "SUB2_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::MUL2_IMM8_V8:
        os << "MUL2_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DIV2_IMM8_V8:
        os << "DIV2_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::MOD2_IMM8_V8:
        os << "MOD2_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::EQ_IMM8_V8:
        os << "EQ_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::NOTEQ_IMM8_V8:
        os << "NOTEQ_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::LESS_IMM8_V8:
        os << "LESS_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::LESSEQ_IMM8_V8:
        os << "LESSEQ_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::GREATER_IMM8_V8:
        os << "GREATER_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::GREATEREQ_IMM8_V8:
        os << "GREATEREQ_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::SHL2_IMM8_V8:
        os << "SHL2_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::SHR2_IMM8_V8:
        os << "SHR2_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::ASHR2_IMM8_V8:
        os << "ASHR2_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::AND2_IMM8_V8:
        os << "AND2_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::OR2_IMM8_V8:
        os << "OR2_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::XOR2_IMM8_V8:
        os << "XOR2_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::EXP_IMM8_V8:
        os << "EXP_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::TYPEOF_IMM8:
        os << "TYPEOF_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::TONUMBER_IMM8:
        os << "TONUMBER_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::TONUMERIC_IMM8:
        os << "TONUMERIC_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::NEG_IMM8:
        os << "NEG_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::NOT_IMM8:
        os << "NOT_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::INC_IMM8:
        os << "INC_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::DEC_IMM8:
        os << "DEC_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::ISTRUE:
        os << "ISTRUE";
        break;
    case BytecodeInst<Mode>::Opcode::ISFALSE:
        os << "ISFALSE";
        break;
    case BytecodeInst<Mode>::Opcode::ISIN_IMM8_V8:
        os << "ISIN_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::INSTANCEOF_IMM8_V8:
        os << "INSTANCEOF_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::STRICTNOTEQ_IMM8_V8:
        os << "STRICTNOTEQ_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::STRICTEQ_IMM8_V8:
        os << "STRICTEQ_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLARG0_IMM8:
        os << "CALLARG0_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLARG1_IMM8_V8:
        os << "CALLARG1_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLARGS2_IMM8_V8_V8:
        os << "CALLARGS2_IMM8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLARGS3_IMM8_V8_V8_V8:
        os << "CALLARGS3_IMM8_V8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS0_IMM8_V8:
        os << "CALLTHIS0_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS1_IMM8_V8_V8:
        os << "CALLTHIS1_IMM8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS2_IMM8_V8_V8_V8:
        os << "CALLTHIS2_IMM8_V8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS3_IMM8_V8_V8_V8_V8:
        os << "CALLTHIS3_IMM8_V8_V8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGE_IMM8_IMM8_V8:
        os << "CALLTHISRANGE_IMM8_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::SUPERCALLTHISRANGE_IMM8_IMM8_V8:
        os << "SUPERCALLTHISRANGE_IMM8_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEFUNC_IMM8_ID16_IMM8:
        os << "DEFINEFUNC_IMM8_ID16_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEMETHOD_IMM8_ID16_IMM8:
        os << "DEFINEMETHOD_IMM8_ID16_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::DEFINECLASSWITHBUFFER_IMM8_ID16_ID16_IMM16_V8:
        os << "DEFINECLASSWITHBUFFER_IMM8_ID16_ID16_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::GETNEXTPROPNAME_V8:
        os << "GETNEXTPROPNAME_V8";
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYVALUE_IMM8_V8:
        os << "LDOBJBYVALUE_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYVALUE_IMM8_V8_V8:
        os << "STOBJBYVALUE_IMM8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYVALUE_IMM8_V8:
        os << "LDSUPERBYVALUE_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYINDEX_IMM8_IMM16:
        os << "LDOBJBYINDEX_IMM8_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYINDEX_IMM8_V8_IMM16:
        os << "STOBJBYINDEX_IMM8_V8_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::LDLEXVAR_IMM4_IMM4:
        os << "LDLEXVAR_IMM4_IMM4";
        break;
    case BytecodeInst<Mode>::Opcode::STLEXVAR_IMM4_IMM4:
        os << "STLEXVAR_IMM4_IMM4";
        break;
    case BytecodeInst<Mode>::Opcode::LDA_STR_ID16:
        os << "LDA_STR_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::TRYLDGLOBALBYNAME_IMM8_ID16:
        os << "TRYLDGLOBALBYNAME_IMM8_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::TRYSTGLOBALBYNAME_IMM8_ID16:
        os << "TRYSTGLOBALBYNAME_IMM8_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::LDGLOBALVAR_IMM16_ID16:
        os << "LDGLOBALVAR_IMM16_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYNAME_IMM8_ID16:
        os << "LDOBJBYNAME_IMM8_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYNAME_IMM8_ID16_V8:
        os << "STOBJBYNAME_IMM8_ID16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::MOV_V4_V4:
        os << "MOV_V4_V4";
        break;
    case BytecodeInst<Mode>::Opcode::MOV_V8_V8:
        os << "MOV_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYNAME_IMM8_ID16:
        os << "LDSUPERBYNAME_IMM8_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::STCONSTTOGLOBALRECORD_IMM16_ID16:
        os << "STCONSTTOGLOBALRECORD_IMM16_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::STTOGLOBALRECORD_IMM16_ID16:
        os << "STTOGLOBALRECORD_IMM16_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::LDTHISBYNAME_IMM8_ID16:
        os << "LDTHISBYNAME_IMM8_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::STTHISBYNAME_IMM8_ID16:
        os << "STTHISBYNAME_IMM8_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::LDTHISBYVALUE_IMM8:
        os << "LDTHISBYVALUE_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::STTHISBYVALUE_IMM8_V8:
        os << "STTHISBYVALUE_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::JMP_IMM8:
        os << "JMP_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::JMP_IMM16:
        os << "JMP_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM8:
        os << "JEQZ_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM16:
        os << "JEQZ_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM8:
        os << "JNEZ_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM8:
        os << "JSTRICTEQZ_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM8:
        os << "JNSTRICTEQZ_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM8:
        os << "JEQNULL_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM8:
        os << "JNENULL_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM8:
        os << "JSTRICTEQNULL_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM8:
        os << "JNSTRICTEQNULL_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM8:
        os << "JEQUNDEFINED_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM8:
        os << "JNEUNDEFINED_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM8:
        os << "JSTRICTEQUNDEFINED_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM8:
        os << "JNSTRICTEQUNDEFINED_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM8:
        os << "JEQ_V8_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM8:
        os << "JNE_V8_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM8:
        os << "JSTRICTEQ_V8_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM8:
        os << "JNSTRICTEQ_V8_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::LDA_V8:
        os << "LDA_V8";
        break;
    case BytecodeInst<Mode>::Opcode::STA_V8:
        os << "STA_V8";
        break;
    case BytecodeInst<Mode>::Opcode::LDAI_IMM32:
        os << "LDAI_IMM32";
        break;
    case BytecodeInst<Mode>::Opcode::FLDAI_IMM64:
        os << "FLDAI_IMM64";
        break;
    case BytecodeInst<Mode>::Opcode::RETURN:
        os << "RETURN";
        break;
    case BytecodeInst<Mode>::Opcode::RETURNUNDEFINED:
        os << "RETURNUNDEFINED";
        break;
    case BytecodeInst<Mode>::Opcode::GETPROPITERATOR:
        os << "GETPROPITERATOR";
        break;
    case BytecodeInst<Mode>::Opcode::GETITERATOR_IMM8:
        os << "GETITERATOR_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::CLOSEITERATOR_IMM8_V8:
        os << "CLOSEITERATOR_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::POPLEXENV:
        os << "POPLEXENV";
        break;
    case BytecodeInst<Mode>::Opcode::LDNAN:
        os << "LDNAN";
        break;
    case BytecodeInst<Mode>::Opcode::LDINFINITY:
        os << "LDINFINITY";
        break;
    case BytecodeInst<Mode>::Opcode::GETUNMAPPEDARGS:
        os << "GETUNMAPPEDARGS";
        break;
    case BytecodeInst<Mode>::Opcode::LDGLOBAL:
        os << "LDGLOBAL";
        break;
    case BytecodeInst<Mode>::Opcode::LDNEWTARGET:
        os << "LDNEWTARGET";
        break;
    case BytecodeInst<Mode>::Opcode::LDTHIS:
        os << "LDTHIS";
        break;
    case BytecodeInst<Mode>::Opcode::LDHOLE:
        os << "LDHOLE";
        break;
    case BytecodeInst<Mode>::Opcode::CREATEREGEXPWITHLITERAL_IMM8_ID16_IMM8:
        os << "CREATEREGEXPWITHLITERAL_IMM8_ID16_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::CREATEREGEXPWITHLITERAL_IMM16_ID16_IMM8:
        os << "CREATEREGEXPWITHLITERAL_IMM16_ID16_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRANGE_IMM8_IMM8_V8:
        os << "CALLRANGE_IMM8_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEFUNC_IMM16_ID16_IMM8:
        os << "DEFINEFUNC_IMM16_ID16_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::DEFINECLASSWITHBUFFER_IMM16_ID16_ID16_IMM16_V8:
        os << "DEFINECLASSWITHBUFFER_IMM16_ID16_ID16_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::GETTEMPLATEOBJECT_IMM8:
        os << "GETTEMPLATEOBJECT_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::SETOBJECTWITHPROTO_IMM8_V8:
        os << "SETOBJECTWITHPROTO_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUE_IMM8_V8_V8:
        os << "STOWNBYVALUE_IMM8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYINDEX_IMM8_V8_IMM16:
        os << "STOWNBYINDEX_IMM8_V8_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAME_IMM8_ID16_V8:
        os << "STOWNBYNAME_IMM8_ID16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::GETMODULENAMESPACE_IMM8:
        os << "GETMODULENAMESPACE_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::STMODULEVAR_IMM8:
        os << "STMODULEVAR_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::LDLOCALMODULEVAR_IMM8:
        os << "LDLOCALMODULEVAR_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::LDEXTERNALMODULEVAR_IMM8:
        os << "LDEXTERNALMODULEVAR_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::STGLOBALVAR_IMM16_ID16:
        os << "STGLOBALVAR_IMM16_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYARRAY_IMM16:
        os << "CREATEEMPTYARRAY_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::CREATEARRAYWITHBUFFER_IMM16_ID16:
        os << "CREATEARRAYWITHBUFFER_IMM16_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHBUFFER_IMM16_ID16:
        os << "CREATEOBJECTWITHBUFFER_IMM16_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM16_IMM8_V8:
        os << "NEWOBJRANGE_IMM16_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::TYPEOF_IMM16:
        os << "TYPEOF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYVALUE_IMM16_V8:
        os << "LDOBJBYVALUE_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYVALUE_IMM16_V8_V8:
        os << "STOBJBYVALUE_IMM16_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYVALUE_IMM16_V8:
        os << "LDSUPERBYVALUE_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYINDEX_IMM16_IMM16:
        os << "LDOBJBYINDEX_IMM16_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYINDEX_IMM16_V8_IMM16:
        os << "STOBJBYINDEX_IMM16_V8_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::LDLEXVAR_IMM8_IMM8:
        os << "LDLEXVAR_IMM8_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::STLEXVAR_IMM8_IMM8:
        os << "STLEXVAR_IMM8_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::TRYLDGLOBALBYNAME_IMM16_ID16:
        os << "TRYLDGLOBALBYNAME_IMM16_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::TRYSTGLOBALBYNAME_IMM16_ID16:
        os << "TRYSTGLOBALBYNAME_IMM16_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAMEWITHNAMESET_IMM8_ID16_V8:
        os << "STOWNBYNAMEWITHNAMESET_IMM8_ID16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::MOV_V16_V16:
        os << "MOV_V16_V16";
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYNAME_IMM16_ID16:
        os << "LDOBJBYNAME_IMM16_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYNAME_IMM16_ID16_V8:
        os << "STOBJBYNAME_IMM16_ID16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYNAME_IMM16_ID16:
        os << "LDSUPERBYNAME_IMM16_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::LDTHISBYNAME_IMM16_ID16:
        os << "LDTHISBYNAME_IMM16_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::STTHISBYNAME_IMM16_ID16:
        os << "STTHISBYNAME_IMM16_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::LDTHISBYVALUE_IMM16:
        os << "LDTHISBYVALUE_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::STTHISBYVALUE_IMM16_V8:
        os << "STTHISBYVALUE_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCGENERATORREJECT_V8:
        os << "ASYNCGENERATORREJECT_V8";
        break;
    case BytecodeInst<Mode>::Opcode::JMP_IMM32:
        os << "JMP_IMM32";
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUEWITHNAMESET_IMM8_V8_V8:
        os << "STOWNBYVALUEWITHNAMESET_IMM8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM32:
        os << "JEQZ_IMM32";
        break;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM16:
        os << "JNEZ_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM32:
        os << "JNEZ_IMM32";
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM16:
        os << "JSTRICTEQZ_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM16:
        os << "JNSTRICTEQZ_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM16:
        os << "JEQNULL_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM16:
        os << "JNENULL_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM16:
        os << "JSTRICTEQNULL_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM16:
        os << "JNSTRICTEQNULL_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM16:
        os << "JEQUNDEFINED_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM16:
        os << "JNEUNDEFINED_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM16:
        os << "JSTRICTEQUNDEFINED_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM16:
        os << "JNSTRICTEQUNDEFINED_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM16:
        os << "JEQ_V8_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM16:
        os << "JNE_V8_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM16:
        os << "JSTRICTEQ_V8_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM16:
        os << "JNSTRICTEQ_V8_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::GETITERATOR_IMM16:
        os << "GETITERATOR_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::CLOSEITERATOR_IMM16_V8:
        os << "CLOSEITERATOR_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::LDSYMBOL:
        os << "LDSYMBOL";
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONENTER:
        os << "ASYNCFUNCTIONENTER";
        break;
    case BytecodeInst<Mode>::Opcode::LDFUNCTION:
        os << "LDFUNCTION";
        break;
    case BytecodeInst<Mode>::Opcode::DEBUGGER:
        os << "DEBUGGER";
        break;
    case BytecodeInst<Mode>::Opcode::CREATEGENERATOROBJ_V8:
        os << "CREATEGENERATOROBJ_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CREATEITERRESULTOBJ_V8_V8:
        os << "CREATEITERRESULTOBJ_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHEXCLUDEDKEYS_IMM8_V8_V8:
        os << "CREATEOBJECTWITHEXCLUDEDKEYS_IMM8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::NEWOBJAPPLY_IMM8_V8:
        os << "NEWOBJAPPLY_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::NEWOBJAPPLY_IMM16_V8:
        os << "NEWOBJAPPLY_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::NEWLEXENVWITHNAME_IMM8_ID16:
        os << "NEWLEXENVWITHNAME_IMM8_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::CREATEASYNCGENERATOROBJ_V8:
        os << "CREATEASYNCGENERATOROBJ_V8";
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCGENERATORRESOLVE_V8_V8_V8:
        os << "ASYNCGENERATORRESOLVE_V8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::SUPERCALLSPREAD_IMM8_V8:
        os << "SUPERCALLSPREAD_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::APPLY_IMM8_V8_V8:
        os << "APPLY_IMM8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::SUPERCALLARROWRANGE_IMM8_IMM8_V8:
        os << "SUPERCALLARROWRANGE_IMM8_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEGETTERSETTERBYVALUE_V8_V8_V8_V8:
        os << "DEFINEGETTERSETTERBYVALUE_V8_V8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DYNAMICIMPORT:
        os << "DYNAMICIMPORT";
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEMETHOD_IMM16_ID16_IMM8:
        os << "DEFINEMETHOD_IMM16_ID16_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::RESUMEGENERATOR:
        os << "RESUMEGENERATOR";
        break;
    case BytecodeInst<Mode>::Opcode::GETRESUMEMODE:
        os << "GETRESUMEMODE";
        break;
    case BytecodeInst<Mode>::Opcode::GETTEMPLATEOBJECT_IMM16:
        os << "GETTEMPLATEOBJECT_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::DELOBJPROP_V8:
        os << "DELOBJPROP_V8";
        break;
    case BytecodeInst<Mode>::Opcode::SUSPENDGENERATOR_V8:
        os << "SUSPENDGENERATOR_V8";
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONAWAITUNCAUGHT_V8:
        os << "ASYNCFUNCTIONAWAITUNCAUGHT_V8";
        break;
    case BytecodeInst<Mode>::Opcode::COPYDATAPROPERTIES_V8:
        os << "COPYDATAPROPERTIES_V8";
        break;
    case BytecodeInst<Mode>::Opcode::STARRAYSPREAD_V8_V8:
        os << "STARRAYSPREAD_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::SETOBJECTWITHPROTO_IMM16_V8:
        os << "SETOBJECTWITHPROTO_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUE_IMM16_V8_V8:
        os << "STOWNBYVALUE_IMM16_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::STSUPERBYVALUE_IMM8_V8_V8:
        os << "STSUPERBYVALUE_IMM8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::STSUPERBYVALUE_IMM16_V8_V8:
        os << "STSUPERBYVALUE_IMM16_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYINDEX_IMM16_V8_IMM16:
        os << "STOWNBYINDEX_IMM16_V8_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAME_IMM16_ID16_V8:
        os << "STOWNBYNAME_IMM16_ID16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONRESOLVE_V8:
        os << "ASYNCFUNCTIONRESOLVE_V8";
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONREJECT_V8:
        os << "ASYNCFUNCTIONREJECT_V8";
        break;
    case BytecodeInst<Mode>::Opcode::COPYRESTARGS_IMM8:
        os << "COPYRESTARGS_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::STSUPERBYNAME_IMM8_ID16_V8:
        os << "STSUPERBYNAME_IMM8_ID16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::STSUPERBYNAME_IMM16_ID16_V8:
        os << "STSUPERBYNAME_IMM16_ID16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUEWITHNAMESET_IMM16_V8_V8:
        os << "STOWNBYVALUEWITHNAMESET_IMM16_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::LDBIGINT_ID16:
        os << "LDBIGINT_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAMEWITHNAMESET_IMM16_ID16_V8:
        os << "STOWNBYNAMEWITHNAMESET_IMM16_ID16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::NOP:
        os << "NOP";
        break;
    case BytecodeInst<Mode>::Opcode::SETGENERATORSTATE_IMM8:
        os << "SETGENERATORSTATE_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::GETASYNCITERATOR_IMM8:
        os << "GETASYNCITERATOR_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::LDPRIVATEPROPERTY_IMM8_IMM16_IMM16:
        os << "LDPRIVATEPROPERTY_IMM8_IMM16_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::STPRIVATEPROPERTY_IMM8_IMM16_IMM16_V8:
        os << "STPRIVATEPROPERTY_IMM8_IMM16_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::TESTIN_IMM8_IMM16_IMM16:
        os << "TESTIN_IMM8_IMM16_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEFIELDBYNAME_IMM8_ID16_V8:
        os << "DEFINEFIELDBYNAME_IMM8_ID16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEPROPERTYBYNAME_IMM8_ID16_V8:
        os << "DEFINEPROPERTYBYNAME_IMM8_ID16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS0WITHNAME_IMM8_ID16_V8:
        os << "CALLTHIS0WITHNAME_IMM8_ID16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS1WITHNAME_IMM8_ID16_V8_V8:
        os << "CALLTHIS1WITHNAME_IMM8_ID16_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS2WITHNAME_IMM8_ID16_V8_V8_V8:
        os << "CALLTHIS2WITHNAME_IMM8_ID16_V8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS3WITHNAME_IMM8_ID16_V8_V8_V8_V8:
        os << "CALLTHIS3WITHNAME_IMM8_ID16_V8_V8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGEWITHNAME_IMM8_IMM8_ID16_V8:
        os << "CALLTHISRANGEWITHNAME_IMM8_IMM8_ID16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_NOTIFYCONCURRENTRESULT_PREF_NONE:
        os << "CALLRUNTIME_NOTIFYCONCURRENTRESULT_PREF_NONE";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDLEXENV_PREF_NONE:
        os << "DEPRECATED_LDLEXENV_PREF_NONE";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_CREATEOBJECTWITHEXCLUDEDKEYS_PREF_IMM16_V8_V8:
        os << "WIDE_CREATEOBJECTWITHEXCLUDEDKEYS_PREF_IMM16_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::THROW_PREF_NONE:
        os << "THROW_PREF_NONE";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEFIELDBYVALUE_PREF_IMM8_V8_V8:
        os << "CALLRUNTIME_DEFINEFIELDBYVALUE_PREF_IMM8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_POPLEXENV_PREF_NONE:
        os << "DEPRECATED_POPLEXENV_PREF_NONE";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWOBJRANGE_PREF_IMM16_V8:
        os << "WIDE_NEWOBJRANGE_PREF_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::THROW_NOTEXISTS_PREF_NONE:
        os << "THROW_NOTEXISTS_PREF_NONE";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEFIELDBYINDEX_PREF_IMM8_IMM32_V8:
        os << "CALLRUNTIME_DEFINEFIELDBYINDEX_PREF_IMM8_IMM32_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETITERATORNEXT_PREF_V8_V8:
        os << "DEPRECATED_GETITERATORNEXT_PREF_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWLEXENV_PREF_IMM16:
        os << "WIDE_NEWLEXENV_PREF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::THROW_PATTERNNONCOERCIBLE_PREF_NONE:
        os << "THROW_PATTERNNONCOERCIBLE_PREF_NONE";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_TOPROPERTYKEY_PREF_NONE:
        os << "CALLRUNTIME_TOPROPERTYKEY_PREF_NONE";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEARRAYWITHBUFFER_PREF_IMM16:
        os << "DEPRECATED_CREATEARRAYWITHBUFFER_PREF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWLEXENVWITHNAME_PREF_IMM16_ID16:
        os << "WIDE_NEWLEXENVWITHNAME_PREF_IMM16_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::THROW_DELETESUPERPROPERTY_PREF_NONE:
        os << "THROW_DELETESUPERPROPERTY_PREF_NONE";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_CREATEPRIVATEPROPERTY_PREF_IMM16_ID16:
        os << "CALLRUNTIME_CREATEPRIVATEPROPERTY_PREF_IMM16_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEOBJECTWITHBUFFER_PREF_IMM16:
        os << "DEPRECATED_CREATEOBJECTWITHBUFFER_PREF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLRANGE_PREF_IMM16_V8:
        os << "WIDE_CALLRANGE_PREF_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::THROW_CONSTASSIGNMENT_PREF_V8:
        os << "THROW_CONSTASSIGNMENT_PREF_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEPRIVATEPROPERTY_PREF_IMM8_IMM16_IMM16_V8:
        os << "CALLRUNTIME_DEFINEPRIVATEPROPERTY_PREF_IMM8_IMM16_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_TONUMBER_PREF_V8:
        os << "DEPRECATED_TONUMBER_PREF_V8";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGE_PREF_IMM16_V8:
        os << "WIDE_CALLTHISRANGE_PREF_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::THROW_IFNOTOBJECT_PREF_V8:
        os << "THROW_IFNOTOBJECT_PREF_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_CALLINIT_PREF_IMM8_V8:
        os << "CALLRUNTIME_CALLINIT_PREF_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_TONUMERIC_PREF_V8:
        os << "DEPRECATED_TONUMERIC_PREF_V8";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLTHISRANGE_PREF_IMM16_V8:
        os << "WIDE_SUPERCALLTHISRANGE_PREF_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::THROW_UNDEFINEDIFHOLE_PREF_V8_V8:
        os << "THROW_UNDEFINEDIFHOLE_PREF_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINESENDABLECLASS_PREF_IMM16_ID16_ID16_IMM16_V8:
        os << "CALLRUNTIME_DEFINESENDABLECLASS_PREF_IMM16_ID16_ID16_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_NEG_PREF_V8:
        os << "DEPRECATED_NEG_PREF_V8";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLARROWRANGE_PREF_IMM16_V8:
        os << "WIDE_SUPERCALLARROWRANGE_PREF_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::THROW_IFSUPERNOTCORRECTCALL_PREF_IMM8:
        os << "THROW_IFSUPERNOTCORRECTCALL_PREF_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLECLASS_PREF_IMM16:
        os << "CALLRUNTIME_LDSENDABLECLASS_PREF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_NOT_PREF_V8:
        os << "DEPRECATED_NOT_PREF_V8";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDOBJBYINDEX_PREF_IMM32:
        os << "WIDE_LDOBJBYINDEX_PREF_IMM32";
        break;
    case BytecodeInst<Mode>::Opcode::THROW_IFSUPERNOTCORRECTCALL_PREF_IMM16:
        os << "THROW_IFSUPERNOTCORRECTCALL_PREF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEEXTERNALMODULEVAR_PREF_IMM8:
        os << "CALLRUNTIME_LDSENDABLEEXTERNALMODULEVAR_PREF_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_INC_PREF_V8:
        os << "DEPRECATED_INC_PREF_V8";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STOBJBYINDEX_PREF_V8_IMM32:
        os << "WIDE_STOBJBYINDEX_PREF_V8_IMM32";
        break;
    case BytecodeInst<Mode>::Opcode::THROW_UNDEFINEDIFHOLEWITHNAME_PREF_ID16:
        os << "THROW_UNDEFINEDIFHOLEWITHNAME_PREF_ID16";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLEEXTERNALMODULEVAR_PREF_IMM16:
        os << "CALLRUNTIME_WIDELDSENDABLEEXTERNALMODULEVAR_PREF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DEC_PREF_V8:
        os << "DEPRECATED_DEC_PREF_V8";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STOWNBYINDEX_PREF_V8_IMM32:
        os << "WIDE_STOWNBYINDEX_PREF_V8_IMM32";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_NEWSENDABLEENV_PREF_IMM8:
        os << "CALLRUNTIME_NEWSENDABLEENV_PREF_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARG0_PREF_V8:
        os << "DEPRECATED_CALLARG0_PREF_V8";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_COPYRESTARGS_PREF_IMM16:
        os << "WIDE_COPYRESTARGS_PREF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDENEWSENDABLEENV_PREF_IMM16:
        os << "CALLRUNTIME_WIDENEWSENDABLEENV_PREF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARG1_PREF_V8_V8:
        os << "DEPRECATED_CALLARG1_PREF_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDLEXVAR_PREF_IMM16_IMM16:
        os << "WIDE_LDLEXVAR_PREF_IMM16_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_STSENDABLEVAR_PREF_IMM4_IMM4:
        os << "CALLRUNTIME_STSENDABLEVAR_PREF_IMM4_IMM4";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARGS2_PREF_V8_V8_V8:
        os << "DEPRECATED_CALLARGS2_PREF_V8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STLEXVAR_PREF_IMM16_IMM16:
        os << "WIDE_STLEXVAR_PREF_IMM16_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_STSENDABLEVAR_PREF_IMM8_IMM8:
        os << "CALLRUNTIME_STSENDABLEVAR_PREF_IMM8_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARGS3_PREF_V8_V8_V8_V8:
        os << "DEPRECATED_CALLARGS3_PREF_V8_V8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_GETMODULENAMESPACE_PREF_IMM16:
        os << "WIDE_GETMODULENAMESPACE_PREF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDESTSENDABLEVAR_PREF_IMM16_IMM16:
        os << "CALLRUNTIME_WIDESTSENDABLEVAR_PREF_IMM16_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLRANGE_PREF_IMM16_V8:
        os << "DEPRECATED_CALLRANGE_PREF_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STMODULEVAR_PREF_IMM16:
        os << "WIDE_STMODULEVAR_PREF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEVAR_PREF_IMM4_IMM4:
        os << "CALLRUNTIME_LDSENDABLEVAR_PREF_IMM4_IMM4";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLSPREAD_PREF_V8_V8_V8:
        os << "DEPRECATED_CALLSPREAD_PREF_V8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDLOCALMODULEVAR_PREF_IMM16:
        os << "WIDE_LDLOCALMODULEVAR_PREF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEVAR_PREF_IMM8_IMM8:
        os << "CALLRUNTIME_LDSENDABLEVAR_PREF_IMM8_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLTHISRANGE_PREF_IMM16_V8:
        os << "DEPRECATED_CALLTHISRANGE_PREF_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDEXTERNALMODULEVAR_PREF_IMM16:
        os << "WIDE_LDEXTERNALMODULEVAR_PREF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLEVAR_PREF_IMM16_IMM16:
        os << "CALLRUNTIME_WIDELDSENDABLEVAR_PREF_IMM16_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DEFINECLASSWITHBUFFER_PREF_ID16_IMM16_IMM16_V8_V8:
        os << "DEPRECATED_DEFINECLASSWITHBUFFER_PREF_ID16_IMM16_IMM16_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDPATCHVAR_PREF_IMM16:
        os << "WIDE_LDPATCHVAR_PREF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_ISTRUE_PREF_IMM8:
        os << "CALLRUNTIME_ISTRUE_PREF_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_RESUMEGENERATOR_PREF_V8:
        os << "DEPRECATED_RESUMEGENERATOR_PREF_V8";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STPATCHVAR_PREF_IMM16:
        os << "WIDE_STPATCHVAR_PREF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_ISFALSE_PREF_IMM8:
        os << "CALLRUNTIME_ISFALSE_PREF_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETRESUMEMODE_PREF_V8:
        os << "DEPRECATED_GETRESUMEMODE_PREF_V8";
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGEWITHNAME_PREF_IMM16_ID16_V8:
        os << "WIDE_CALLTHISRANGEWITHNAME_PREF_IMM16_ID16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDLAZYMODULEVAR_PREF_IMM8:
        os << "CALLRUNTIME_LDLAZYMODULEVAR_PREF_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETTEMPLATEOBJECT_PREF_V8:
        os << "DEPRECATED_GETTEMPLATEOBJECT_PREF_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDLAZYMODULEVAR_PREF_IMM16:
        os << "CALLRUNTIME_WIDELDLAZYMODULEVAR_PREF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DELOBJPROP_PREF_V8_V8:
        os << "DEPRECATED_DELOBJPROP_PREF_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDLAZYSENDABLEMODULEVAR_PREF_IMM8:
        os << "CALLRUNTIME_LDLAZYSENDABLEMODULEVAR_PREF_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_SUSPENDGENERATOR_PREF_V8_V8:
        os << "DEPRECATED_SUSPENDGENERATOR_PREF_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDLAZYSENDABLEMODULEVAR_PREF_IMM16:
        os << "CALLRUNTIME_WIDELDLAZYSENDABLEMODULEVAR_PREF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONAWAITUNCAUGHT_PREF_V8_V8:
        os << "DEPRECATED_ASYNCFUNCTIONAWAITUNCAUGHT_PREF_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_SUPERCALLFORWARDALLARGS_PREF_V8:
        os << "CALLRUNTIME_SUPERCALLFORWARDALLARGS_PREF_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_COPYDATAPROPERTIES_PREF_V8_V8:
        os << "DEPRECATED_COPYDATAPROPERTIES_PREF_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLELOCALMODULEVAR_PREF_IMM8:
        os << "CALLRUNTIME_LDSENDABLELOCALMODULEVAR_PREF_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_SETOBJECTWITHPROTO_PREF_V8_V8:
        os << "DEPRECATED_SETOBJECTWITHPROTO_PREF_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLELOCALMODULEVAR_PREF_IMM16:
        os << "CALLRUNTIME_WIDELDSENDABLELOCALMODULEVAR_PREF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYVALUE_PREF_V8_V8:
        os << "DEPRECATED_LDOBJBYVALUE_PREF_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDSUPERBYVALUE_PREF_V8_V8:
        os << "DEPRECATED_LDSUPERBYVALUE_PREF_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYINDEX_PREF_V8_IMM32:
        os << "DEPRECATED_LDOBJBYINDEX_PREF_V8_IMM32";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONRESOLVE_PREF_V8_V8_V8:
        os << "DEPRECATED_ASYNCFUNCTIONRESOLVE_PREF_V8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONREJECT_PREF_V8_V8_V8:
        os << "DEPRECATED_ASYNCFUNCTIONREJECT_PREF_V8_V8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM4_IMM4_V8:
        os << "DEPRECATED_STLEXVAR_PREF_IMM4_IMM4_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM8_IMM8_V8:
        os << "DEPRECATED_STLEXVAR_PREF_IMM8_IMM8_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM16_IMM16_V8:
        os << "DEPRECATED_STLEXVAR_PREF_IMM16_IMM16_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETMODULENAMESPACE_PREF_ID32:
        os << "DEPRECATED_GETMODULENAMESPACE_PREF_ID32";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STMODULEVAR_PREF_ID32:
        os << "DEPRECATED_STMODULEVAR_PREF_ID32";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYNAME_PREF_ID32_V8:
        os << "DEPRECATED_LDOBJBYNAME_PREF_ID32_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDSUPERBYNAME_PREF_ID32_V8:
        os << "DEPRECATED_LDSUPERBYNAME_PREF_ID32_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDMODULEVAR_PREF_ID32_IMM8:
        os << "DEPRECATED_LDMODULEVAR_PREF_ID32_IMM8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STCONSTTOGLOBALRECORD_PREF_ID32:
        os << "DEPRECATED_STCONSTTOGLOBALRECORD_PREF_ID32";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLETTOGLOBALRECORD_PREF_ID32:
        os << "DEPRECATED_STLETTOGLOBALRECORD_PREF_ID32";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STCLASSTOGLOBALRECORD_PREF_ID32:
        os << "DEPRECATED_STCLASSTOGLOBALRECORD_PREF_ID32";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDHOMEOBJECT_PREF_NONE:
        os << "DEPRECATED_LDHOMEOBJECT_PREF_NONE";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEOBJECTHAVINGMETHOD_PREF_IMM16:
        os << "DEPRECATED_CREATEOBJECTHAVINGMETHOD_PREF_IMM16";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DYNAMICIMPORT_PREF_V8:
        os << "DEPRECATED_DYNAMICIMPORT_PREF_V8";
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCGENERATORREJECT_PREF_V8_V8:
        os << "DEPRECATED_ASYNCGENERATORREJECT_PREF_V8_V8";
        break;
    default:
        os << "(unknown opcode:) " << static_cast<uint16_t>(op);
        break;

    }
    return os;
}

template <const BytecodeInstMode Mode>
inline bool BytecodeInst<Mode>::IsPrimaryOpcodeValid() const
{
    auto opcode = GetPrimaryOpcode();
    // NOLINTNEXTLINE(readability-magic-numbers)
    if (((opcode >= 226) &&
        // NOLINTNEXTLINE(readability-magic-numbers)
        (opcode <= 250)) ||
        // NOLINTNEXTLINE(readability-magic-numbers)
        ((opcode >= 255) &&
        // NOLINTNEXTLINE(readability-magic-numbers)
        (opcode <= 255))) {
        // NOLINTNEXTLINE(readability-simplify-boolean-expr)
        return false;
    }
    return true;
}

// NOLINTNEXTLINE(readability-function-size)
template<const BytecodeInstMode Mode> inline size_t BytecodeInst<Mode>::GetLiteralIndex() const {
    switch(GetOpcode()) {
    case BytecodeInst<Mode>::Opcode::LDUNDEFINED:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDNULL:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDTRUE:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDFALSE:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYOBJECT:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYARRAY_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CREATEARRAYWITHBUFFER_IMM8_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHBUFFER_IMM8_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM8_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::NEWLEXENV_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::ADD2_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::SUB2_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::MUL2_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DIV2_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::MOD2_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::EQ_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::NOTEQ_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LESS_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LESSEQ_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::GREATER_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::GREATEREQ_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::SHL2_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::SHR2_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::ASHR2_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::AND2_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::OR2_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::XOR2_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::EXP_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::TYPEOF_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::TONUMBER_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::TONUMERIC_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::NEG_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::NOT_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::INC_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEC_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::ISTRUE:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::ISFALSE:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::ISIN_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::INSTANCEOF_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STRICTNOTEQ_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STRICTEQ_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLARG0_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLARG1_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLARGS2_IMM8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLARGS3_IMM8_V8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS0_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS1_IMM8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS2_IMM8_V8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS3_IMM8_V8_V8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGE_IMM8_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::SUPERCALLTHISRANGE_IMM8_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEFUNC_IMM8_ID16_IMM8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEMETHOD_IMM8_ID16_IMM8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::DEFINECLASSWITHBUFFER_IMM8_ID16_ID16_IMM16_V8:
        return 1;
        break;
    case BytecodeInst<Mode>::Opcode::GETNEXTPROPNAME_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYVALUE_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYVALUE_IMM8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYVALUE_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYINDEX_IMM8_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYINDEX_IMM8_V8_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDLEXVAR_IMM4_IMM4:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STLEXVAR_IMM4_IMM4:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDA_STR_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::TRYLDGLOBALBYNAME_IMM8_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::TRYSTGLOBALBYNAME_IMM8_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::LDGLOBALVAR_IMM16_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYNAME_IMM8_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYNAME_IMM8_ID16_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::MOV_V4_V4:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::MOV_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYNAME_IMM8_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::STCONSTTOGLOBALRECORD_IMM16_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::STTOGLOBALRECORD_IMM16_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::LDTHISBYNAME_IMM8_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::STTHISBYNAME_IMM8_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::LDTHISBYVALUE_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STTHISBYVALUE_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JMP_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JMP_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDA_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STA_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDAI_IMM32:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::FLDAI_IMM64:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::RETURN:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::RETURNUNDEFINED:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::GETPROPITERATOR:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::GETITERATOR_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CLOSEITERATOR_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::POPLEXENV:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDNAN:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDINFINITY:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::GETUNMAPPEDARGS:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDGLOBAL:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDNEWTARGET:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDTHIS:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDHOLE:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CREATEREGEXPWITHLITERAL_IMM8_ID16_IMM8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::CREATEREGEXPWITHLITERAL_IMM16_ID16_IMM8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRANGE_IMM8_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEFUNC_IMM16_ID16_IMM8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::DEFINECLASSWITHBUFFER_IMM16_ID16_ID16_IMM16_V8:
        return 1;
        break;
    case BytecodeInst<Mode>::Opcode::GETTEMPLATEOBJECT_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::SETOBJECTWITHPROTO_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUE_IMM8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYINDEX_IMM8_V8_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAME_IMM8_ID16_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::GETMODULENAMESPACE_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STMODULEVAR_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDLOCALMODULEVAR_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDEXTERNALMODULEVAR_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STGLOBALVAR_IMM16_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::CREATEEMPTYARRAY_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CREATEARRAYWITHBUFFER_IMM16_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHBUFFER_IMM16_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM16_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::TYPEOF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYVALUE_IMM16_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYVALUE_IMM16_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYVALUE_IMM16_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYINDEX_IMM16_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYINDEX_IMM16_V8_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDLEXVAR_IMM8_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STLEXVAR_IMM8_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::TRYLDGLOBALBYNAME_IMM16_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::TRYSTGLOBALBYNAME_IMM16_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAMEWITHNAMESET_IMM8_ID16_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::MOV_V16_V16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDOBJBYNAME_IMM16_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::STOBJBYNAME_IMM16_ID16_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::LDSUPERBYNAME_IMM16_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::LDTHISBYNAME_IMM16_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::STTHISBYNAME_IMM16_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::LDTHISBYVALUE_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STTHISBYVALUE_IMM16_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCGENERATORREJECT_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JMP_IMM32:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUEWITHNAMESET_IMM8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM32:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM32:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::GETITERATOR_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CLOSEITERATOR_IMM16_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDSYMBOL:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONENTER:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDFUNCTION:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEBUGGER:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CREATEGENERATOROBJ_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CREATEITERRESULTOBJ_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHEXCLUDEDKEYS_IMM8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::NEWOBJAPPLY_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::NEWOBJAPPLY_IMM16_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::NEWLEXENVWITHNAME_IMM8_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::CREATEASYNCGENERATOROBJ_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCGENERATORRESOLVE_V8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::SUPERCALLSPREAD_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::APPLY_IMM8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::SUPERCALLARROWRANGE_IMM8_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEGETTERSETTERBYVALUE_V8_V8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DYNAMICIMPORT:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEMETHOD_IMM16_ID16_IMM8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::RESUMEGENERATOR:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::GETRESUMEMODE:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::GETTEMPLATEOBJECT_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DELOBJPROP_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::SUSPENDGENERATOR_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONAWAITUNCAUGHT_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::COPYDATAPROPERTIES_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STARRAYSPREAD_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::SETOBJECTWITHPROTO_IMM16_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUE_IMM16_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STSUPERBYVALUE_IMM8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STSUPERBYVALUE_IMM16_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYINDEX_IMM16_V8_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAME_IMM16_ID16_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONRESOLVE_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::ASYNCFUNCTIONREJECT_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::COPYRESTARGS_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STSUPERBYNAME_IMM8_ID16_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::STSUPERBYNAME_IMM16_ID16_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYVALUEWITHNAMESET_IMM16_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDBIGINT_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::STOWNBYNAMEWITHNAMESET_IMM16_ID16_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::NOP:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::SETGENERATORSTATE_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::GETASYNCITERATOR_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::LDPRIVATEPROPERTY_IMM8_IMM16_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::STPRIVATEPROPERTY_IMM8_IMM16_IMM16_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::TESTIN_IMM8_IMM16_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEFIELDBYNAME_IMM8_ID16_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::DEFINEPROPERTYBYNAME_IMM8_ID16_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS0WITHNAME_IMM8_ID16_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS1WITHNAME_IMM8_ID16_V8_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS2WITHNAME_IMM8_ID16_V8_V8_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHIS3WITHNAME_IMM8_ID16_V8_V8_V8_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGEWITHNAME_IMM8_IMM8_ID16_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_NOTIFYCONCURRENTRESULT_PREF_NONE:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDLEXENV_PREF_NONE:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_CREATEOBJECTWITHEXCLUDEDKEYS_PREF_IMM16_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::THROW_PREF_NONE:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEFIELDBYVALUE_PREF_IMM8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_POPLEXENV_PREF_NONE:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWOBJRANGE_PREF_IMM16_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::THROW_NOTEXISTS_PREF_NONE:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEFIELDBYINDEX_PREF_IMM8_IMM32_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETITERATORNEXT_PREF_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWLEXENV_PREF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::THROW_PATTERNNONCOERCIBLE_PREF_NONE:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_TOPROPERTYKEY_PREF_NONE:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEARRAYWITHBUFFER_PREF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWLEXENVWITHNAME_PREF_IMM16_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::THROW_DELETESUPERPROPERTY_PREF_NONE:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_CREATEPRIVATEPROPERTY_PREF_IMM16_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEOBJECTWITHBUFFER_PREF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLRANGE_PREF_IMM16_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::THROW_CONSTASSIGNMENT_PREF_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINEPRIVATEPROPERTY_PREF_IMM8_IMM16_IMM16_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_TONUMBER_PREF_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGE_PREF_IMM16_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::THROW_IFNOTOBJECT_PREF_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_CALLINIT_PREF_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_TONUMERIC_PREF_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLTHISRANGE_PREF_IMM16_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::THROW_UNDEFINEDIFHOLE_PREF_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_DEFINESENDABLECLASS_PREF_IMM16_ID16_ID16_IMM16_V8:
        return 1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_NEG_PREF_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLARROWRANGE_PREF_IMM16_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::THROW_IFSUPERNOTCORRECTCALL_PREF_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLECLASS_PREF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_NOT_PREF_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDOBJBYINDEX_PREF_IMM32:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::THROW_IFSUPERNOTCORRECTCALL_PREF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEEXTERNALMODULEVAR_PREF_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_INC_PREF_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STOBJBYINDEX_PREF_V8_IMM32:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::THROW_UNDEFINEDIFHOLEWITHNAME_PREF_ID16:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLEEXTERNALMODULEVAR_PREF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DEC_PREF_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STOWNBYINDEX_PREF_V8_IMM32:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_NEWSENDABLEENV_PREF_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARG0_PREF_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_COPYRESTARGS_PREF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDENEWSENDABLEENV_PREF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARG1_PREF_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDLEXVAR_PREF_IMM16_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_STSENDABLEVAR_PREF_IMM4_IMM4:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARGS2_PREF_V8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STLEXVAR_PREF_IMM16_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_STSENDABLEVAR_PREF_IMM8_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLARGS3_PREF_V8_V8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_GETMODULENAMESPACE_PREF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDESTSENDABLEVAR_PREF_IMM16_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLRANGE_PREF_IMM16_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STMODULEVAR_PREF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEVAR_PREF_IMM4_IMM4:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLSPREAD_PREF_V8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDLOCALMODULEVAR_PREF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLEVAR_PREF_IMM8_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLTHISRANGE_PREF_IMM16_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDEXTERNALMODULEVAR_PREF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLEVAR_PREF_IMM16_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DEFINECLASSWITHBUFFER_PREF_ID16_IMM16_IMM16_V8_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_LDPATCHVAR_PREF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_ISTRUE_PREF_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_RESUMEGENERATOR_PREF_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_STPATCHVAR_PREF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_ISFALSE_PREF_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETRESUMEMODE_PREF_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGEWITHNAME_PREF_IMM16_ID16_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDLAZYMODULEVAR_PREF_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETTEMPLATEOBJECT_PREF_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDLAZYMODULEVAR_PREF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DELOBJPROP_PREF_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDLAZYSENDABLEMODULEVAR_PREF_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_SUSPENDGENERATOR_PREF_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDLAZYSENDABLEMODULEVAR_PREF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONAWAITUNCAUGHT_PREF_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_SUPERCALLFORWARDALLARGS_PREF_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_COPYDATAPROPERTIES_PREF_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_LDSENDABLELOCALMODULEVAR_PREF_IMM8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_SETOBJECTWITHPROTO_PREF_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::CALLRUNTIME_WIDELDSENDABLELOCALMODULEVAR_PREF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYVALUE_PREF_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDSUPERBYVALUE_PREF_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYINDEX_PREF_V8_IMM32:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONRESOLVE_PREF_V8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCFUNCTIONREJECT_PREF_V8_V8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM4_IMM4_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM8_IMM8_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLEXVAR_PREF_IMM16_IMM16_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_GETMODULENAMESPACE_PREF_ID32:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STMODULEVAR_PREF_ID32:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDOBJBYNAME_PREF_ID32_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDSUPERBYNAME_PREF_ID32_V8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDMODULEVAR_PREF_ID32_IMM8:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STCONSTTOGLOBALRECORD_PREF_ID32:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STLETTOGLOBALRECORD_PREF_ID32:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_STCLASSTOGLOBALRECORD_PREF_ID32:
        return 0;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_LDHOMEOBJECT_PREF_NONE:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CREATEOBJECTHAVINGMETHOD_PREF_IMM16:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_DYNAMICIMPORT_PREF_V8:
        return -1;
        break;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_ASYNCGENERATORREJECT_PREF_V8_V8:
        return -1;
        break;
    default:
        return -1;
        break;
    }
}

template<const BytecodeInstMode Mode>
inline bool BytecodeInst<Mode>::IsJumpInstruction() const {
    switch(GetOpcode()) {
    case BytecodeInst<Mode>::Opcode::JMP_IMM8:
        return true;
    case BytecodeInst<Mode>::Opcode::JMP_IMM16:
        return true;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM8:
        return true;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM16:
        return true;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM8:
        return true;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM8:
        return true;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM8:
        return true;
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM8:
        return true;
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM8:
        return true;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM8:
        return true;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM8:
        return true;
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM8:
        return true;
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM8:
        return true;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM8:
        return true;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM8:
        return true;
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM8:
        return true;
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM8:
        return true;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM8:
        return true;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM8:
        return true;
    case BytecodeInst<Mode>::Opcode::JMP_IMM32:
        return true;
    case BytecodeInst<Mode>::Opcode::JEQZ_IMM32:
        return true;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM16:
        return true;
    case BytecodeInst<Mode>::Opcode::JNEZ_IMM32:
        return true;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQZ_IMM16:
        return true;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQZ_IMM16:
        return true;
    case BytecodeInst<Mode>::Opcode::JEQNULL_IMM16:
        return true;
    case BytecodeInst<Mode>::Opcode::JNENULL_IMM16:
        return true;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQNULL_IMM16:
        return true;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQNULL_IMM16:
        return true;
    case BytecodeInst<Mode>::Opcode::JEQUNDEFINED_IMM16:
        return true;
    case BytecodeInst<Mode>::Opcode::JNEUNDEFINED_IMM16:
        return true;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQUNDEFINED_IMM16:
        return true;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQUNDEFINED_IMM16:
        return true;
    case BytecodeInst<Mode>::Opcode::JEQ_V8_IMM16:
        return true;
    case BytecodeInst<Mode>::Opcode::JNE_V8_IMM16:
        return true;
    case BytecodeInst<Mode>::Opcode::JSTRICTEQ_V8_IMM16:
        return true;
    case BytecodeInst<Mode>::Opcode::JNSTRICTEQ_V8_IMM16:
        return true;
    default:
        return false;
    }

    UNREACHABLE();
}

template<const BytecodeInstMode Mode>
inline bool BytecodeInst<Mode>::IsRangeInstruction() const {
    switch (GetOpcode()) {
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM8_IMM8_V8:
        return true;
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGE_IMM8_IMM8_V8:
        return true;
    case BytecodeInst<Mode>::Opcode::SUPERCALLTHISRANGE_IMM8_IMM8_V8:
        return true;
    case BytecodeInst<Mode>::Opcode::CALLRANGE_IMM8_IMM8_V8:
        return true;
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM16_IMM8_V8:
        return true;
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHEXCLUDEDKEYS_IMM8_V8_V8:
        return true;
    case BytecodeInst<Mode>::Opcode::SUPERCALLARROWRANGE_IMM8_IMM8_V8:
        return true;
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGEWITHNAME_IMM8_IMM8_ID16_V8:
        return true;
    case BytecodeInst<Mode>::Opcode::WIDE_CREATEOBJECTWITHEXCLUDEDKEYS_PREF_IMM16_V8_V8:
        return true;
    case BytecodeInst<Mode>::Opcode::WIDE_NEWOBJRANGE_PREF_IMM16_V8:
        return true;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLRANGE_PREF_IMM16_V8:
        return true;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGE_PREF_IMM16_V8:
        return true;
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLTHISRANGE_PREF_IMM16_V8:
        return true;
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLARROWRANGE_PREF_IMM16_V8:
        return true;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLRANGE_PREF_IMM16_V8:
        return true;
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLTHISRANGE_PREF_IMM16_V8:
        return true;
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGEWITHNAME_PREF_IMM16_ID16_V8:
        return true;
    default:
        return false;
    }
    UNREACHABLE();
}

template <const BytecodeInstMode Mode>
inline std::optional<uint64_t> BytecodeInst<Mode>::GetLastVReg() const {
    Format format = GetFormat();
    ASSERT_PRINT(HasVReg(format, 0), "Instruction doesn't have VReg operand with such index");

    if (!HasVReg(format, 0)) {
        return std::nullopt;
    }

    switch (format) {
    case Format::IMM16_ID16_ID16_IMM16_V8: {
        return GetVReg<BytecodeInstruction::Format::IMM16_ID16_ID16_IMM16_V8, 0>();
    }
    case Format::IMM16_ID16_V8: {
        return GetVReg<BytecodeInstruction::Format::IMM16_ID16_V8, 0>();
    }
    case Format::IMM16_IMM8_V8: {
        return GetVReg<BytecodeInstruction::Format::IMM16_IMM8_V8, 0>();
    }
    case Format::IMM16_V8: {
        return GetVReg<BytecodeInstruction::Format::IMM16_V8, 0>();
    }
    case Format::IMM16_V8_IMM16: {
        return GetVReg<BytecodeInstruction::Format::IMM16_V8_IMM16, 0>();
    }
    case Format::IMM16_V8_V8: {
        return GetVReg<BytecodeInstruction::Format::IMM16_V8_V8, 1>();
    }
    case Format::IMM8_ID16_ID16_IMM16_V8: {
        return GetVReg<BytecodeInstruction::Format::IMM8_ID16_ID16_IMM16_V8, 0>();
    }
    case Format::IMM8_ID16_V8: {
        return GetVReg<BytecodeInstruction::Format::IMM8_ID16_V8, 0>();
    }
    case Format::IMM8_ID16_V8_V8: {
        return GetVReg<BytecodeInstruction::Format::IMM8_ID16_V8_V8, 1>();
    }
    case Format::IMM8_ID16_V8_V8_V8: {
        return GetVReg<BytecodeInstruction::Format::IMM8_ID16_V8_V8_V8, 2>();
    }
    case Format::IMM8_ID16_V8_V8_V8_V8: {
        return GetVReg<BytecodeInstruction::Format::IMM8_ID16_V8_V8_V8_V8, 3>();
    }
    case Format::IMM8_IMM16_IMM16_V8: {
        return GetVReg<BytecodeInstruction::Format::IMM8_IMM16_IMM16_V8, 0>();
    }
    case Format::IMM8_IMM8_ID16_V8: {
        return GetVReg<BytecodeInstruction::Format::IMM8_IMM8_ID16_V8, 0>();
    }
    case Format::IMM8_IMM8_V8: {
        return GetVReg<BytecodeInstruction::Format::IMM8_IMM8_V8, 0>();
    }
    case Format::IMM8_V8: {
        return GetVReg<BytecodeInstruction::Format::IMM8_V8, 0>();
    }
    case Format::IMM8_V8_IMM16: {
        return GetVReg<BytecodeInstruction::Format::IMM8_V8_IMM16, 0>();
    }
    case Format::IMM8_V8_V8: {
        return GetVReg<BytecodeInstruction::Format::IMM8_V8_V8, 1>();
    }
    case Format::IMM8_V8_V8_V8: {
        return GetVReg<BytecodeInstruction::Format::IMM8_V8_V8_V8, 2>();
    }
    case Format::IMM8_V8_V8_V8_V8: {
        return GetVReg<BytecodeInstruction::Format::IMM8_V8_V8_V8_V8, 3>();
    }
    case Format::PREF_ID16_IMM16_IMM16_V8_V8: {
        return GetVReg<BytecodeInstruction::Format::PREF_ID16_IMM16_IMM16_V8_V8, 1>();
    }
    case Format::PREF_ID32_V8: {
        return GetVReg<BytecodeInstruction::Format::PREF_ID32_V8, 0>();
    }
    case Format::PREF_IMM16_ID16_ID16_IMM16_V8: {
        return GetVReg<BytecodeInstruction::Format::PREF_IMM16_ID16_ID16_IMM16_V8, 0>();
    }
    case Format::PREF_IMM16_ID16_V8: {
        return GetVReg<BytecodeInstruction::Format::PREF_IMM16_ID16_V8, 0>();
    }
    case Format::PREF_IMM16_IMM16_V8: {
        return GetVReg<BytecodeInstruction::Format::PREF_IMM16_IMM16_V8, 0>();
    }
    case Format::PREF_IMM16_V8: {
        return GetVReg<BytecodeInstruction::Format::PREF_IMM16_V8, 0>();
    }
    case Format::PREF_IMM16_V8_V8: {
        return GetVReg<BytecodeInstruction::Format::PREF_IMM16_V8_V8, 1>();
    }
    case Format::PREF_IMM4_IMM4_V8: {
        return GetVReg<BytecodeInstruction::Format::PREF_IMM4_IMM4_V8, 0>();
    }
    case Format::PREF_IMM8_IMM16_IMM16_V8: {
        return GetVReg<BytecodeInstruction::Format::PREF_IMM8_IMM16_IMM16_V8, 0>();
    }
    case Format::PREF_IMM8_IMM32_V8: {
        return GetVReg<BytecodeInstruction::Format::PREF_IMM8_IMM32_V8, 0>();
    }
    case Format::PREF_IMM8_IMM8_V8: {
        return GetVReg<BytecodeInstruction::Format::PREF_IMM8_IMM8_V8, 0>();
    }
    case Format::PREF_IMM8_V8: {
        return GetVReg<BytecodeInstruction::Format::PREF_IMM8_V8, 0>();
    }
    case Format::PREF_IMM8_V8_V8: {
        return GetVReg<BytecodeInstruction::Format::PREF_IMM8_V8_V8, 1>();
    }
    case Format::PREF_V8: {
        return GetVReg<BytecodeInstruction::Format::PREF_V8, 0>();
    }
    case Format::PREF_V8_IMM32: {
        return GetVReg<BytecodeInstruction::Format::PREF_V8_IMM32, 0>();
    }
    case Format::PREF_V8_V8: {
        return GetVReg<BytecodeInstruction::Format::PREF_V8_V8, 1>();
    }
    case Format::PREF_V8_V8_V8: {
        return GetVReg<BytecodeInstruction::Format::PREF_V8_V8_V8, 2>();
    }
    case Format::PREF_V8_V8_V8_V8: {
        return GetVReg<BytecodeInstruction::Format::PREF_V8_V8_V8_V8, 3>();
    }
    case Format::V16_V16: {
        return GetVReg<BytecodeInstruction::Format::V16_V16, 1>();
    }
    case Format::V4_V4: {
        return GetVReg<BytecodeInstruction::Format::V4_V4, 1>();
    }
    case Format::V8: {
        return GetVReg<BytecodeInstruction::Format::V8, 0>();
    }
    case Format::V8_IMM16: {
        return GetVReg<BytecodeInstruction::Format::V8_IMM16, 0>();
    }
    case Format::V8_IMM8: {
        return GetVReg<BytecodeInstruction::Format::V8_IMM8, 0>();
    }
    case Format::V8_V8: {
        return GetVReg<BytecodeInstruction::Format::V8_V8, 1>();
    }
    case Format::V8_V8_V8: {
        return GetVReg<BytecodeInstruction::Format::V8_V8_V8, 2>();
    }
    case Format::V8_V8_V8_V8: {
        return GetVReg<BytecodeInstruction::Format::V8_V8_V8_V8, 3>();
    }
    default: {
        break;
    }
    }

    UNREACHABLE();
}

template <const BytecodeInstMode Mode>
inline std::optional<uint64_t> BytecodeInst<Mode>::GetRangeInsLastRegIdx() const {
    // For the range instruction, where A stores the number of registers
    // The actual register index needs to handle 2 cases: B~B+A-1 / B~B+A
    // range_0 is B~B+A-1
    // range_1 is B~B+A
    size_t count = GetImmCount();
    if (count == 0) {
        return std::nullopt;
    }
    int64_t range_reg_num = GetImmData(count - 1);
    switch (GetOpcode()) {
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM8_IMM8_V8:
        if (range_reg_num > 0) {
            return SafeAdd(GetLastVReg().value(), range_reg_num - 1);
        }
        return GetLastVReg();
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGE_IMM8_IMM8_V8:
        if (range_reg_num > 0) {
            return SafeAdd(GetLastVReg().value(), range_reg_num - 1);
        }
        return GetLastVReg();
    case BytecodeInst<Mode>::Opcode::SUPERCALLTHISRANGE_IMM8_IMM8_V8:
        if (range_reg_num > 0) {
            return SafeAdd(GetLastVReg().value(), range_reg_num - 1);
        }
        return GetLastVReg();
    case BytecodeInst<Mode>::Opcode::CALLRANGE_IMM8_IMM8_V8:
        if (range_reg_num > 0) {
            return SafeAdd(GetLastVReg().value(), range_reg_num - 1);
        }
        return GetLastVReg();
    case BytecodeInst<Mode>::Opcode::NEWOBJRANGE_IMM16_IMM8_V8:
        if (range_reg_num > 0) {
            return SafeAdd(GetLastVReg().value(), range_reg_num - 1);
        }
        return GetLastVReg();
    case BytecodeInst<Mode>::Opcode::CREATEOBJECTWITHEXCLUDEDKEYS_IMM8_V8_V8:
        return SafeAdd(GetLastVReg().value(), range_reg_num);
    case BytecodeInst<Mode>::Opcode::SUPERCALLARROWRANGE_IMM8_IMM8_V8:
        if (range_reg_num > 0) {
            return SafeAdd(GetLastVReg().value(), range_reg_num - 1);
        }
        return GetLastVReg();
    case BytecodeInst<Mode>::Opcode::CALLTHISRANGEWITHNAME_IMM8_IMM8_ID16_V8:
        if (range_reg_num > 0) {
            return SafeAdd(GetLastVReg().value(), range_reg_num - 1);
        }
        return GetLastVReg();
    case BytecodeInst<Mode>::Opcode::WIDE_CREATEOBJECTWITHEXCLUDEDKEYS_PREF_IMM16_V8_V8:
        return SafeAdd(GetLastVReg().value(), range_reg_num);
    case BytecodeInst<Mode>::Opcode::WIDE_NEWOBJRANGE_PREF_IMM16_V8:
        if (range_reg_num > 0) {
            return SafeAdd(GetLastVReg().value(), range_reg_num - 1);
        }
        return GetLastVReg();
    case BytecodeInst<Mode>::Opcode::WIDE_CALLRANGE_PREF_IMM16_V8:
        if (range_reg_num > 0) {
            return SafeAdd(GetLastVReg().value(), range_reg_num - 1);
        }
        return GetLastVReg();
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGE_PREF_IMM16_V8:
        return SafeAdd(GetLastVReg().value(), range_reg_num);
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLTHISRANGE_PREF_IMM16_V8:
        if (range_reg_num > 0) {
            return SafeAdd(GetLastVReg().value(), range_reg_num - 1);
        }
        return GetLastVReg();
    case BytecodeInst<Mode>::Opcode::WIDE_SUPERCALLARROWRANGE_PREF_IMM16_V8:
        if (range_reg_num > 0) {
            return SafeAdd(GetLastVReg().value(), range_reg_num - 1);
        }
        return GetLastVReg();
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLRANGE_PREF_IMM16_V8:
        if (range_reg_num > 0) {
            return SafeAdd(GetLastVReg().value(), range_reg_num - 1);
        }
        return GetLastVReg();
    case BytecodeInst<Mode>::Opcode::DEPRECATED_CALLTHISRANGE_PREF_IMM16_V8:
        return SafeAdd(GetLastVReg().value(), range_reg_num);
    case BytecodeInst<Mode>::Opcode::WIDE_CALLTHISRANGEWITHNAME_PREF_IMM16_ID16_V8:
        return SafeAdd(GetLastVReg().value(), range_reg_num);
    default:
        return std::nullopt;
    }
    UNREACHABLE();
}

template<const BytecodeInstMode Mode>
inline bool BytecodeInst<Mode>::IsReturnOrThrowInstruction() const {
    switch (GetOpcode()) {
    case BytecodeInst<Mode>::Opcode::RETURN:
        return true;
    case BytecodeInst<Mode>::Opcode::RETURNUNDEFINED:
        return true;
    case BytecodeInst<Mode>::Opcode::THROW_PREF_NONE:
        return true;
    case BytecodeInst<Mode>::Opcode::THROW_NOTEXISTS_PREF_NONE:
        return true;
    case BytecodeInst<Mode>::Opcode::THROW_PATTERNNONCOERCIBLE_PREF_NONE:
        return true;
    case BytecodeInst<Mode>::Opcode::THROW_DELETESUPERPROPERTY_PREF_NONE:
        return true;
    case BytecodeInst<Mode>::Opcode::THROW_CONSTASSIGNMENT_PREF_V8:
        return true;
    default:
        return false;
    }
    UNREACHABLE();
}