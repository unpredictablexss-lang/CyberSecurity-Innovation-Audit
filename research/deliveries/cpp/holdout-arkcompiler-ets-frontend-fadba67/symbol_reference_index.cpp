/**
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lsp/include/symbol_reference_index.h"
#include "checker/ETSchecker.h"
#include "compiler/lowering/util.h"
#include "ir/astNode.h"
#include "ir/ets/etsImportDeclaration.h"
#include "ir/ets/etsReExportDeclaration.h"
#include "ir/module/exportSpecifier.h"
#include "ir/module/importDefaultSpecifier.h"
#include "ir/module/importNamespaceSpecifier.h"
#include "ir/module/importSpecifier.h"
#include "lsp/include/internal_api.h"
#include "parser/program/program.h"
#include "public/public.h"
#include "checker/types/ets/etsObjectType.h"
#include "varbinder/ETSBinder.h"
#include "varbinder/variable.h"

#include <algorithm>
#include <cmath>
#include <cctype>
#include <functional>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace ark::es2panda::lsp {
namespace {

enum ExportFlag : uint8_t {
    EXPORT_NONE = 0U,
    EXPORT_NAMED = 1U << 0U,
    EXPORT_DEFAULT = 1U << 1U,
};

struct SymbolOccurrence {
    size_t start = 0;
    size_t end = 0;
    SymbolId symbolId = 0;
};

struct FileIndexData {
    std::string source;
    std::vector<SymbolOccurrence> symbolOccurrences;
    std::vector<std::pair<SymbolId, ReferenceInfo>> references;
};

struct ExportSymbolInfo {
    uint8_t flags = EXPORT_NONE;
    std::string symbolName;
    std::string fileName;
    ir::AstNodeType declType = static_cast<ir::AstNodeType>(0);
    std::string returnType;
};

std::unordered_map<std::string, FileIndexData> g_fileIndices {};
std::unordered_map<SymbolId, std::vector<ReferenceInfo>> g_symbolReferences {};
std::unordered_map<SymbolId, ReferenceInfo> g_symbolDefinitions {};
std::unordered_map<SymbolId, ExportSymbolInfo> g_symbolExportInfos {};

bool HasExportFlag(SymbolId symbolId, ExportFlag flag)
{
    auto it = g_symbolExportInfos.find(symbolId);
    return it != g_symbolExportInfos.end() && (it->second.flags & static_cast<uint8_t>(flag)) != 0U;
}

std::string NormalizePathForExportFilter(std::string fileName)
{
    std::replace(fileName.begin(), fileName.end(), '\\', '/');
    std::transform(fileName.begin(), fileName.end(), fileName.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return fileName;
}

bool ShouldCollectExportInfo(const std::string &fileName)
{
    static constexpr std::string_view OH_SDK_ETS_DIR = "/sdk/default/openharmony/ets/";
    return NormalizePathForExportFilter(fileName).find(OH_SDK_ETS_DIR) == std::string::npos;
}

ir::AstNodeType GetDeclTypeForCompletion(const ir::AstNode *owner)
{
    if (owner == nullptr) {
        return static_cast<ir::AstNodeType>(0);
    }

    const ir::AstNode *node = owner;
    while (node != nullptr) {
        auto type = node->Type();
        switch (type) {
            case ir::AstNodeType::SCRIPT_FUNCTION:
            case ir::AstNodeType::METHOD_DEFINITION:
                return ir::AstNodeType::FUNCTION_DECLARATION;
            default:
                break;
        }
        switch (type) {
            case ir::AstNodeType::FUNCTION_DECLARATION:
            case ir::AstNodeType::CLASS_DECLARATION:
            case ir::AstNodeType::TS_INTERFACE_DECLARATION:
            case ir::AstNodeType::TS_ENUM_DECLARATION:
            case ir::AstNodeType::TS_TYPE_ALIAS_DECLARATION:
            case ir::AstNodeType::TS_MODULE_DECLARATION:
            case ir::AstNodeType::VARIABLE_DECLARATION:
                return type;
            default:
                break;
        }
        node = node->Parent();
    }
    return owner->Type();
}

ir::AstNodeType ResolveDeclTypeForCompletion(const ir::Identifier *identifier, const ir::AstNode *owner)
{
    if (identifier != nullptr) {
        auto *decl = compiler::DeclarationFromIdentifier(identifier);
        if (decl != nullptr) {
            return GetDeclTypeForCompletion(decl);
        }
    }
    return GetDeclTypeForCompletion(owner);
}

std::string NormalizeTypeText(std::string typeText)
{
    std::string normalized;
    normalized.reserve(typeText.size());
    bool pendingSpace = false;
    for (unsigned char c : typeText) {
        if (std::isspace(c) != 0) {
            pendingSpace = !normalized.empty();
            continue;
        }
        if (pendingSpace) {
            normalized.push_back(' ');
            pendingSpace = false;
        }
        normalized.push_back(static_cast<char>(c));
    }
    return normalized;
}

std::string GetFunctionReturnTypeForIndex(const ir::ScriptFunction *func)
{
    if (func == nullptr) {
        return "void";
    }
    auto *retAnno = func->ReturnTypeAnnotation();
    if (retAnno != nullptr) {
        auto ret = NormalizeTypeText(retAnno->DumpEtsSrc());
        if (!ret.empty()) {
            return ret;
        }
    }
    if (retAnno != nullptr && retAnno->TsType() != nullptr) {
        auto ret = NormalizeTypeText(retAnno->TsType()->ToString());
        if (!ret.empty()) {
            return ret;
        }
    }
    auto *signature = func->Signature();
    if (signature != nullptr && signature->ReturnType() != nullptr) {
        auto ret = NormalizeTypeText(signature->ReturnType()->ToString());
        if (!ret.empty()) {
            return retAnno == nullptr && ret == "undefined" ? "void" : ret;
        }
    }
    return "void";
}

const ir::ScriptFunction *FindScriptFunctionOwner(const ir::AstNode *owner)
{
    for (auto *node = owner; node != nullptr; node = node->Parent()) {
        if (node->IsScriptFunction()) {
            return node->AsScriptFunction();
        }
        if (node->IsFunctionDeclaration()) {
            return node->AsFunctionDeclaration()->Function();
        }
        if (node->IsMethodDefinition()) {
            return node->AsMethodDefinition()->Function();
        }
    }
    return nullptr;
}

std::string BuildDisplayNameForExport(ir::AstNodeType declType, const ir::AstNode *owner)
{
    if (declType != ir::AstNodeType::FUNCTION_DECLARATION) {
        return "";
    }
    auto *func = FindScriptFunctionOwner(owner);
    if (func == nullptr) {
        return "";
    }
    return GetFunctionReturnTypeForIndex(func);
}

std::string GetNodeFileName(const ir::AstNode *node, const public_lib::Context *ctx)
{
    if (node == nullptr) {
        return ctx != nullptr ? ctx->sourceFileName : "";
    }
    if (node->Range().start.Program() != nullptr) {
        return std::string(node->Range().start.Program()->SourceFilePath());
    }
    if (ctx != nullptr) {
        return ctx->sourceFileName;
    }
    return "";
}

bool IsImportOwnerIdentifier(const ir::Identifier *declIdentifier)
{
    if (declIdentifier == nullptr) {
        return false;
    }

    auto *parent = declIdentifier->Parent();
    if (parent == nullptr || parent->Parent() == nullptr) {
        return false;
    }
    if (!parent->Parent()->IsETSImportDeclaration()) {
        return false;
    }

    return parent->IsImportSpecifier() || parent->IsImportDefaultSpecifier() || parent->IsImportNamespaceSpecifier();
}

std::string GetImportSourcePath(const ir::Identifier *declIdentifier)
{
    if (!IsImportOwnerIdentifier(declIdentifier)) {
        return "";
    }

    auto *importDecl = declIdentifier->Parent()->Parent()->AsETSImportDeclaration();
    std::string sourcePath = std::string(importDecl->ResolvedSource());
    if (sourcePath.empty() && importDecl->ImportInfo().HasSpecifiedDeclPath()) {
        sourcePath = std::string(importDecl->DeclPath());
    }
    if (sourcePath.empty() && importDecl->Source() != nullptr) {
        sourcePath = std::string(importDecl->Source()->Str());
    }
    return sourcePath;
}

std::string BuildModuleSymbolKey(const ir::Identifier *declIdentifier, const public_lib::Context *ctx)
{
    if (declIdentifier == nullptr || declIdentifier->Parent() == nullptr) {
        return "";
    }

    auto *parent = declIdentifier->Parent();
    if (IsImportOwnerIdentifier(declIdentifier)) {
        const auto sourcePath = GetImportSourcePath(declIdentifier);
        if (sourcePath.empty()) {
            return "";
        }

        std::string exportedName;
        if (parent->IsImportSpecifier()) {
            auto *specifier = parent->AsImportSpecifier();
            if (specifier->Imported() != nullptr) {
                exportedName = std::string(specifier->Imported()->Name());
            }
        } else if (parent->IsImportDefaultSpecifier()) {
            exportedName = "default";
        } else if (parent->IsImportNamespaceSpecifier()) {
            exportedName = "*";
        }

        if (exportedName.empty()) {
            return "";
        }
        return "module:" + sourcePath + ":" + exportedName;
    }

    if (!declIdentifier->IsExported() && !declIdentifier->IsDefaultExported() && !declIdentifier->HasExportAlias()) {
        return "";
    }

    const auto moduleFileName = GetNodeFileName(declIdentifier, ctx);
    if (moduleFileName.empty()) {
        return "";
    }

    std::string exportedName;
    if (declIdentifier->IsDefaultExported()) {
        exportedName = "default";
    } else if (parent->IsExportSpecifier() && parent->AsExportSpecifier()->Exported() != nullptr) {
        exportedName = std::string(parent->AsExportSpecifier()->Exported()->Name());
    } else {
        exportedName = std::string(declIdentifier->Name());
    }

    if (exportedName.empty()) {
        return "";
    }
    return "module:" + moduleFileName + ":" + exportedName;
}

SymbolId BuildSymbolId(const ir::AstNode *declNode, const ir::Identifier *identifier, const public_lib::Context *ctx)
{
    if (declNode == nullptr || identifier == nullptr) {
        return 0;
    }

    std::string key;
    if (declNode->IsIdentifier()) {
        key = BuildModuleSymbolKey(declNode->AsIdentifier(), ctx);
    }
    if (key.empty()) {
        const auto declFileName = GetNodeFileName(declNode, ctx);
        auto start = declNode->Start().index;
        auto end = declNode->End().index;
        // For "ETSGLOBAL" and the "main" function within it, there is no need to add them to the symbol table.
        if (start == 0 && end == 0 && !declFileName.empty()) {
            return 0;
        }
        key = declFileName + ":" + std::to_string(start) + ":" + std::to_string(end) + ":" +
              std::string(identifier->Name()) + ":" + std::to_string(static_cast<int>(declNode->Type()));
    }

    return static_cast<SymbolId>(std::hash<std::string> {}(key));
}

SymbolId BuildFileReferenceSymbolId(const std::string &targetPath)
{
    return static_cast<SymbolId>(std::hash<std::string> {}("file_ref:" + targetPath));
}

const checker::Type *GetTypeReferenceType(const ir::AstNode *targetNode)
{
    return targetNode != nullptr && targetNode->IsTyped() ? targetNode->AsTyped()->TsType() : nullptr;
}

bool HasBuiltinTypeVariable(const checker::Type *type)
{
    auto *const variable = type != nullptr ? type->Variable() : nullptr;
    return variable != nullptr && variable->HasFlag(varbinder::VariableFlags::BUILTIN_TYPE);
}

bool IsIntrinsicTypeReference(const public_lib::Context *ctx, const ir::AstNode *targetNode)
{
    auto *const type = GetTypeReferenceType(targetNode);
    if (type == nullptr) {
        return false;
    }
    if (type->IsETSAnyType() || HasBuiltinTypeVariable(type)) {
        return true;
    }
    if (ctx != nullptr && ctx->GetChecker() != nullptr &&
        type == ctx->GetChecker()->AsETSChecker()->GlobalETSObjectType()) {
        return true;
    }
    return type->IsETSObjectType() && type->AsETSObjectType()->BuiltInKind() != checker::ETSObjectFlags::NO_OPTS;
}

SymbolId BuildIntrinsicTypeReferenceSymbolId(util::StringView name)
{
    constexpr SymbolId INTRINSIC_TYPE_REFERENCE_SYMBOL_SALT = 0x9E3779B97F4A7C15ULL;
    return static_cast<SymbolId>(std::hash<std::string_view> {}(name.Utf8())) ^ INTRINSIC_TYPE_REFERENCE_SYMBOL_SALT;
}

bool IsDefinitionNode(const ir::AstNode *node, const ir::AstNode *owner)
{
    if (node == nullptr || owner == nullptr) {
        return false;
    }
    return node->Start().index == owner->Start().index && node->End().index == owner->End().index;
}

void RemoveFileContributions(const std::string &fileName)
{
    auto it = g_fileIndices.find(fileName);
    if (it == g_fileIndices.end()) {
        return;
    }

    std::unordered_set<SymbolId> visitedSymbols;
    for (const auto &entry : it->second.references) {
        const auto symbolId = entry.first;
        if (!visitedSymbols.insert(symbolId).second) {
            continue;
        }

        auto defIt = g_symbolDefinitions.find(symbolId);
        if (defIt != g_symbolDefinitions.end() && defIt->second.fileName == fileName) {
            g_symbolDefinitions.erase(defIt);
            g_symbolExportInfos.erase(symbolId);
        }
    }

    for (const auto &entry : it->second.references) {
        const auto symbolId = entry.first;
        const auto refInfo = entry.second;
        auto refsIt = g_symbolReferences.find(symbolId);
        if (refsIt == g_symbolReferences.end()) {
            continue;
        }
        auto &refs = refsIt->second;
        refs.erase(std::remove_if(refs.begin(), refs.end(),
                                  // CC-OFFNXT(G.FMT.06-CPP) project code style
                                  [refInfo](const ReferenceInfo &current) {
                                      return current.fileName == refInfo.fileName && current.start == refInfo.start &&
                                             current.length == refInfo.length;
                                  }),  // CC-OFF(G.FMT.02-CPP) project code style
                   refs.end());
        if (refs.empty()) {
            g_symbolReferences.erase(refsIt);
        }
    }

    g_fileIndices.erase(it);
}

void DeduplicateAndSortReferences(std::vector<ReferenceInfo> &refs)
{
    std::sort(refs.begin(), refs.end(), [](const ReferenceInfo &lhs, const ReferenceInfo &rhs) {
        if (lhs.fileName != rhs.fileName) {
            return lhs.fileName < rhs.fileName;
        }
        if (lhs.start != rhs.start) {
            return lhs.start < rhs.start;
        }
        return lhs.length < rhs.length;
    });
    refs.erase(std::unique(refs.begin(), refs.end(),
                           // CC-OFFNXT(G.FMT.06-CPP) project code style
                           [](const ReferenceInfo &lhs, const ReferenceInfo &rhs) {
                               return lhs.fileName == rhs.fileName && lhs.start == rhs.start &&
                                      lhs.length == rhs.length;
                           }),  // CC-OFF(G.FMT.02-CPP) project code style
               refs.end());
}

bool IsExportedDefinition(const ir::Identifier *identifier, const ir::AstNode *owner)
{
    if (identifier == nullptr || owner == nullptr) {
        return false;
    }
    if (identifier->IsExported() || identifier->IsDefaultExported() || identifier->HasExportAlias() ||
        owner->IsExported() || owner->IsDefaultExported()) {
        return true;
    }
    auto *parent = owner->Parent();
    return parent != nullptr &&
           (parent->IsExported() || parent->IsExportNamedDeclaration() || parent->IsExportDefaultDeclaration());
}

bool IsDefaultExportDefinition(const ir::Identifier *identifier, const ir::AstNode *owner)
{
    if (identifier == nullptr || owner == nullptr) {
        return false;
    }
    if (identifier->IsDefaultExported() || owner->IsDefaultExported()) {
        return true;
    }
    for (auto *parent = owner->Parent(); parent != nullptr; parent = parent->Parent()) {
        if (parent->IsDefaultExported() || parent->IsExportDefaultDeclaration()) {
            return true;
        }
    }
    return false;
}

SymbolId ResolveSymbolId(const public_lib::Context *ctx, const ir::AstNode *targetNode,
                         const ir::Identifier *identifier, ir::AstNode *owner)
{
    if (identifier == nullptr) {
        return 0;
    }
    if (targetNode != nullptr && targetNode->IsETSTypeReference() && IsIntrinsicTypeReference(ctx, targetNode)) {
        return BuildIntrinsicTypeReferenceSymbolId(identifier->Name());
    }
    if (owner == nullptr) {
        return 0;
    }
    return BuildSymbolId(owner, identifier, ctx);
}

std::optional<std::pair<ReferenceInfo, size_t>> BuildReferenceInfo(const public_lib::Context *ctx,
                                                                   const ir::AstNode *targetNode,
                                                                   const ir::Identifier *identifier)
{
    if (targetNode == nullptr || identifier == nullptr) {
        return std::nullopt;
    }

    const size_t start = targetNode->IsETSTypeReference() ? identifier->Start().index : targetNode->Start().index;
    const std::string identifierName = std::string(identifier->Name());
    const size_t refLength = identifierName.length();
    if (refLength == 0) {
        return std::nullopt;
    }
    const size_t end = start + refLength;

    std::string sourceStorage {};
    std::string_view source {};
    if (auto *program = targetNode->Range().start.Program(); program != nullptr) {
        sourceStorage = std::string(program->SourceCode());
        source = sourceStorage;
    }
    if (!source.empty() && (end > source.length() || source.substr(start, refLength) != identifierName)) {
        return std::nullopt;
    }

    const std::string refFileName = GetNodeFileName(targetNode, ctx);
    return std::make_pair(ReferenceInfo(refFileName, start, refLength), end);
}

bool RegisterReference(SymbolId symbolId, const ReferenceInfo &ref, size_t end,
                       std::unordered_set<std::string> &localDedup, FileIndexData &fileIndex)
{
    const std::string dedupKey = std::to_string(symbolId) + ":" + ref.fileName + ":" + std::to_string(ref.start) + ":" +
                                 std::to_string(ref.length);
    if (!localDedup.insert(dedupKey).second) {
        return false;
    }

    fileIndex.symbolOccurrences.push_back(SymbolOccurrence {ref.start, end, symbolId});
    fileIndex.references.emplace_back(symbolId, ref);
    g_symbolReferences[symbolId].push_back(ref);
    return true;
}

void GetReferenceIdentifierAndOwner(const ir::AstNode *targetNode, const ir::Identifier **identifier,
                                    ir::AstNode **owner)
{
    if (targetNode->IsETSTypeReference()) {
        auto *typeReference = targetNode->AsETSTypeReference();
        *identifier = typeReference->BaseName();
        if (*identifier != nullptr) {
            *owner = ark::es2panda::lsp::GetOwner(const_cast<ir::Identifier *>(*identifier));
        }
    } else if (targetNode->IsIdentifier()) {
        *identifier = targetNode->AsIdentifier();
        *owner = ark::es2panda::lsp::GetOwner(const_cast<ir::AstNode *>(targetNode));
    }
}

void AddDefinitionAndExportInfo(SymbolId symbolId, const ReferenceInfo &ref, const ir::Identifier *identifier,
                                const ir::AstNode *owner)
{
    g_symbolDefinitions[symbolId] = ReferenceInfo(ref.fileName, ref.start, ref.length);
    g_symbolExportInfos.erase(symbolId);
    if (!ShouldCollectExportInfo(ref.fileName)) {
        return;
    }
    uint8_t exportFlags = EXPORT_NONE;
    const bool isExported = IsExportedDefinition(identifier, owner);
    if (isExported) {
        exportFlags |= static_cast<uint8_t>(EXPORT_NAMED);
    }
    if (identifier->IsDefaultExported() || (owner->Parent() != nullptr && owner->Parent()->IsDefaultExported())) {
        exportFlags |= static_cast<uint8_t>(EXPORT_DEFAULT);
    }
    if (exportFlags == EXPORT_NONE) {
        return;
    }

    auto &exportInfo = g_symbolExportInfos[symbolId];
    exportInfo.flags |= exportFlags;
    exportInfo.symbolName = std::string(identifier->Name());
    exportInfo.fileName = ref.fileName;
    exportInfo.declType = ResolveDeclTypeForCompletion(identifier, owner);
    exportInfo.returnType = BuildDisplayNameForExport(exportInfo.declType, owner);
}

void AddReferenceFromNode(const public_lib::Context *ctx, const ir::AstNode *targetNode,
                          std::unordered_set<std::string> &localDedup, FileIndexData &fileIndex)
{
    if (targetNode == nullptr) {
        return;
    }

    const ir::Identifier *identifier = nullptr;
    ir::AstNode *owner = nullptr;
    GetReferenceIdentifierAndOwner(targetNode, &identifier, &owner);

    const SymbolId symbolId = ResolveSymbolId(ctx, targetNode, identifier, owner);
    if (symbolId == 0) {
        return;
    }
    auto refInfo = BuildReferenceInfo(ctx, targetNode, identifier);
    if (!refInfo.has_value()) {
        return;
    }
    auto &[ref, end] = refInfo.value();
    if (!RegisterReference(symbolId, ref, end, localDedup, fileIndex)) {
        return;
    }
    if (owner == nullptr) {
        return;
    }
    const bool ownerIsImportAlias = owner->IsIdentifier() && IsImportOwnerIdentifier(owner->AsIdentifier());
    if (IsDefinitionNode(targetNode, owner) && !ownerIsImportAlias) {
        AddDefinitionAndExportInfo(symbolId, ref, identifier, owner);
    }
}

void ProcessNodeForSymbolIndex(const public_lib::Context *ctx, ir::AstNode *node,
                               const std::unordered_set<const ir::AstNode *> &handledReExportIdentifiers,
                               std::unordered_set<std::string> &localDedup, FileIndexData &fileIndex)
{
    auto *targetNode = node->OriginalNode() != nullptr ? node->OriginalNode() : node;
    if (handledReExportIdentifiers.find(node) != handledReExportIdentifiers.end() ||
        handledReExportIdentifiers.find(targetNode) != handledReExportIdentifiers.end()) {
        return;
    }
    if (targetNode == nullptr) {
        return;
    }

    if (targetNode->IsETSTypeReference()) {
        AddReferenceFromNode(ctx, targetNode, localDedup, fileIndex);
        return;
    }

    if (!targetNode->IsIdentifier()) {
        return;
    }
    AddReferenceFromNode(ctx, targetNode, localDedup, fileIndex);
}

void AddFileReferenceFromImportDecl(const public_lib::Context *ctx, const ir::ETSImportDeclaration *importDecl,
                                    std::unordered_set<std::string> &localDedup, FileIndexData &fileIndex)
{
    if (importDecl == nullptr || importDecl->Source() == nullptr || !importDecl->Source()->IsStringLiteral()) {
        return;
    }

    std::string sourcePath = std::string(importDecl->ResolvedSource());
    if (sourcePath.empty() && importDecl->ImportInfo().HasSpecifiedDeclPath()) {
        sourcePath = std::string(importDecl->DeclPath());
    }
    if (sourcePath.empty() && importDecl->Source() != nullptr) {
        sourcePath = std::string(importDecl->Source()->Str());
    }
    if (sourcePath.empty()) {
        return;
    }

    const auto *sourceLiteral = importDecl->Source();
    const size_t start = sourceLiteral->Start().index;
    const size_t end = sourceLiteral->End().index;
    if (end <= start) {
        return;
    }

    const std::string refFileName = GetNodeFileName(importDecl, ctx);
    ReferenceInfo refInfo(refFileName, start, end - start);
    const auto symbolId = BuildFileReferenceSymbolId(sourcePath);
    const std::string dedupKey = "file-ref:" + std::to_string(symbolId) + ":" + refFileName + ":" +
                                 std::to_string(refInfo.start) + ":" + std::to_string(refInfo.length);
    if (!localDedup.insert(dedupKey).second) {
        return;
    }

    fileIndex.references.emplace_back(symbolId, refInfo);
    g_symbolReferences[symbolId].push_back(refInfo);
}

void BuildImportFileReferencesForProgram(const public_lib::Context *ctx, parser::Program *program,
                                         std::unordered_set<std::string> &localDedup, FileIndexData &fileIndex)
{
    if (program == nullptr || program->Ast() == nullptr || !program->Ast()->IsETSModule()) {
        return;
    }
    for (auto *statement : program->Ast()->AsETSModule()->Statements()) {
        if (statement == nullptr || !statement->IsETSImportDeclaration()) {
            continue;
        }
        AddFileReferenceFromImportDecl(ctx, statement->AsETSImportDeclaration(), localDedup, fileIndex);
    }
}

parser::Program *FindExternalProgram(parser::Program *program, const std::string &sourcePath)
{
    auto *externalPrograms = program->GetExternalPrograms();
    if (externalPrograms == nullptr) {
        return nullptr;
    }
    parser::Program *result = nullptr;
    auto findMatchingProgram = [&result, &sourcePath](parser::Program *candidate) {
        if (result == nullptr && candidate != nullptr &&
            (candidate->SourceFilePath().Is(sourcePath) || candidate->AbsoluteName().Is(sourcePath))) {
            result = candidate;
        }
    };
    for (const auto &[_, candidate] : externalPrograms->Direct()) {
        findMatchingProgram(candidate);
    }
    externalPrograms->template Visit<false>(
        [&findMatchingProgram](auto *candidate) { findMatchingProgram(candidate); });
    return result;
}

std::unordered_map<std::string, ir::AstNode *> CollectExportedSymbolOwners(parser::Program *program)
{
    std::unordered_map<std::string, ir::AstNode *> result {};
    if (program == nullptr || program->Ast() == nullptr) {
        return result;
    }
    program->Ast()->IterateRecursively([&result](ir::AstNode *node) {
        auto *targetNode = node->OriginalNode() != nullptr ? node->OriginalNode() : node;
        if (targetNode == nullptr || !targetNode->IsIdentifier()) {
            return;
        }
        auto *identifier = targetNode->AsIdentifier();
        auto *owner = ark::es2panda::lsp::GetOwner(targetNode);
        const bool isDefaultExport = IsDefaultExportDefinition(identifier, owner);
        if (!IsDefinitionNode(targetNode, owner) || (!IsExportedDefinition(identifier, owner) && !isDefaultExport)) {
            return;
        }
        const std::string exportedName = isDefaultExport ? "default" : std::string(identifier->Name());
        result.emplace(exportedName, owner);
    });
    return result;
}

struct ReExportIndexState {
    const public_lib::Context *ctx;
    parser::Program *program;
    std::unordered_set<const ir::AstNode *> &handledIdentifiers;
    std::unordered_set<std::string> &localDedup;
    FileIndexData &fileIndex;
};

void AddReExportReference(const ReExportIndexState &state, const ir::Identifier *identifier, SymbolId symbolId)
{
    if (identifier == nullptr || symbolId == 0) {
        return;
    }
    auto refInfo = BuildReferenceInfo(state.ctx, identifier, identifier);
    if (!refInfo.has_value()) {
        return;
    }
    auto &[ref, end] = refInfo.value();
    RegisterReference(symbolId, ref, end, state.localDedup, state.fileIndex);
}

ir::AstNode *ResolveReExportOwnerFromBinding(const public_lib::Context *ctx, const ir::ImportSpecifier *specifier)
{
    if (ctx == nullptr || specifier == nullptr || specifier->Local() == nullptr ||
        specifier->Local()->Variable() == nullptr || ctx->GetChecker() == nullptr) {
        return nullptr;
    }
    auto *resolver = ctx->GetChecker()->AsETSChecker()->GetNavigationExportClosureResolver();
    if (resolver == nullptr) {
        return nullptr;
    }
    auto *variable = resolver->ResolveEffectiveImportVariable(specifier->Local()->Variable(),
                                                              checker::ImportBindingResolveOptions {false, false});
    if (variable == nullptr || variable->Declaration() == nullptr) {
        return nullptr;
    }
    auto *identifier = ark::es2panda::lsp::GetIdentifier(variable->Declaration()->Node());
    return identifier != nullptr && identifier->IsIdentifier() ? identifier : nullptr;
}

ir::AstNode *ResolveReExportOwnerFromSource(parser::Program *program, const ir::ETSImportDeclaration *importDecl,
                                            util::StringView importedName)
{
    std::string sourcePath = std::string(importDecl->ResolvedSource());
    if (sourcePath.empty() && importDecl->ImportInfo().HasSpecifiedDeclPath()) {
        sourcePath = std::string(importDecl->DeclPath());
    }
    const auto exportedSymbols = CollectExportedSymbolOwners(FindExternalProgram(program, sourcePath));
    const auto symbolIt = exportedSymbols.find(std::string(importedName));
    return symbolIt == exportedSymbols.end() ? nullptr : symbolIt->second;
}

void BuildReExportReferenceForSpecifier(const ReExportIndexState &state, const ir::ETSImportDeclaration *importDecl,
                                        ir::AstNode *specifier)
{
    if (specifier == nullptr || !specifier->IsImportSpecifier()) {
        return;
    }
    auto *importSpecifier = specifier->AsImportSpecifier();
    const auto *imported = importSpecifier->Imported();
    if (imported == nullptr) {
        return;
    }
    const auto importedName = varbinder::NormalizeReExportName(imported->Name());
    auto *symbolOwner = ResolveReExportOwnerFromBinding(state.ctx, importSpecifier);
    if (symbolOwner == nullptr) {
        symbolOwner = ResolveReExportOwnerFromSource(state.program, importDecl, importedName);
    }
    if (symbolOwner == nullptr) {
        return;
    }
    const auto *local = importSpecifier->Local();
    const auto symbolId = BuildSymbolId(symbolOwner, local == nullptr ? imported : local, state.ctx);
    state.handledIdentifiers.insert(imported);
    if (local != nullptr) {
        state.handledIdentifiers.insert(local);
    }
    if (imported->Name() == importedName) {
        AddReExportReference(state, imported, symbolId);
    }
    AddReExportReference(state, local, symbolId);
}

void BuildReExportReferencesForProgram(const ReExportIndexState &state)
{
    if (state.program == nullptr || state.program->Ast() == nullptr || !state.program->Ast()->IsETSModule()) {
        return;
    }
    for (auto *statement : state.program->Ast()->AsETSModule()->Statements()) {
        if (statement == nullptr || !statement->IsETSReExportDeclaration()) {
            continue;
        }
        auto *importDecl = statement->AsETSReExportDeclaration()->GetETSImportDeclarations();
        if (importDecl == nullptr) {
            continue;
        }
        for (auto *specifier : importDecl->Specifiers()) {
            BuildReExportReferenceForSpecifier(state, importDecl, specifier);
        }
    }
}

bool BuildSymbolReferenceIndexForProgram(const public_lib::Context *ctx, parser::Program *program)
{
    const std::string fileName = std::string(program->SourceFilePath());
    RemoveFileContributions(fileName);

    FileIndexData fileIndex {};
    fileIndex.source = std::string(program->SourceCode());

    std::unordered_set<std::string> localDedup {};
    std::unordered_set<const ir::AstNode *> handledReExportIdentifiers {};
    BuildImportFileReferencesForProgram(ctx, program, localDedup, fileIndex);
    ReExportIndexState reExportState {ctx, program, handledReExportIdentifiers, localDedup, fileIndex};
    BuildReExportReferencesForProgram(reExportState);
    auto *astRoot = reinterpret_cast<ir::AstNode *>(program->Ast());
    astRoot->IterateRecursively([ctx, &handledReExportIdentifiers, &localDedup, &fileIndex](ir::AstNode *node) {
        ProcessNodeForSymbolIndex(ctx, node, handledReExportIdentifiers, localDedup, fileIndex);
    });

    std::sort(fileIndex.symbolOccurrences.begin(), fileIndex.symbolOccurrences.end(),
              // CC-OFFNXT(G.FMT.06-CPP) project code style
              [](const SymbolOccurrence &lhs, const SymbolOccurrence &rhs) {
                  if (lhs.start != rhs.start) {
                      return lhs.start < rhs.start;
                  }
                  return lhs.end < rhs.end;  // CC-OFF(G.FMT.02-CPP) project code style
              });

    for (auto &[symbolId, refs] : g_symbolReferences) {
        DeduplicateAndSortReferences(refs);
    }

    g_fileIndices[fileName] = std::move(fileIndex);
    return true;
}

}  // namespace

void InitSymbolReferenceIndex()
{
    g_fileIndices.clear();
    g_symbolReferences.clear();
    g_symbolDefinitions.clear();
    g_symbolExportInfos.clear();
}

void ClearSymbolReferenceIndex()
{
    InitSymbolReferenceIndex();
}

bool BuildSymbolReferenceIndexForContext(es2panda_Context *context)
{
    auto *ctx = reinterpret_cast<public_lib::Context *>(context);
    if (ctx->parserProgram == nullptr || ctx->parserProgram->Ast() == nullptr) {
        return false;
    }

    return BuildSymbolReferenceIndexForProgram(ctx, ctx->parserProgram);
}

bool BuildSymbolReferenceIndexForContextWithExternal(es2panda_Context *context)
{
    auto *ctx = reinterpret_cast<public_lib::Context *>(context);
    bool buildSuccess = true;
    std::unordered_set<std::string> indexedFiles {};

    auto buildIfNeeded = [ctx, &buildSuccess, &indexedFiles](parser::Program *program) {
        if (program == nullptr || program->Ast() == nullptr) {
            return;
        }
        std::string fileName = std::string(program->AbsoluteName());
        if (!indexedFiles.emplace(fileName).second) {
            return;
        }
        buildSuccess = BuildSymbolReferenceIndexForProgram(ctx, program) && buildSuccess;
    };

    buildIfNeeded(ctx->parserProgram);

    auto *externalSources = ctx->parserProgram->GetExternalPrograms();
    if (externalSources == nullptr) {
        return buildSuccess;
    }

    for (const auto &[_, program] : externalSources->Direct()) {
        buildIfNeeded(program);
    }

    // Traverse transitive externals across all module kinds:
    // MODULE, SOURCE_DECL, PACKAGE, ETSCACHE_DECL.
    externalSources->template Visit<false>([&buildIfNeeded](auto *program) { buildIfNeeded(program); });
    return buildSuccess;
}

bool RemoveSymbolReferenceIndexForFile(const std::string &fileName)
{
    const auto before = g_fileIndices.size();
    RemoveFileContributions(fileName);
    return g_fileIndices.size() < before;
}

References GetReferencesAtPositionFromIndex(es2panda_Context *context, size_t position)
{
    References result {};
    if (context == nullptr) {
        return result;
    }

    auto *ctx = reinterpret_cast<public_lib::Context *>(context);
    const std::string fileName = ctx->sourceFileName;
    auto fileIt = g_fileIndices.find(fileName);
    if (fileIt == g_fileIndices.end()) {
        return result;
    }

    SymbolId hitSymbol = 0;
    size_t hitLength = static_cast<size_t>(-1);
    for (const auto &occurrence : fileIt->second.symbolOccurrences) {
        if (position < occurrence.start || position >= occurrence.end) {
            continue;
        }
        const size_t currentLength = occurrence.end - occurrence.start;
        if (currentLength <= hitLength) {
            hitLength = currentLength;
            hitSymbol = occurrence.symbolId;
        }
    }

    if (hitSymbol == 0) {
        return result;
    }

    auto refsIt = g_symbolReferences.find(hitSymbol);
    if (refsIt == g_symbolReferences.end()) {
        return result;
    }

    auto refs = refsIt->second;
    auto defIt = g_symbolDefinitions.find(hitSymbol);
    if (defIt != g_symbolDefinitions.end()) {
        const auto &defRef = defIt->second;
        result.definitionInfo = DefinitionInfo(defRef.fileName, defRef.start, defRef.length);
        refs.erase(std::remove_if(refs.begin(), refs.end(),
                                  // CC-OFFNXT(G.FMT.06-CPP) project code style
                                  [defRef](const ReferenceInfo &ref) {
                                      return ref.fileName == defRef.fileName && ref.start == defRef.start &&
                                             ref.length == defRef.length;
                                  }),  // CC-OFF(G.FMT.02-CPP) project code style
                   refs.end());
    }

    DeduplicateAndSortReferences(refs);
    result.referenceInfos = std::move(refs);
    return result;
}

References GetFileReferencesFromIndex(es2panda_Context *context, const std::string &searchFileName,
                                      bool isPackageModule)
{
    References result {};
    if (context == nullptr || searchFileName.empty()) {
        return result;
    }

    std::string searchTarget = searchFileName;
    if (isPackageModule) {
        const auto pos = searchFileName.find_last_of("/\\");
        if (pos == std::string::npos) {
            return result;
        }
        searchTarget = searchFileName.substr(0, pos);
    }

    const auto symbolId = BuildFileReferenceSymbolId(searchTarget);
    auto refsIt = g_symbolReferences.find(symbolId);
    if (refsIt == g_symbolReferences.end()) {
        return result;
    }

    auto refs = refsIt->second;
    DeduplicateAndSortReferences(refs);
    result.referenceInfos = std::move(refs);
    return result;
}

std::string GetIndexedFileSource(const std::string &fileName)
{
    auto it = g_fileIndices.find(fileName);
    if (it == g_fileIndices.end()) {
        return "";
    }
    return it->second.source;
}

double JaccardSimilarity(const std::string &a, const std::string &b)
{
    std::unordered_set<char> setA;
    std::unordered_set<char> setB;

    for (char ch : a) {
        if (isalpha(ch) != 0) {
            setA.insert(tolower(ch));
        }
    }

    for (char ch : b) {
        if (isalpha(ch) != 0) {
            setB.insert(tolower(ch));
        }
    }

    size_t intersectionSize = 0;
    for (char ch : setA) {
        if (setB.find(ch) != setB.end()) {
            intersectionSize++;
        }
    }

    size_t unionSize = setA.size() + setB.size() - intersectionSize;
    if (unionSize == 0) {
        return 0.0;
    }

    return static_cast<double>(intersectionSize) / unionSize;
}

int GetSubstitutionCost(char c1, char c2)
{
    constexpr int SUBSTITUTE_COST = 20;
    constexpr int CASE_COST = 1;

    if (c1 == c2) {
        return 0;
    }
    if (tolower(static_cast<unsigned char>(c1)) == tolower(static_cast<unsigned char>(c2))) {
        return CASE_COST;
    }
    return SUBSTITUTE_COST;
}

int LevenshteinDistance(const std::string &s1, const std::string &s2, int maxDistance)
{
    // Use scaled costs: insert/delete = COST_SCALE, substitute = 2*COST_SCALE, case-only change = 1
    constexpr int COST_SCALE = 10;
    constexpr int INSERT_COST = COST_SCALE;
    constexpr int DELETE_COST = COST_SCALE;

    auto len1 = static_cast<int>(s1.size());
    auto len2 = static_cast<int>(s2.size());

    if (len1 == 0) {
        return len2 <= maxDistance ? len2 * COST_SCALE : -1;
    }
    if (len2 == 0) {
        return len1 <= maxDistance ? len1 * COST_SCALE : -1;
    }

    std::vector<int> prevRow(len2 + 1);
    std::vector<int> currRow(len2 + 1);

    // Initialize first row
    for (int j = 0; j <= len2; j++) {
        prevRow[j] = j * INSERT_COST;
    }

    int maxDistanceScaled = maxDistance * COST_SCALE;

    for (int i = 1; i <= len1; i++) {
        currRow[0] = i * DELETE_COST;
        int rowMin = currRow[0];

        for (int j = 1; j <= len2; j++) {
            int cost = GetSubstitutionCost(s1[i - 1], s2[j - 1]);

            currRow[j] = std::min({prevRow[j] + DELETE_COST, currRow[j - 1] + INSERT_COST, prevRow[j - 1] + cost});
            rowMin = std::min(rowMin, currRow[j]);
        }

        // Early termination: if the minimum value in current row exceeds threshold, give up
        if (rowMin > maxDistanceScaled) {
            return -1;
        }

        std::swap(prevRow, currRow);
    }

    int result = prevRow[len2];
    return result <= maxDistanceScaled ? result : -1;
}

bool IsCaseOnlyDifference(const std::string &a, const std::string &b)
{
    if (a.length() != b.length()) {
        return false;
    }
    for (size_t i = 0; i < a.length(); i++) {
        if (tolower(static_cast<unsigned char>(a[i])) != tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

std::string GetSpellingSuggestion(const std::string &name, const std::vector<std::string> &candidates)
{
    // NOLINTNEXTLINE(readability-magic-numbers)
    constexpr double MAX_LENGTH_DIFF_RATIO = 0.34;
    // NOLINTNEXTLINE(readability-magic-numbers)
    constexpr double BEST_DISTANCE_RATIO = 0.4;
    // NOLINTNEXTLINE(readability-magic-numbers)
    constexpr int COST_SCALE = 10;

    if (candidates.empty()) {
        return "";
    }

    int maximumLengthDifference = std::max(2, static_cast<int>(name.length() * MAX_LENGTH_DIFF_RATIO));
    int bestDistance = static_cast<int>(name.length() * BEST_DISTANCE_RATIO * COST_SCALE) + 1;
    std::string bestCandidate;

    for (const auto &candidate : candidates) {
        if (candidate == name) {
            continue;
        }

        // Skip if length difference is too large
        int lengthDiff = static_cast<int>(candidate.length()) - static_cast<int>(name.length());
        if (lengthDiff < 0) {
            lengthDiff = -lengthDiff;
        }
        if (lengthDiff > maximumLengthDifference) {
            continue;
        }

        // Skip short names (< 3) unless it's a case-only difference
        if (candidate.length() < 3 && name.length() < 3 && !IsCaseOnlyDifference(candidate, name)) {
            continue;
        }

        int distance = LevenshteinDistance(name, candidate, bestDistance / COST_SCALE + 1);
        if (distance >= 0 && distance < bestDistance) {
            bestDistance = distance;
            bestCandidate = candidate;
        }
    }

    return bestCandidate;
}

std::vector<std::string> FindSimilarSymbolNames(const std::string &query, const std::string &fileName)
{
    std::vector<std::string> candidates;

    for (const auto &[symbolId, refInfos] : g_symbolReferences) {
        for (const auto &refInfo : refInfos) {
            if (refInfo.fileName != fileName) {
                continue;
            }
            // Extract symbol name from g_fileIndices source using the reference position
            auto fileIt = g_fileIndices.find(refInfo.fileName);
            if (fileIt == g_fileIndices.end()) {
                continue;
            }
            const auto &source = fileIt->second.source;
            if (refInfo.start >= source.size()) {
                continue;
            }

            // Extract the identifier text from source at reference position
            size_t nameStart = refInfo.start;
            size_t nameEnd = nameStart;
            while (nameEnd < source.size() && (isalnum(source[nameEnd]) != 0 || source[nameEnd] == '_')) {
                nameEnd++;
            }
            std::string symbolName = source.substr(nameStart, nameEnd - nameStart);
            if (symbolName.empty()) {
                continue;
            }

            candidates.push_back(symbolName);
        }
    }

    std::string best = GetSpellingSuggestion(query, candidates);
    std::vector<std::string> result;
    if (!best.empty()) {
        result.push_back(best);
    }
    return result;
}

std::vector<SymbolDefSearchResult> FindSymbolDefinitionsByName(const std::string &name, const std::string &excludeFile)
{
    std::vector<SymbolDefSearchResult> results;
    std::unordered_set<std::string> seen;

    for (const auto &[symbolId, defRef] : g_symbolDefinitions) {
        if (defRef.fileName == excludeFile) {
            continue;
        }

        auto fileIt = g_fileIndices.find(defRef.fileName);
        if (fileIt == g_fileIndices.end()) {
            continue;
        }
        const auto &source = fileIt->second.source;
        if (defRef.start >= source.size()) {
            continue;
        }

        size_t nameStart = defRef.start;
        size_t nameEnd = nameStart;
        while (nameEnd < source.size() && (isalnum(source[nameEnd]) != 0 || source[nameEnd] == '_')) {
            nameEnd++;
        }
        std::string symbolName = source.substr(nameStart, nameEnd - nameStart);
        if (symbolName != name) {
            continue;
        }

        std::string dedupKey = defRef.fileName + ":" + symbolName;
        if (!seen.insert(dedupKey).second) {
            continue;
        }

        bool isDefault = HasExportFlag(symbolId, EXPORT_DEFAULT);

        results.push_back(SymbolDefSearchResult {defRef.fileName, symbolName, isDefault});
    }

    return results;
}

std::vector<SymbolDefSearchResult> FindExportSymbolDefinitionsByPrefix(const std::string &prefix,
                                                                       const std::string &excludeFile)
{
    std::vector<SymbolDefSearchResult> results;
    std::unordered_set<std::string> seen;
    auto lowerPrefix = prefix;
    std::transform(lowerPrefix.begin(), lowerPrefix.end(), lowerPrefix.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    for (const auto &[symbolId, info] : g_symbolExportInfos) {
        if ((info.flags & (EXPORT_NAMED | EXPORT_DEFAULT)) == 0U) {
            continue;
        }
        auto defIt = g_symbolDefinitions.find(symbolId);
        if (defIt == g_symbolDefinitions.end()) {
            continue;
        }
        const auto &defRef = defIt->second;
        if (defRef.fileName == excludeFile) {
            continue;
        }

        std::string symbolName = info.symbolName;
        if (symbolName.empty()) {
            continue;
        }

        auto lowerName = symbolName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (!lowerPrefix.empty() && lowerName.find(lowerPrefix) == std::string::npos) {
            continue;
        }

        const auto dedupKey = defRef.fileName + ":" + symbolName;
        if (!seen.insert(dedupKey).second) {
            continue;
        }

        bool isDefault = HasExportFlag(symbolId, EXPORT_DEFAULT);
        results.push_back(
            SymbolDefSearchResult {defRef.fileName, symbolName, isDefault, info.declType, info.returnType});
    }
    return results;
}

}  // namespace ark::es2panda::lsp
