# Blind applicability holdout: official ETS Frontend

This packet contains pinned source excerpts only. It contains no C-line detector output, developer labels, or product-impact conclusions. Label each sample independently. For each, record whether the exact Ark Runtime TypeSafety model is in scope and choose `candidate`, `partial`, `blocked`, `safe`, or `unknown`; cite evidence lines and a root cause. Use `unknown` when the excerpt and pinned source do not support a decision. Do not infer runtime behavior or product impact from source text.

This is a clustered applicability/false-match frame from one production translation unit, not a semantic recall set; do not derive component-wide precision or recall.

## F001

Symbol: `ark::es2panda::lsp::NormalizePathForExportFilter`. Source-relative lines: 81–87.

```cpp
std::string NormalizePathForExportFilter(std::string fileName)
{
    std::replace(fileName.begin(), fileName.end(), '\\', '/');
    std::transform(fileName.begin(), fileName.end(), fileName.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return fileName;
}
```

## F002

Symbol: `ark::es2panda::lsp::ShouldCollectExportInfo`. Source-relative lines: 89–93.

```cpp
bool ShouldCollectExportInfo(const std::string &fileName)
{
    static constexpr std::string_view OH_SDK_ETS_DIR = "/sdk/default/openharmony/ets/";
    return NormalizePathForExportFilter(fileName).find(OH_SDK_ETS_DIR) == std::string::npos;
}
```

## F003

Symbol: `ark::es2panda::lsp::NormalizeTypeText`. Source-relative lines: 139–156.

```cpp
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
```

## F004

Symbol: `ark::es2panda::lsp::BuildDisplayNameForExport`. Source-relative lines: 202–212.

```cpp
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
```

## F005

Symbol: `ark::es2panda::lsp::IsImportOwnerIdentifier`. Source-relative lines: 228–243.

```cpp
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
```

## F006

Symbol: `ark::es2panda::lsp::BuildSymbolId`. Source-relative lines: 317–340.

```cpp
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
```

## F007

Symbol: `ark::es2panda::lsp::HasBuiltinTypeVariable`. Source-relative lines: 352–356.

```cpp
bool HasBuiltinTypeVariable(const checker::Type *type)
{
    auto *const variable = type != nullptr ? type->Variable() : nullptr;
    return variable != nullptr && variable->HasFlag(varbinder::VariableFlags::BUILTIN_TYPE);
}
```

## F008

Symbol: `ark::es2panda::lsp::IsDefinitionNode`. Source-relative lines: 380–386.

```cpp
bool IsDefinitionNode(const ir::AstNode *node, const ir::AstNode *owner)
{
    if (node == nullptr || owner == nullptr) {
        return false;
    }
    return node->Start().index == owner->Start().index && node->End().index == owner->End().index;
}
```

## F009

Symbol: `ark::es2panda::lsp::DeduplicateAndSortReferences`. Source-relative lines: 432–450.

```cpp
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
```

## F010

Symbol: `ark::es2panda::lsp::ResolveSymbolId`. Source-relative lines: 482–495.

```cpp
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
```

## F011

Symbol: `ark::es2panda::lsp::GetReferenceIdentifierAndOwner`. Source-relative lines: 542–555.

```cpp
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
```

## F012

Symbol: `ark::es2panda::lsp::AddReferenceFromNode`. Source-relative lines: 585–615.

```cpp
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
```

## F013

Symbol: `ark::es2panda::lsp::BuildImportFileReferencesForProgram`. Source-relative lines: 679–691.

```cpp
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
```

## F014

Symbol: `ark::es2panda::lsp::AddReExportReference`. Source-relative lines: 745–756.

```cpp
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
```

## F015

Symbol: `ark::es2panda::lsp::BuildReExportReferenceForSpecifier`. Source-relative lines: 789–818.

```cpp
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
```

## F016

Symbol: `ark::es2panda::lsp::BuildSymbolReferenceIndexForProgram`. Source-relative lines: 839–872.

```cpp
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
```

## F017

Symbol: `ark::es2panda::lsp::BuildSymbolReferenceIndexForContext`. Source-relative lines: 889–897.

```cpp
bool BuildSymbolReferenceIndexForContext(es2panda_Context *context)
{
    auto *ctx = reinterpret_cast<public_lib::Context *>(context);
    if (ctx->parserProgram == nullptr || ctx->parserProgram->Ast() == nullptr) {
        return false;
    }

    return BuildSymbolReferenceIndexForProgram(ctx, ctx->parserProgram);
}
```

## F018

Symbol: `ark::es2panda::lsp::GetReferencesAtPositionFromIndex`. Source-relative lines: 940–993.

```cpp
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
```

## F019

Symbol: `ark::es2panda::lsp::GetIndexedFileSource`. Source-relative lines: 1024–1031.

```cpp
std::string GetIndexedFileSource(const std::string &fileName)
{
    auto it = g_fileIndices.find(fileName);
    if (it == g_fileIndices.end()) {
        return "";
    }
    return it->second.source;
}
```

## F020

Symbol: `ark::es2panda::lsp::LevenshteinDistance`. Source-relative lines: 1079–1127.

```cpp
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
```

## F021

Symbol: `ark::es2panda::lsp::FindSimilarSymbolNames`. Source-relative lines: 1188–1228.

```cpp
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
```

