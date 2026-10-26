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

Source: `ets2panda/lsp/src/class_hierarchy_info.cpp`; symbol: `ark::es2panda::lsp::CreateClassPropertyItem`. Source-relative lines: 172–185.

```cpp
std::shared_ptr<ClassPropertyItem> CreateClassPropertyItem(const ir::ClassProperty *property,
                                                           const std::string &propertyName, std::string detail)
{
    if (property == nullptr || propertyName.empty() || detail.empty()) {
        return nullptr;
    }
    AccessModifierStyle access = AccessModifierStyle::PUBLIC;
    if (property->IsProtected()) {
        access = AccessModifierStyle::PROTECTED;
    }
    auto item = std::make_shared<ClassPropertyItem>(access, std::move(detail));
    item->SetVariableName(propertyName);
    return item;
}
```

## F003

Source: `ets2panda/lsp/src/create_type_help_items.cpp`; symbol: `ark::es2panda::lsp::GetEffectiveTypeParameterDeclarations`. Source-relative lines: 54–81.

```cpp
std::vector<checker::Type *> GetEffectiveTypeParameterDeclarations(const ir::AstNode *node,
                                                                   std::vector<checker::Type *> &result)
{
    if (node == nullptr) {
        return result;
    }
    const ir::TSTypeParameterDeclaration *typeParams = nullptr;
    if (node->IsClassDefinition()) {
        typeParams = node->AsClassDefinition()->TypeParams();
    } else if (node->IsTSInterfaceDeclaration()) {
        typeParams = node->AsTSInterfaceDeclaration()->TypeParams();
    } else if (node->IsTSTypeAliasDeclaration()) {
        typeParams = node->AsTSTypeAliasDeclaration()->TypeParams();
    } else if (node->IsETSStructDeclaration()) {
        typeParams = node->AsETSStructDeclaration()->Definition()->TypeParams();
    } else if (node->IsTSEnumDeclaration()) {
        auto members = node->AsTSEnumDeclaration()->Members();
        for (auto member : members) {
            result.push_back(reinterpret_cast<checker::Type *>(member->AsTSEnumMember()->Type()));
        }
    }
    if (typeParams != nullptr) {
        for (auto *param : typeParams->Params()) {
            result.push_back(reinterpret_cast<checker::Type *>(param));
        }
    }
    return result;
}
```

## F004

Source: `ets2panda/lsp/src/formatting/formatting_context.cpp`; symbol: `ark::es2panda::lsp::&FormattingContext::GetNextToken()const`. Source-relative lines: 65–68.

```cpp
const lexer::Token &FormattingContext::GetNextToken() const
{
    return nextToken_;
}
```

## F005

Source: `ets2panda/lsp/src/formatting/smart_indenter.cpp`; symbol: `ark::es2panda::lsp::GetActualIndentationForListStartLine`. Source-relative lines: 423–430.

```cpp
static size_t GetActualIndentationForListStartLine(const IndentContext &ctx, const std::vector<ir::AstNode *> &list)
{
    if (list.empty()) {
        return UNKNOWN_INDENT;
    }

    return GetIndentationForNode(ctx, list[0]);
}
```

## F006

Source: `ets2panda/lsp/src/get_definition_at_position.cpp`; symbol: `ark::es2panda::lsp::GetInvalidTypeOnlyExportTarget`. Source-relative lines: 143–164.

```cpp
static ir::Identifier *GetInvalidTypeOnlyExportTarget(const varbinder::ExportFact &fact, parser::Program *targetProgram,
                                                      util::StringView importedName)
{
    if (!fact.isInvalid || !fact.isExplicitTypeOnly || !fact.isLocalAlias || fact.sourceProgram != targetProgram ||
        fact.exportedName != importedName || fact.variable == nullptr || fact.variable->Declaration() == nullptr) {
        return nullptr;
    }

    auto *node = fact.variable->Declaration()->Node();
    if (node == nullptr || node->Program() != targetProgram) {
        return nullptr;
    }
    auto *identifier = node->IsIdentifier() ? node : node->FindChild([&fact](ir::AstNode *child) {
        return child->IsIdentifier() && child->AsIdentifier()->Name() == fact.localName &&
               child->AsIdentifier()->Variable() == fact.variable;
    });
    if (identifier == nullptr || !identifier->IsIdentifier() || identifier->AsIdentifier()->Name() != fact.localName ||
        identifier->AsIdentifier()->Variable() != fact.variable) {
        return nullptr;
    }
    return identifier->AsIdentifier();
}
```

## F007

Source: `ets2panda/lsp/src/get_signature.cpp`; symbol: `ark::es2panda::lsp::ClassPropertyHandler`. Source-relative lines: 89–127.

```cpp
ir::AstNode *ClassPropertyHandler(std::string sourceCode, size_t position, ir::AstNode *node, es2panda_Context *context)
{
    auto targetPos = FindClassNameStart(std::string(std::move(sourceCode)), position);
    auto methodName = std::string(node->AsIdentifier()->Name());
    auto targetNode = GetTouchingToken(context, targetPos, false);
    if (targetNode == nullptr || !targetNode->IsIdentifier()) {
        return nullptr;
    }
    auto declNode = compiler::DeclarationFromIdentifier(targetNode->AsIdentifier());
    if (declNode == nullptr || !declNode->IsClassProperty()) {
        return nullptr;
    }
    ir::Expression *typeRef;
    if (declNode->AsClassProperty()->TypeAnnotation() != nullptr) {
        typeRef = declNode->AsClassProperty()->TypeAnnotation();
    } else {
        auto value = declNode->AsClassProperty()->Value();
        if (value == nullptr || !value->IsETSNewClassInstanceExpression()) {
            return nullptr;
        }
        typeRef = value->AsETSNewClassInstanceExpression()->GetTypeRef();
    }
    if (typeRef == nullptr || !typeRef->IsETSTypeReference()) {
        return nullptr;
    }
    auto part = typeRef->AsETSTypeReference()->Part();
    if (part == nullptr) {
        return nullptr;
    }
    auto className = part->GetIdent();
    auto classNode = compiler::DeclarationFromIdentifier(className->AsIdentifier());
    if (classNode == nullptr) {
        return nullptr;
    }
    auto methodNode = classNode->FindChild([&methodName](ir::AstNode *childNode) {
        return childNode->IsMethodDefinition() && childNode->AsMethodDefinition()->Key()->ToString() == methodName;
    });
    return methodNode;
}
```

## F008

Source: `ets2panda/lsp/src/lsp_utils.cpp`; symbol: `ark::es2panda::lsp::ApplyRefactorTextChangesToSource`. Source-relative lines: 76–111.

```cpp
std::string ApplyRefactorTextChangesToSource(const std::string &source, const std::vector<TextChange> &textChanges)
{
    if (textChanges.empty()) {
        return source;
    }

    std::vector<const TextChange *> ordered;
    ordered.reserve(textChanges.size());
    for (const auto &change : textChanges) {
        ordered.push_back(&change);
    }
    std::stable_sort(ordered.begin(), ordered.end(),
                     [](const TextChange *lhs, const TextChange *rhs) { return lhs->span.start < rhs->span.start; });

    std::string result;
    result.reserve(source.size());
    size_t cursor = 0;
    for (const auto *change : ordered) {
        if (change->span.start > source.size()) {
            continue;
        }
        const size_t originalStart = change->span.start;
        const size_t start = std::max(originalStart, cursor);
        const size_t remaining = source.size() - originalStart;
        const size_t end = originalStart + std::min(change->span.length, remaining);
        if (cursor < start) {
            result.append(source, cursor, start - cursor);
        }
        result.append(change->newText);
        cursor = std::max(cursor, end);
    }
    if (cursor < source.size()) {
        result.append(source, cursor, source.size() - cursor);
    }
    return result;
}
```

## F009

Source: `ets2panda/lsp/src/refactors/convert_arrow_braces.cpp`; symbol: `ark::es2panda::lsp::GenerateBlockBody`. Source-relative lines: 156–160.

```cpp
static std::string GenerateBlockBody(ir::AstNode *blockBody)
{
    std::string bodyContent = blockBody->DumpEtsSrc();
    return "{ " + bodyContent + " }";
}
```

## F010

Source: `ets2panda/lsp/src/refactors/convert_overload_list.cpp`; symbol: `ark::es2panda::lsp::ConvertOverloadListRefactor::ConvertOverloadListRefactor`. Source-relative lines: 167–170.

```cpp
ConvertOverloadListRefactor::ConvertOverloadListRefactor()
{
    AddKind(std::string(CONVERT_OVERLOAD_LIST_ACTION.kind));
}
```

## F011

Source: `ets2panda/lsp/src/refactors/extract_symbol_impl.cpp`; symbol: `ark::es2panda::lsp::FindNextNonIndentAfterOptionalBlankLine`. Source-relative lines: 2384–2397.

```cpp
static size_t FindNextNonIndentAfterOptionalBlankLine(std::string_view source, size_t insertPos)
{
    size_t probe = std::min(insertPos, source.size());
    while (probe < source.size() && IsIndentChar(source[probe])) {
        ++probe;
    }
    if (probe < source.size() && IsLineBreakChar(source[probe])) {
        probe = NormalizeInsertPos(source, probe);
        while (probe < source.size() && IsIndentChar(source[probe])) {
            ++probe;
        }
    }
    return probe;
}
```

## F012

Source: `ets2panda/lsp/src/refactors/generate_override_methods.cpp`; symbol: `ark::es2panda::lsp::ParamNameFor`. Source-relative lines: 206–224.

```cpp
static std::string ParamNameFor(const ir::AstNode *param)
{
    if (param == nullptr) {
        return "param";
    }
    if (param->IsETSParameterExpression()) {
        auto *ident = param->AsETSParameterExpression()->Ident();
        if (ident != nullptr && ident->IsIdentifier()) {
            return ident->Name().Mutf8();
        }
    }
    if (param->IsAssignmentPattern()) {
        auto *left = param->AsAssignmentPattern()->Left();
        if (left != nullptr && left->IsIdentifier()) {
            return left->AsIdentifier()->Name().Mutf8();
        }
    }
    return "param";
}
```

## F013

Source: `ets2panda/lsp/src/register_code_fix/add_local_variable.cpp`; symbol: `ark::es2panda::lsp::AddLocalVariable::IsNonThisPropertyAccess`. Source-relative lines: 298–316.

```cpp
bool AddLocalVariable::IsNonThisPropertyAccess(es2panda_Context *context, size_t pos)
{
    auto *token = GetTouchingToken(context, pos, false);
    if (token == nullptr || !token->IsIdentifier()) {
        return false;
    }

    auto *parent = token->Parent();
    if (parent == nullptr || !parent->IsMemberExpression()) {
        return false;
    }

    auto *memberExpr = parent->AsMemberExpression();
    if (memberExpr->Property() != token) {
        return false;
    }

    return memberExpr->Object() != nullptr && !memberExpr->Object()->IsThisExpression();
}
```

## F014

Source: `ets2panda/lsp/src/register_code_fix/constructor_for_derived_need_super_call.cpp`; symbol: `ark::es2panda::lsp::ConstructorDerivedNeedSuper::NeedsSuperCall`. Source-relative lines: 76–99.

```cpp
bool ConstructorDerivedNeedSuper::NeedsSuperCall(ir::ScriptFunction *scriptFunc)
{
    if (scriptFunc == nullptr || scriptFunc->Body() == nullptr || !scriptFunc->Body()->IsBlockStatement()) {
        return false;
    }

    auto *block = scriptFunc->Body()->AsBlockStatement();
    for (const auto *stmt : block->Statements()) {
        if (!stmt->IsExpressionStatement()) {
            continue;
        }
        const auto *exprStmt = stmt->AsExpressionStatement();
        const auto *expr = exprStmt->GetExpression();
        if (!expr->IsCallExpression()) {
            continue;
        }
        const auto *callExpr = expr->AsCallExpression();
        const auto *callee = callExpr->Callee();
        if (callee != nullptr && callee->IsSuperExpression()) {
            return false;
        }
    }
    return true;
}
```

## F015

Source: `ets2panda/lsp/src/register_code_fix/fix_class_super_must_precede_this_access.cpp`; symbol: `ark::es2panda::lsp::FixClassSuperMustPrecedeThisAccess::FixClassSuperMustPrecedeThisAccess`. Source-relative lines: 107–112.

```cpp
FixClassSuperMustPrecedeThisAccess::FixClassSuperMustPrecedeThisAccess()
{
    auto errorCodes = CLASS_SUPER_MUST_PRECEDE_THIS_ACCESS.GetSupportedCodeNumbers();
    SetErrorCodes({errorCodes.begin(), errorCodes.end()});
    SetFixIds({CLASS_SUPER_MUST_PRECEDE_THIS_ACCESS.GetFixId().data()});
}
```

## F016

Source: `ets2panda/lsp/src/register_code_fix/fix_missing_call_parantheses.cpp`; symbol: `ark::es2panda::lsp::FixMissingCallParantheses::GetCodeActions`. Source-relative lines: 32–38.

```cpp
std::vector<CodeFixAction> FixMissingCallParantheses::GetCodeActions(const CodeFixContext &context)
{
    std::vector<CodeFixAction> returnedActions;
    if (context.errorCode == G_FIX_MISSING_CALL_PARANTHESES_CODE) {
    }
    return returnedActions;
}
```

## F017

Source: `ets2panda/lsp/src/register_code_fix/fix_remove_illegal_await.cpp`; symbol: `ark::es2panda::lsp::IsPromiseReturnType`. Source-relative lines: 228–235.

```cpp
bool IsPromiseReturnType(ir::TypeNode *returnType)
{
    if (returnType == nullptr) {
        return false;
    }

    return IsPromiseType(returnType->TsType()) || IsPromiseReturnTypeByName(returnType);
}
```

## F018

Source: `ets2panda/lsp/src/register_code_fix/fix_spelling_for_type.cpp`; symbol: `ark::es2panda::lsp::FixSpellingForType::MakeChangeForFixSpellingForType`. Source-relative lines: 89–100.

```cpp
void FixSpellingForType::MakeChangeForFixSpellingForType(ChangeTracker &changeTracker, es2panda_Context *context,
                                                         size_t pos, const std::string &target)
{
    auto *token = GetTouchingTokenRightMatch(context, pos);
    if (token == nullptr || !token->IsIdentifier()) {
        return;
    }

    auto ctx = reinterpret_cast<ark::es2panda::public_lib::Context *>(context);
    TextRange range = {token->Start().index, token->End().index};
    changeTracker.ReplaceRangeWithText(ctx->sourceFile, range, target);
}
```

## F019

Source: `ets2panda/lsp/src/register_code_fix/remove_catch_type_annotation.cpp`; symbol: `ark::es2panda::lsp::RemoveCatchTypeAnnotation::RemoveCatchTypeAnnotation`. Source-relative lines: 75–80.

```cpp
RemoveCatchTypeAnnotation::RemoveCatchTypeAnnotation()
{
    auto errorCodes = REMOVE_CATCH_TYPE_ANNOTATION.GetSupportedCodeNumbers();
    SetErrorCodes({errorCodes.begin(), errorCodes.end()});
    SetFixIds({REMOVE_CATCH_TYPE_ANNOTATION.GetFixId().data()});
}
```

## F020

Source: `ets2panda/lsp/src/services/import_utils.cpp`; symbol: `ark::es2panda::lsp::FormatImportSpecifier`. Source-relative lines: 197–203.

```cpp
std::string FormatImportSpecifier(const std::pair<std::string, std::string> &specifier)
{
    if (specifier.first == specifier.second) {
        return specifier.first;
    }
    return specifier.first + " as " + specifier.second;
}
```

## F021

Source: `ets2panda/lsp/src/signature_help_items.cpp`; symbol: `ark::es2panda::lsp::CreateSignatureHelpItem`. Source-relative lines: 82–115.

```cpp
SignatureHelpItem CreateSignatureHelpItem(checker::Signature &signature)
{
    const checker::SignatureInfo *signatureInfo = signature.GetSignatureInfo();
    SignatureHelpItem item;
    if (!signatureInfo->typeParams.empty()) {
        item.SetPrefixDisplayParts(CreatePunctuation("<"));
        for (auto it = signatureInfo->typeParams.begin(); it != signatureInfo->typeParams.end(); ++it) {
            std::string typeName = (*it)->ToString();
            item.SetPrefixDisplayParts(CreateTypeName(typeName));
            if (std::next(it) != signatureInfo->typeParams.end()) {
                item.SetPrefixDisplayParts(CreatePunctuation(","));
                item.SetSeparatorDisplayParts(CreatePunctuation(","));
            }
        }
        item.SetPrefixDisplayParts(CreatePunctuation(">"));
    }
    item.SetPrefixDisplayParts(CreatePunctuation("("));

    SetSignatureHelpParameter(signatureInfo, item);

    item.SetSuffixDisplayParts(CreatePunctuation(")"));

    if (signature.HasFunction() ||
        (signature.OwnerVar() != nullptr && signature.OwnerVar()->HasFlag(varbinder::VariableFlags::METHOD))) {
        item.SetSuffixDisplayParts(CreatePunctuation(":"));
    } else {
        item.SetSuffixDisplayParts(CreatePunctuation("=>"));
    }

    std::string returnType = signature.ReturnType()->ToString();
    item.SetSuffixDisplayParts(CreateTypeName(returnType));

    return item;
}
```

