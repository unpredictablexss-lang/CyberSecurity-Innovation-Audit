import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { INITIAL_ANALYSIS_LABEL, DEEP_ANALYSIS_LABEL, ANALYSIS_DESCRIPTION, readableAnalysisText } from '../src/features/workbench/analysisLabels.js';

test('analysis names and explanation match the approved plain language copy', () => {
  assert.equal(INITIAL_ANALYSIS_LABEL, 'AI 初步分析（看当前片段）');
  assert.equal(DEEP_ANALYSIS_LABEL, 'AI 深入追查（查相关链）');
  assert.equal(ANALYSIS_DESCRIPTION, '初步分析只分析提供的代码；深入追查会继续查找相关源码。两种方式都不会修改代码。');
});
test('task toolbar and investigation form share the names and explanation', () => {
  for (const relative of ['pages/JobDetail.tsx','features/audits/OperationForms.tsx']) {
    const source=fs.readFileSync(new URL('../src/'+relative,import.meta.url),'utf8');
    assert.match(source,/label: INITIAL_ANALYSIS_LABEL/);
    assert.match(source,/label: DEEP_ANALYSIS_LABEL/);
    assert.ok(source.includes('{ANALYSIS_DESCRIPTION}') || source.includes(ANALYSIS_DESCRIPTION));
  }
});
test('dynamic historical disclosure and event text uses plain names without changing stored data', () => {
  const record=Object.freeze({message:'L2 快速研判结束；R2 queued',kind:'progressive_quick_screen'});
  assert.equal(readableAnalysisText(record.message),'AI 初步分析结束；AI 深入追查 queued');
  assert.equal(record.message,'L2 快速研判结束；R2 queued');
  assert.equal(record.kind,'progressive_quick_screen');
  assert.equal(readableAnalysisText(undefined),'');
});
test('all normal frontend copy excludes level codes and superseded analysis names', () => {
  const root=fileURLToPath(new URL('../src',import.meta.url));
  const findings=[];
  function walk(dir) {
    for(const item of fs.readdirSync(dir,{withFileTypes:true})) {
      const file=path.join(dir,item.name);
      if(item.isDirectory()) {walk(file);continue;}
      if(!/\.(tsx?|jsx?)$/.test(file) || file.endsWith('.d.ts')) continue;
      const source=fs.readFileSync(file,'utf8');
      const ast=ts.createSourceFile(file,source,ts.ScriptTarget.Latest,true,file.endsWith('.tsx')?ts.ScriptKind.TSX:ts.ScriptKind.JS);
      function visit(node) {
        const key=node.parent && (ts.isPropertyAssignment(node.parent)||ts.isPropertySignature(node.parent)) && node.parent.name===node;
        if(!key && (ts.isStringLiteral(node)||ts.isJsxText(node)||ts.isNoSubstitutionTemplateLiteral(node)||ts.isTemplateHead(node)||ts.isTemplateMiddle(node)||ts.isTemplateTail(node))) {
          if(/\b[LR][0-4]\b|快速研判|初步研判|深度调查|AI 分析（单次）|AI 追查源码（只读）/.test(node.text)) findings.push(path.relative(root,file)+': '+node.text.slice(0,100));
        }
        ts.forEachChild(node,visit);
      }
      visit(ast);
    }
  }
  walk(root);
  assert.deepEqual(findings,[]);
});
