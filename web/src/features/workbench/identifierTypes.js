const CWE_TYPES = Object.freeze({
  'CWE-22': '路径遍历', 'CWE-78': '操作系统命令注入', 'CWE-94': '代码注入',
  'CWE-119': '内存边界访问不当', 'CWE-125': '越界读取', 'CWE-129': '数组索引校验不当',
  'CWE-134': '格式化字符串使用不当', 'CWE-190': '整数溢出', 'CWE-191': '整数下溢',
  'CWE-195': '有符号到无符号转换错误', 'CWE-200': '敏感信息泄露',
  'CWE-319': '敏感信息明文传输', 'CWE-362': '竞态条件', 'CWE-400': '资源消耗失控',
  'CWE-401': '内存泄漏', 'CWE-404': '资源关闭或释放不当', 'CWE-415': '重复释放',
  'CWE-416': '释放后使用', 'CWE-457': '使用未初始化变量', 'CWE-476': '空指针解引用',
  'CWE-522': '凭据保护不足', 'CWE-532': '日志中写入敏感信息', 'CWE-681': '数值类型转换错误',
  'CWE-732': '关键资源权限配置不当', 'CWE-770': '资源分配缺少限制',
  'CWE-787': '越界写入', 'CWE-789': '内存分配缺少限制', 'CWE-825': '访问过期指针',
  'CWE-862': '缺少授权检查', 'CWE-863': '授权检查不当',
});

// These two labels are bound to the checked libpng detector rules and D30 source evidence.
// Do not assign a CVE to unrelated findings just because they share a CWE.
const CVE_TYPES = Object.freeze({
  'CVE-2026-33636': 'ARM NEON 调色板越界访问',
  'CVE-2026-46675': '释放后使用',
});

export function identifierType(id) {
  const normalized = typeof id === 'string' ? id.trim().toUpperCase() : '';
  return CWE_TYPES[normalized] || CVE_TYPES[normalized] || '类型待核对';
}

export function identifierLabel(id) {
  return `${id} · ${identifierType(id)}`;
}
