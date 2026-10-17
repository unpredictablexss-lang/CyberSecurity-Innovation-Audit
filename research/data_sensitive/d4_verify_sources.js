#!/usr/bin/env node
'use strict';

// Offline verifier for D4's pinned OpenHarmony source evidence.
// It reads an existing local Git object database and never fetches or mutates it.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

function fail(message) {
  console.error(`FAIL: ${message}`);
  process.exitCode = 1;
}

function git(gitDir, args, asBuffer = false) {
  return execFileSync('git', [`--git-dir=${gitDir}`, ...args], {
    encoding: asBuffer ? undefined : 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
}

function blobSha(data) {
  const header = Buffer.from(`blob ${data.length}\0`, 'utf8');
  return crypto.createHash('sha1').update(Buffer.concat([header, data])).digest('hex');
}

function argValue(name) {
  const index = process.argv.indexOf(name);
  return index < 0 ? null : process.argv[index + 1];
}

const gitDirArg = argValue('--git-dir');
const sourceCacheArg = argValue('--source-cache');
if (!gitDirArg && !sourceCacheArg) {
  console.error('Usage: node d4_verify_sources.js (--git-dir <local-git-dir> | --source-cache <blob-cache-dir>) [--manifest <path>] [--api-evidence <path>]');
  process.exit(2);
}

const scriptDir = __dirname;
const manifestPath = argValue('--manifest') || path.join(scriptDir, 'D4_SOURCE_MANIFEST.json');
const gitDir = gitDirArg ? path.resolve(gitDirArg) : null;
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const sourceCache = sourceCacheArg ? path.resolve(sourceCacheArg) : null;
const apiEvidencePath = argValue('--api-evidence') || path.join(scriptDir, 'D4_SOURCE_API_VERIFICATION.json');
const apiEvidence = sourceCache ? JSON.parse(fs.readFileSync(apiEvidencePath, 'utf8')) : null;
const rows = manifest.files;
const checked = new Map();

if (sourceCache) {
  if (apiEvidence.repository !== manifest.repository) throw new Error('API evidence repository does not match source manifest');
  for (const sha of [manifest.before_commit, manifest.after_commit]) {
    const treeSha = sha === manifest.before_commit ? manifest.before_tree : manifest.after_tree;
    const commit = apiEvidence.commits?.[sha];
    const tree = apiEvidence.trees?.find((row) => row.sha === treeSha);
    if (!commit || commit.sha !== sha || commit.tree_sha !== treeSha || !tree || tree.truncated) {
      throw new Error(`${sha}: recorded GitHub commit/tree evidence is missing or mismatched`);
    }
  }
}

for (const row of rows) {
  const key = `${row.commit}:${row.file}`;
  if (checked.has(key)) continue;
  let data;
  if (sourceCache) {
    const apiRow = apiEvidence.files?.find((item) => item.commit === row.commit && item.path === row.file);
    if (!apiRow || apiRow.tree !== row.tree || apiRow.blob !== row.blob
        || apiRow.api_tree_blob !== row.blob || apiRow.size !== row.size || apiRow.api_tree_size !== row.size) {
      throw new Error(`${key}: recorded GitHub tree path evidence does not match the manifest`);
    }
    data = fs.readFileSync(path.join(sourceCache, row.blob));
    const actualBlob = blobSha(data);
    if (actualBlob !== row.blob) throw new Error(`${key}: cached Git blob ${actualBlob} != ${row.blob}`);
  } else {
    const actualTree = git(gitDir, ['rev-parse', `${row.commit}^{tree}`]).trim();
    if (actualTree !== row.tree) throw new Error(`${key}: tree ${actualTree} != ${row.tree}`);
    const actualBlob = git(gitDir, ['rev-parse', `${row.commit}:${row.file}`]).trim();
    if (actualBlob !== row.blob) throw new Error(`${key}: blob ${actualBlob} != ${row.blob}`);
    data = git(gitDir, ['show', `${row.commit}:${row.file}`], true);
  }
  const sha256 = crypto.createHash('sha256').update(data).digest('hex');
  if (sha256 !== row.sha256) throw new Error(`${key}: SHA-256 ${sha256} != ${row.sha256}`);
  if (data.length !== row.size) throw new Error(`${key}: size ${data.length} != ${row.size}`);
  checked.set(key, data.toString('utf8'));
}

const before = checked.get(`${manifest.before_commit}:core/transmission/trans_channel/tcp_direct/src/trans_tcp_direct_message.c`);
const after = checked.get(`${manifest.after_commit}:core/transmission/trans_channel/tcp_direct/src/trans_tcp_direct_message.c`);
const request = checked.get(`${manifest.before_commit}:core/transmission/common/src/softbus_message_open_channel.c`);
const afterRequest = checked.get(`${manifest.after_commit}:core/transmission/common/src/softbus_message_open_channel.c`);
const unpackStart = request.indexOf('int UnpackRequest(');
const unpackEnd = request.indexOf('char *PackReply(', unpackStart);
const unpackRequest = unpackStart >= 0 && unpackEnd > unpackStart ? request.slice(unpackStart, unpackEnd) : '';
const logger = checked.get(`${manifest.before_commit}:core/common/log/softbus_log.c`);
const adapter = checked.get(`${manifest.before_commit}:adapter/common/log/softbus_adapter_log.c`);
const config = checked.get(`${manifest.before_commit}:core/common/softbus_property/softbus_feature_config.c`);
const listener = checked.get(`${manifest.before_commit}:core/transmission/trans_channel/tcp_direct/src/trans_tcp_direct_listener.c`);
const rootBuild = checked.get(`${manifest.before_commit}:BUILD.gn`);
const coreBuild = checked.get(`${manifest.before_commit}:core/BUILD.gn`);
const frameBuild = checked.get(`${manifest.before_commit}:core/frame/BUILD.gn`);
const transBuild = checked.get(`${manifest.before_commit}:core/transmission/trans.gni`);
const transChannelBuild = checked.get(`${manifest.before_commit}:core/transmission/trans_channel/trans_channel.gni`);
const tcpDirectBuild = checked.get(`${manifest.before_commit}:core/transmission/trans_channel/tcp_direct/tcp_direct.gni`);
const adapterBuild = checked.get(`${manifest.before_commit}:adapter/BUILD.gn`);
const standardServiceConfig = checked.get(`${manifest.before_commit}:core/frame/standard/init/src/softbus_server.cfg`);
const muslServiceConfig = checked.get(`${manifest.before_commit}:core/frame/standard/init/src/softbus_server_musl.cfg`);
const replyStart = request.indexOf('char *PackReply(');
const replyEnd = request.indexOf('UnpackReply(', replyStart);
const packReply = replyStart >= 0 && replyEnd > replyStart ? request.slice(replyStart, replyEnd) : '';
const logCall = 'SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ProcessReceivedData: %s", crypInfo.out)';
const decryptGuard = before.indexOf('if (DecryptMessage(channelId, flags, &crypInfo) != SOFTBUS_OK)');
const decryptFailureReturn = before.indexOf('return SOFTBUS_ERR;', decryptGuard);
const parseCall = before.indexOf('cJSON *packet = cJSON_Parse(crypInfo.out)');
const parseGuard = before.indexOf('if (packet == NULL)', parseCall);
const parseFailureReturn = before.indexOf('return SOFTBUS_ERR;', parseGuard);
const plaintextLog = before.indexOf(logCall);
const authSideStart = before.indexOf('static AuthSideFlag GetAuthSideFlag(');
const authSideEnd = authSideStart < 0 ? -1 : before.indexOf('\n}', authSideStart);
const authSideBody = authSideEnd > authSideStart ? before.slice(authSideStart, authSideEnd) : '';
const parseFailureBody = parseGuard >= 0 && plaintextLog > parseGuard ? before.slice(parseGuard, plaintextLog) : '';
const packBytesStart = before.indexOf('static int32_t PackBytes(');
const postBytesStart = before.indexOf('int32_t TransTdcPostBytes(');
const decryptStart = before.indexOf('static int32_t DecryptMessage(');
const receivedDataStart = before.indexOf('static int32_t ProcessReceivedData(');
const packBytesBody = packBytesStart >= 0 && postBytesStart > packBytesStart ? before.slice(packBytesStart, postBytesStart) : '';
const postBytesBody = postBytesStart >= 0 && decryptStart > postBytesStart ? before.slice(postBytesStart, decryptStart) : '';
const decryptBody = decryptStart >= 0 && receivedDataStart > decryptStart ? before.slice(decryptStart, receivedDataStart) : '';

const checks = [
  ['pre-dispatch plaintext log exists', /SoftBusLog\(SOFTBUS_LOG_TRAN,\s*SOFTBUS_LOG_ERROR,\s*"ProcessReceivedData: %s",\s*crypInfo\.out\)/.test(before)],
  ['later revision removes that log', !/SoftBusLog\(SOFTBUS_LOG_TRAN,\s*SOFTBUS_LOG_ERROR,\s*"ProcessReceivedData: %s",\s*crypInfo\.out\)/.test(after)],
  ['plaintext log is reached only after successful decryption', decryptGuard >= 0 && decryptFailureReturn > decryptGuard && decryptFailureReturn < plaintextLog],
  ['decrypted output is NUL-terminated before JSON parsing and string logging', /crypInfo\.out\[crypInfo\.outLen\]\s*=\s*0;[\s\S]*?cJSON\s*\*packet\s*=\s*cJSON_Parse\(crypInfo\.out\)[\s\S]*?SoftBusLog\(SOFTBUS_LOG_TRAN,\s*SOFTBUS_LOG_ERROR,\s*"ProcessReceivedData: %s",\s*crypInfo\.out\)/.test(before)],
  ['plaintext log is reached only after successful JSON parse', parseCall >= 0 && parseGuard > parseCall && parseFailureReturn > parseGuard && parseFailureReturn < plaintextLog],
  ['sender stores generated key, packs that AppInfo and transmits it as FLAG_REQUEST', /SoftBusGenerateSessionKey\(conn->appInfo\.sessionKey,\s*SESSION_KEY_LENGTH\)[\s\S]*?PackRequest\(&conn->appInfo\)[\s\S]*?\.flags\s*=\s*\(FLAG_REQUEST\s*\|\s*cipherFlag\)[\s\S]*?TransTdcPostBytes\(conn->channelId,\s*&packetHead,\s*bytes\)/.test(listener)],
  ['request packs SESSION_KEY', /AddStringToJsonObject\(json,\s*SESSION_KEY,\s*\(char\s*\*\)encodeSessionKey\)/.test(request)],
  ['request decoder reads SESSION_KEY and Base64-decodes it into AppInfo sessionKey', /GetJsonObjectStringItem\(msg,\s*SESSION_KEY,\s*sessionKey,\s*sizeof\(sessionKey\)\)/.test(unpackRequest) && /SoftBusBase64Decode\(\(unsigned char\s*\*\)appInfo->sessionKey,[\s\S]*?\(unsigned char\s*\*\)sessionKey/.test(unpackRequest)],
  ['later revision retains SESSION_KEY decode into AppInfo sessionKey', (() => {
    const start = afterRequest.indexOf('int UnpackRequest(');
    const end = afterRequest.indexOf('char *PackReply(', start);
    const body = start >= 0 && end > start ? afterRequest.slice(start, end) : '';
    return /GetJsonObjectStringItem\(msg,\s*SESSION_KEY,\s*sessionKey,\s*sizeof\(sessionKey\)\)/.test(body)
      && /SoftBusBase64Decode\(\(unsigned char\s*\*\)appInfo->sessionKey,[\s\S]*?\(unsigned char\s*\*\)sessionKey/.test(body);
  })()],
  ['request decoder clears temporary encoded key after decoding', /SoftBusBase64Decode\([\s\S]*?\(void\)memset_s\(sessionKey,\s*sizeof\(sessionKey\),\s*0,\s*sizeof\(sessionKey\)\)/.test(unpackRequest)],
  ['later revision still packs SESSION_KEY in request JSON', /AddStringToJsonObject\(json,\s*SESSION_KEY,\s*\(char\s*\*\)encodeSessionKey\)/.test(afterRequest)],
  ['PackReply does not add SESSION_KEY', replyStart >= 0 && replyEnd > replyStart && !/SESSION_KEY/.test(packReply)],
  ['PackBytes encrypts JSON payload into packet buffer via Auth API', /cryptInfo\.in\s*=\s*\(char\s*\*\)data/.test(packBytesBody)
    && /cryptInfo\.out\s*=\s*buffer\s*\+\s*DC_MSG_PACKET_HEAD_SIZE/.test(packBytesBody)
    && /EncryptDataByAuthId\(authId,\s*&cryptInfo,[\s\S]*?EncryptDataByConnOpt\(channelId,\s*&cryptInfo,/.test(packBytesBody)
    && /AuthEncryptBySeq\(\(int32_t\)authId,[\s\S]*?cryptInfo->in/.test(before)
    && /AuthEncrypt\(&option,[\s\S]*?cryptInfo->in/.test(before)],
  ['TransTdcPostBytes sends encrypted packet buffer produced by PackBytes', /PackBytes\(channelId,\s*data,\s*packetHead,\s*buffer,\s*bufferLen\)[\s\S]*?SendTcpData\(fd,\s*buffer,\s*bufferLen,\s*0\)/.test(postBytesBody)],
  ['DecryptMessage writes AuthDecrypt output to cryptInfo.out and returns success only after decrypt', /outbuf\.buf\s*=\s*\(uint8_t\s*\*\)cryptInfo->out[\s\S]*?AuthDecrypt\(&option,[\s\S]*?if\s*\(ret\s*!=\s*SOFTBUS_OK\)[\s\S]*?return\s+SOFTBUS_ERR;[\s\S]*?cryptInfo->outLen\s*=\s*outbuf\.outLen;[\s\S]*?return\s+ret;/.test(decryptBody)],
  ['message log precedes request/reply dispatch', before.indexOf(logCall) >= 0 && before.indexOf('ProcessMessage(channelId, flags, seq, packet)') > before.indexOf(logCall)],
  ['logger uses 256-byte buffer', /#define LOG_PRINT_MAX_LEN 256/.test(logger)],
  ['logger formats with bounded vsprintf_s', /vsprintf_s\(&szStr\[ulPos\],\s*sizeof\(szStr\)\s*-\s*ulPos/.test(logger)],
  ['formatting error returns before output', /if\s*\(ret\s*<\s*0\)\s*\{[^}]*return;\s*\}[\s\S]*?SoftBusOutPrint\(szStr, level\)/.test(logger)],
  ['HiLog adapter marks full buffer public', /HILOG_ERROR\([^;]*"%\{public\}s",\s*buf\)/s.test(adapter)],
  ['default adapter log threshold is zero', /#define ADAPTER_LOG_LEVEL 0/.test(config)],
  ['component exposes the softbus server feature', /lite_component\("dsoftbus"\)\s*\{[\s\S]*?"core:softbus_server"/.test(rootBuild)],
  ['core server feature depends on the frame server target', /lite_component\("softbus_server"\)\s*\{[\s\S]*?"frame:softbus_server_frame"/.test(coreBuild)],
  ['server frame source set includes trans_session_src', /dsoftbus_server_common_src\s*=[\s\S]*?trans_session_src/.test(frameBuild)],
  ['standard softbus_server target compiles the common source set', /ohos_shared_library\("softbus_server"\)\s*\{[\s\S]*?sources\s*=\s*dsoftbus_server_common_src/.test(frameBuild)],
  ['trans_session_src is sourced from trans_channel_src', /trans_session_src\s*=\s*trans_channel_src/.test(transBuild)],
  ['trans_channel imports and includes TCP Direct source definitions', /trans_channel\/tcp_direct\/tcp_direct\.gni/.test(transChannelBuild) && /trans_direct_channel_src/.test(transChannelBuild)],
  ['TCP Direct source list contains the logged receive and sender paths', /trans_tcp_direct_listener\.c/.test(tcpDirectBuild) && /trans_tcp_direct_message\.c/.test(tcpDirectBuild)],
  ['standard adapter target builds the HiLog adapter implementation', /ohos_shared_library\("softbus_adapter"\)[\s\S]*?softbus_adapter_log\.c/.test(adapterBuild)],
  ['standard adapter declares the Secure-C libsec_static dependency', /ohos_shared_library\("softbus_adapter"\)[\s\S]*?public_deps\s*=\s*\[[\s\S]*?\/\/third_party\/bounds_checking_function:libsec_static/.test(adapterBuild)],
  ['standard service target selects init identity config according to use_musl', /if\s*\(use_musl\)[\s\S]*softbus_server_musl\.cfg[\s\S]*else\s*\{[\s\S]*softbus_server\.cfg/.test(frameBuild)],
  ['non-musl service config runs softbus_server as system', /"name"\s*:\s*"softbus_server"[\s\S]*?"uid"\s*:\s*"system"[\s\S]*?"gid"\s*:\s*\[\s*"system"\s*,\s*"shell"\s*\]/.test(standardServiceConfig)],
  ['musl service config runs softbus_server as dsoftbus', /"name"\s*:\s*"softbus_server"[\s\S]*?"uid"\s*:\s*"dsoftbus"[\s\S]*?"gid"\s*:\s*\[\s*"dsoftbus"\s*,\s*"system"\s*,\s*"shell"\s*\]/.test(muslServiceConfig)],
  ['same SoftBusLog name in GetAuthSideFlag logs only scalar protocol metadata', authSideBody.includes('GetAuthSideFlag: flags=%d, side=%d, seq=%lld') && /,\s*flags,\s*side,\s*seq\s*\)/.test(authSideBody) && !/crypInfo\.out|SESSION_KEY/.test(authSideBody)],
  ['JSON parse failure frees output and logs a constant message before returning', /SoftBusFree\(crypInfo\.out\)[\s\S]*?SoftBusLog\(SOFTBUS_LOG_TRAN,\s*SOFTBUS_LOG_ERROR,\s*"srv process recv data: json parse failed\."\)[\s\S]*?return SOFTBUS_ERR;/.test(parseFailureBody)],
];

for (const [label, passed] of checks) {
  console.log(`${passed ? 'PASS' : 'FAIL'} ${label}`);
  if (!passed) process.exitCode = 1;
}

if (!process.exitCode) {
  console.log(`Verified ${checked.size} exact source objects across ${new Set(rows.map((r) => r.commit)).size} commits.`);
  if (sourceCache) console.log(`Cached source bytes validated against recorded complete GitHub API commit/tree/path evidence at ${apiEvidence.retrieved_on}.`);
  console.log('This verifies source evidence only; it does not prove product build inclusion, runtime output, or reader authorization.');
}
