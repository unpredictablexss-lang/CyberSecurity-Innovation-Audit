from __future__ import annotations
import hashlib
import subprocess
import unittest
from pathlib import Path
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.catalog import build_registry, catalog_metadata, default_detector_ids
from src.ohscanner.detectors.known_cves import KnownDisclosedCveDetector
from src.ohscanner.fixture import snapshot_digest

PINNED_HEAD = "db77164fdc2af0da02e4d3efc056d84694fd68e8"
REPO_ROOT = Path(__file__).resolve().parents[2]

def read_pinned_git_blob(relative_path):
    object_id = f"{PINNED_HEAD}:{relative_path}"
    process = subprocess.run(
        ["git", "cat-file", "blob", object_id],
        cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if process.returncode != 0:
        raise RuntimeError(
            f"cannot read pinned Git blob {object_id}: "
            + process.stderr.decode("utf-8", errors="replace").strip()
        )
    return process.stdout

def git_blob_sha1(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


class KnownDisclosedCveTests(unittest.TestCase):
    def run_source(self, source, path="sample.c", parse_status="complete"):
        unit=SourceUnit(path=path, language="c", text=source, sha256=hashlib.sha256(source.encode()).hexdigest(), parse_status=parse_status)
        request=ScanRequest(request_id="test:known-cves", repository="fixture/known-cves", commit="a"*40, snapshot_sha256=snapshot_digest((unit,)), target_id="current-component:fixture/known-cves", profile_id="fixture-no-build", provenance="fixture")
        run=KnownDisclosedCveDetector().detect(ScanContext(request=request, units=(unit,)), (unit,))
        return run

    def run_units(self, sources):
        units = tuple(
            SourceUnit(path=path, language="cpp" if path.endswith((".cpp", ".h")) else "c",
                       text=text, sha256=hashlib.sha256(text.encode()).hexdigest(),
                       parse_status="complete")
            for path, text in sorted(sources.items())
        )
        request = ScanRequest(request_id="test:known-cves-multi", repository="fixture/known-cves",
                              commit="b" * 40, snapshot_sha256=snapshot_digest(units),
                              target_id="current-component:fixture/known-cves",
                              profile_id="fixture-no-build", provenance="fixture")
        return KnownDisclosedCveDetector().detect(ScanContext(request=request, units=units), units)

    def test_appdomainverify_cve_2026_58313_real_lru_fix_pair(self):
        vulnerable = read_pinned_git_blob(
            "tests/fixtures/data_sensitive/d39_cve_2026_58313_lru_vulnerable.h")
        fixed = read_pinned_git_blob(
            "tests/fixtures/data_sensitive/d39_cve_2026_58313_lru_fixed.h")
        path = "frameworks/common/include/utils/lru_cache_util.h"

        self.assertEqual(git_blob_sha1(vulnerable), "7ce4262e3f1d2c0173d929318a4795ff1573c721")
        self.assertEqual(git_blob_sha1(fixed), "68114f10d83c8f0bdc46679c7efa35ed286bef8a")
        vulnerable_text = vulnerable.decode("utf-8")
        fixed_text = fixed.decode("utf-8")
        run = self.run_source(vulnerable_text, path)
        findings = [finding for finding in run.findings if finding.symbol == "CVE-2026-58313"]
        self.assertEqual(1, len(findings))
        self.assertEqual("CWE-416", findings[0].candidate_cwe)
        self.assertEqual(hashlib.sha256(vulnerable).hexdigest(), findings[0].source_sha256)
        self.assertIn("invalidated iterators", findings[0].message)
        self.assertEqual([], [finding for finding in self.run_source(fixed_text, path).findings
                              if finding.symbol == "CVE-2026-58313"])
        partial = self.run_source(vulnerable_text, path, parse_status="partial")
        self.assertEqual("blocked", partial.status)
        self.assertEqual(1, len([finding for finding in partial.findings
                                 if finding.symbol == "CVE-2026-58313"]))
        self.assertEqual([], [finding for finding in self.run_source(vulnerable_text, "other/lru_cache_util.h").findings
                              if finding.symbol == "CVE-2026-58313"])
    def test_storage_external_volume_cve_2026_25850_vulnerable_fixed_and_unrelated(self):
        path = "services/storage_daemon/volume/src/external_volume_info.cpp"
        vulnerable = """int32_t ExternalVolumeInfo::DoMount4Ext(uint32_t flags) {
            mode_t mode = 0777;
            int32_t ret = mount(devPath_.c_str(), mountPath_.c_str(), fsType_.c_str(), flags, "");
            if (ret) return E_EXT_MOUNT;
            TravelChmod(mountPath_, mode);
            return ret;
        }
        int32_t ExternalVolumeInfo::DoMount4Hmfs(uint32_t flags) {
            mode_t mode = 0777;
            int32_t ret = mount(devPath_.c_str(), mountPath_.c_str(), "hmfs", flags, "");
            if (!ret) TravelChmod(mountPath_, mode);
            return ret;
        }"""
        fixed = vulnerable.replace("            mode_t mode = 0777;\n", "").replace(
            "            TravelChmod(mountPath_, mode);\n", "").replace(
            "            if (!ret) TravelChmod(mountPath_, mode);\n", "")
        unrelated = vulnerable.replace("DoMount4Ext", "MountUnrelated").replace(
            "DoMount4Hmfs", "MountOtherFilesystem")

        findings = [f for f in self.run_source(vulnerable, path).findings
                    if f.symbol == "CVE-2026-25850"]
        self.assertEqual(2, len(findings))
        self.assertEqual({"CWE-732"}, {f.candidate_cwe for f in findings})
        self.assertEqual({"confidentiality"}, {f.consequence_impact for f in findings})
        self.assertTrue(all(f.source_sha256 == hashlib.sha256(vulnerable.encode()).hexdigest()
                            for f in findings))
        self.assertEqual([], [f for f in self.run_source(fixed, path).findings
                              if f.symbol == "CVE-2026-25850"])
        self.assertEqual([], [f for f in self.run_source(vulnerable, "other.cpp").findings
                              if f.symbol == "CVE-2026-25850"])
        self.assertEqual([], [f for f in self.run_source(unrelated, path).findings
                              if f.symbol == "CVE-2026-25850"])

    def test_storage_cve_2026_28733_iterator_escape_survives_mutex_patch(self):
        path = "services/storage_daemon/ipc/src/storage_daemon_stub.cpp"
        shared = """std::map<uint32_t, RadarStatisticInfo>::iterator
        StorageDaemonStub::GetUserStatistics(const uint32_t userId) {
            std::lock_guard<std::mutex> lock(mutexStats_);
            auto it = opStatistics_.find(userId);
            if (it != opStatistics_.end()) return it;
            RadarStatisticInfo radarInfo = { 0 };
            return opStatistics_.insert(make_pair(userId, radarInfo)).first;
        }
        void StorageDaemonStub::GetTempStatistics(std::map<uint32_t, RadarStatisticInfo> &statistics) {
            std::lock_guard<std::mutex> lock(mutexStats_);
            statistics.insert(opStatistics_.begin(), opStatistics_.end());
            opStatistics_.clear();
        }
        int StorageDaemonStub::HandleStartUser(uint32_t userId) {
            auto it = GetUserStatistics(userId);
            int err = StartUser(userId);
            if (err != E_OK) it->second.userStartFailCount++;
            return err;
        }"""
        findings = [f for f in self.run_source(shared, path).findings
                    if f.symbol == "CVE-2026-28733"]
        self.assertEqual(1, len(findings))
        self.assertGreater(findings[0].line, 0)
        self.assertEqual("CWE-416", findings[0].candidate_cwe)
        self.assertEqual(hashlib.sha256(shared.encode()).hexdigest(), findings[0].source_sha256)
        self.assertIn("iterator-lifetime gap", findings[0].message)

        fixed = """void StorageDaemonStub::UpdateUserStatistics(uint32_t userId) {
            std::lock_guard<std::mutex> lock(mutexStats_);
            auto it = opStatistics_.find(userId);
            if (it == opStatistics_.end()) {
                it = opStatistics_.insert(make_pair(userId, RadarStatisticInfo{0})).first;
            }
            it->second.userStartFailCount++;
        }
        void StorageDaemonStub::GetTempStatistics(std::map<uint32_t, RadarStatisticInfo> &statistics) {
            std::lock_guard<std::mutex> lock(mutexStats_);
            statistics.insert(opStatistics_.begin(), opStatistics_.end());
            opStatistics_.clear();
        }
        int StorageDaemonStub::HandleStartUser(uint32_t userId) {
            int err = StartUser(userId);
            if (err != E_OK) UpdateUserStatistics(userId);
            return err;
        }"""
        self.assertEqual([], [f for f in self.run_source(fixed, path).findings
                              if f.symbol == "CVE-2026-28733"])
        self.assertEqual([], [f for f in self.run_source(shared, "other.cpp").findings
                              if f.symbol == "CVE-2026-28733"])

    def test_storage_cve_2026_28751_mtp_full_length_xattr_and_fixed_shape(self):
        path = "services/storage_manager/volume/src/volume_manager_service.cpp"
        vulnerable = """void VolumeManagerService::NotifyMtpMounted(const std::string &id, const std::string &path) {
            std::string key = "user.getfriendlyname";
            char *value = (char *)malloc(sizeof(char) * MTP_DEVICE_NAME_LEN);
            int32_t len = getxattr(path.c_str(), key.c_str(), value, MTP_DEVICE_NAME_LEN);
            if (len >= 0 && len < MTP_DEVICE_NAME_LEN) {
                value[len] = '\\0';
            }
            if (len > 0) {
                volumePtr->SetDescription(std::string(value));
            }
        }"""
        fixed = vulnerable.replace(
            "malloc(sizeof(char) * MTP_DEVICE_NAME_LEN)",
            "malloc(sizeof(char) * (MTP_DEVICE_NAME_LEN + 1))",
        ).replace(
            "len < MTP_DEVICE_NAME_LEN", "len <= MTP_DEVICE_NAME_LEN"
        )
        unrelated = vulnerable.replace(
            "std::string(value)", "std::string(\"constant\")"
        )
        findings = [f for f in self.run_source(vulnerable, path).findings
                    if f.symbol == "CVE-2026-28751"]
        self.assertEqual(1, len(findings))
        self.assertGreater(findings[0].line, 0)
        self.assertEqual("CWE-125", findings[0].candidate_cwe)
        self.assertEqual(hashlib.sha256(vulnerable.encode()).hexdigest(),
                         findings[0].source_sha256)
        self.assertEqual([], [f for f in self.run_source(fixed, path).findings
                              if f.symbol == "CVE-2026-28751"])
        self.assertEqual([], [f for f in self.run_source(unrelated, path).findings
                              if f.symbol == "CVE-2026-28751"])
        self.assertEqual([], [f for f in self.run_source(vulnerable, "other.cpp").findings
                              if f.symbol == "CVE-2026-28751"])

    def test_curl_cve_2026_92392_version_bound_cleanup_order_and_fix(self):
        path = "lib/multi.c"
        vulnerable = """static CURLcode multi_done(struct Curl_easy *data, struct connectdata *conn, bool premature, CURLcode status) {
            result = Curl_1st_fatal(result, Curl_xfer_write_done(data, premature));
            if (conn) Curl_conn_ev_data_done(data, premature);
            multi_schedule_pending(data->multi);
            if (!result) result = Curl_req_done(&data->req, data, premature);
            if (conn) {
                Curl_cpool_do_locked(data, data->conn, multi_done_locked, &mdctx);
            }
            return result;
        }"""
        fixed = """static CURLcode multi_done(struct Curl_easy *data, struct connectdata *conn, bool premature, CURLcode status) {
            result = Curl_1st_fatal(result, Curl_xfer_write_done(data, premature));
            if (!result) result = Curl_req_done(&data->req, data, premature);
            if (conn) {
                Curl_conn_ev_data_done(data, premature);
                Curl_detach_connection(data);
                Curl_cpool_return(data, conn, multi_done_locked, &mdctx);
                if (data->multi) multi_schedule_pending(data->multi);
            }
            return result;
        }"""
        version = '#define LIBCURL_VERSION "8.22.0"\n'
        run = self.run_units({path: vulnerable, "include/curl/curlver.h": version})
        findings = [f for f in run.findings if f.symbol == "CVE-2026-92392"]
        self.assertEqual(1, len(findings))
        self.assertGreater(findings[0].line, 0)
        self.assertEqual("CWE-416", findings[0].candidate_cwe)
        self.assertIn("affected range", findings[0].message)
        self.assertEqual(hashlib.sha256(vulnerable.encode()).hexdigest(), findings[0].source_sha256)

        def scan_with(version_text, code=vulnerable):
            return [f for f in self.run_units({
                path: code,
                "include/curl/curlver.h": f'#define LIBCURL_VERSION "{version_text}"\n',
            }).findings if f.symbol == "CVE-2026-92392"]
        without_pending_reschedule = vulnerable.replace("multi_schedule_pending(data->multi);", "")
        self.assertEqual(1, len(scan_with("8.12.0", without_pending_reschedule)))

        self.assertEqual([], scan_with("8.23.0", fixed))
        self.assertEqual([], scan_with("8.22.0", fixed))
        self.assertEqual([], scan_with("8.8.0"))
        self.assertEqual([], scan_with("8.20.2"))
        for affected_backport in ("8.12.0", "8.14.2", "8.16.1", "8.20.1", "8.21.0"):
            self.assertEqual(1, len(scan_with(affected_backport)), affected_backport)
        for fixed_backport in ("8.14.3", "8.16.2", "8.20.2"):
            self.assertEqual([], scan_with(fixed_backport), fixed_backport)
        conflicting_versions = [f for f in self.run_units({
            path: vulnerable,
            "include/curl/curlver.h": '#define LIBCURL_VERSION "8.22.0"',
            "vendor/include/curl/curlver.h": '#define LIBCURL_VERSION "8.23.0"',
        }).findings if f.symbol == "CVE-2026-92392"]
        self.assertEqual(1, len(conflicting_versions))
        self.assertIn("version applicability remains unknown", conflicting_versions[0].message)

        unknown = [f for f in self.run_source(vulnerable, path).findings
                   if f.symbol == "CVE-2026-92392"]
        self.assertEqual(1, len(unknown))
        self.assertIn("version applicability remains unknown", unknown[0].message)

    def test_device_manager_cve_2022_45877_pin_serialized_to_softbus_and_fixed(self):
        vulnerable = """void DmAuthManager::OnGroupCreated(int64_t requestId, const std::string &groupId) {
            int32_t pinCode = GeneratePincode();
            nlohmann::json jsonObj;
            jsonObj[PIN_CODE_KEY] = pinCode;
            jsonObj[PIN_TOKEN] = authResponseContext_->token;
            authResponseContext_->authToken = jsonObj.dump();
            authMessageProcessor_->SetResponseContext(authResponseContext_);
            std::string message = authMessageProcessor_->CreateSimpleMessage(MSG_TYPE_RESP_AUTH);
            softbusConnector_->GetSoftbusSession()->SendData(authResponseContext_->sessionId, message);
        }"""
        fixed = vulnerable.replace("jsonObj[PIN_CODE_KEY] = pinCode;\n            ", "")
        unrelated = """void Other::OnGroupCreated() {
            jsonObj[PIN_CODE_KEY] = pinCode;
            authResponseContext_->authToken = jsonObj.dump();
        }
        void SendOtherMessage() {
            softbusConnector_->GetSoftbusSession()->SendData(authResponseContext_->sessionId, message);
        }"""
        vulnerable_run = self.run_source(vulnerable, "dm_auth_manager.cpp", "partial")
        findings = [f for f in vulnerable_run.findings if f.symbol == "CVE-2022-45877"]
        self.assertEqual(1, len(findings))
        self.assertEqual("CWE-319", findings[0].candidate_cwe)
        self.assertEqual("sensitive_data_exposure", findings[0].consequence_impact)
        self.assertIn("unconfirmed", findings[0].message)
        self.assertEqual("blocked", vulnerable_run.status)
        self.assertEqual([], [f for f in self.run_source(fixed, "dm_auth_manager.cpp").findings
                              if f.symbol == "CVE-2022-45877"])
        self.assertEqual([], [f for f in self.run_source(unrelated, "dm_auth_manager.cpp").findings
                              if f.symbol == "CVE-2022-45877"])

    def test_libtiff_vulnerable_fixed_and_unrelated_guard_shapes(self):
        vulnerable = """int TIFFReadRGBAImageOriented(TIFF *tif, uint32_t rwidth, uint32_t rheight, uint32_t *raster, int orientation, int stop) {
            ok = TIFFRGBAImageGet(&img, raster + (rheight - img.height) * rwidth, rwidth, img.height);
            return ok;
        }"""
        fixed = """int TIFFReadRGBAImageOriented(TIFF *tif, uint32_t rwidth, uint32_t rheight, uint32_t *raster, int orientation, int stop) {
            ok = TIFFRGBAImageGet(&img, raster, rwidth, rheight);
            return ok;
        }"""
        previous_guard = """void unrelated(void) {
            if (rwidth < img.width || rheight < img.height) return;
        }
        """ + vulnerable
        self.assertIn("CVE-2025-9900", {f.symbol for f in self.run_source(vulnerable, "tif_getimage.c").findings})
        self.assertEqual((), self.run_source(fixed, "tif_getimage.c").findings)
        self.assertIn("CVE-2025-9900", {f.symbol for f in self.run_source(previous_guard, "tif_getimage.c").findings})

    def test_cjson_recursive_bidirectional_linear_matching(self):
        source="""int cJSON_Compare(node *a,node *b){ node *x; for_each(x,a){ y=get_object_item(b,x->string); if(!cJSON_Compare(x,y)) return 0; } for_each(y,b){ x=get_object_item(a,y->string); if(!cJSON_Compare(y,x)) return 0; } return 1; }""".replace("for_each", "cJSON_ArrayForEach")
        run=self.run_source(source, "cJSON.c")
        self.assertIn("CVE-2026-67216", {f.symbol for f in run.findings})

    def test_cjson_non_recursive_or_parse_only_controls(self):
        safe="""int cJSON_Compare(node *a,node *b){ return a->type == b->type; }"""
        unrelated="""node *parse(const char *s){ return cJSON_Parse(s); }"""
        self.assertEqual((), self.run_source(safe, "cJSON.c").findings)
        self.assertEqual((), self.run_source(unrelated, "cJSON.c").findings)

    def test_curl_recursive_owned_mime_cleanup(self):
        source="""void cleanup_part_content(part *p){ p->freefunc(p->arg); } void mime_subparts_free(void *p){ curl_mime_free(p); } void curl_mime_free(mime *m){ while(m->firstpart){ part=m->firstpart; Curl_mime_cleanpart(part); } } void Curl_mime_set_subparts(part *p,mime *m,int take_ownership){ p->freefunc=take_ownership?mime_subparts_free:other; }"""
        self.assertIn("CVE-2026-92391", {f.symbol for f in self.run_source(source, "mime.c").findings})
        bounded=source.replace("void mime_subparts_free(void *p){ curl_mime_free(p); }", "void mime_subparts_free(void *p,int depth){ if(depth > MAX_MIME_DEPTH) return; curl_mime_free(p); }")
        self.assertNotIn("CVE-2026-92391", {f.symbol for f in self.run_source(bounded, "mime.c").findings})

    def test_cjson_array_pointer_cve_2025_57052_vulnerable_and_fixed_shapes(self):
        vulnerable = """static cJSON_bool decode_array_index_from_pointer(const unsigned char * const pointer, size_t * const index) {
            size_t parsed_index = 0;
            size_t position = 0;
            for (position = 0; (pointer[position] >= '0') && (pointer[0] <= '9'); position++) {
                parsed_index = (10 * parsed_index) + (size_t)(pointer[position] - '0');
            }
            if ((pointer[position] != '\0') && (pointer[position] != '/')) return 0;
            *index = parsed_index;
            return 1;
        }"""
        fixed = vulnerable.replace("pointer[0] <= '9'", "pointer[position] <= '9'")
        unrelated = """static void other(const unsigned char *pointer) {
            if (pointer[0] <= '9') consume(pointer);
        }"""
        vulnerable_findings = {f.symbol for f in self.run_source(vulnerable, "cJSON_Utils.c").findings}
        self.assertIn("CVE-2025-57052", vulnerable_findings)
        self.assertNotIn("CVE-2025-57052", {f.symbol for f in self.run_source(fixed, "cJSON_Utils.c").findings})
        self.assertNotIn("CVE-2025-57052", {f.symbol for f in self.run_source(unrelated, "cJSON_Utils.c").findings})

    def test_curl_proxy_credentials_null_clear_vulnerable_and_fixed_shapes(self):
        vulnerable = """CURLcode setopt_cptr_proxy(Curl_easy *data, CURLoption option, va_list param) {
            case CURLOPT_PROXYUSERPWD: {
                if (!result && u) {
                    Curl_safefree(data->set.str[STRING_PROXYUSERNAME]);
                    result = Curl_urldecode(u, 0, &data->set.str[STRING_PROXYUSERNAME], NULL, REJECT_ZERO);
                }
                if (!result && p) {
                    Curl_safefree(data->set.str[STRING_PROXYPASSWORD]);
                    result = Curl_urldecode(p, 0, &data->set.str[STRING_PROXYPASSWORD], NULL, REJECT_ZERO);
                }
                break;
            }
            case CURLOPT_PROXYUSERNAME:
                break;
        }"""
        fixed = """CURLcode setopt_cptr_proxy(Curl_easy *data, CURLoption option, va_list param) {
            case CURLOPT_PROXYUSERPWD: {
                if (!result) {
                    Curl_safefree(data->set.str[STRING_PROXYUSERNAME]);
                    Curl_safefree(data->set.str[STRING_PROXYPASSWORD]);
                    if (u)
                        result = Curl_urldecode(u, 0, &data->set.str[STRING_PROXYUSERNAME], NULL, REJECT_ZERO);
                }
                if (!result && p)
                    result = Curl_urldecode(p, 0, &data->set.str[STRING_PROXYPASSWORD], NULL, REJECT_ZERO);
                break;
            }
            case CURLOPT_PROXYUSERNAME:
                break;
        }"""
        self.assertIn("CVE-2026-9079", {f.symbol for f in self.run_source(vulnerable, "setopt.c").findings})
        self.assertNotIn("CVE-2026-9079", {f.symbol for f in self.run_source(fixed, "setopt.c").findings})

    def test_libpng_affected_and_fixed_version_markers(self):
        affected='#define PNG_LIBPNG_VER_STRING "1.6.55"\n'
        fixed='#define PNG_LIBPNG_VER_STRING "1.6.59"\n'
        self.assertIn("CVE-2026-46675", {f.symbol for f in self.run_source(affected, "pnglibconf.h").findings})
        self.assertEqual((), self.run_source(fixed, "pnglibconf.h").findings)

    def test_libpng_sequence_requires_end_without_row_read(self):
        bad="void decode(png_structp p,png_infop i){ png_read_info(p,i); png_read_end(p,i); }"
        safe="void decode(png_structp p,png_infop i){ png_read_info(p,i); png_read_row(p,row,0); png_read_end(p,i); }"
        self.assertIn("CVE-2026-46675", {f.symbol for f in self.run_source(bad, "decoder.c").findings})
        self.assertEqual((), self.run_source(safe, "decoder.c").findings)

    def test_libpng_neon_palette_cve_2026_33636_exact_upstream_pair(self):
        vulnerable = read_pinned_git_blob(
            "tests/fixtures/data_sensitive/cve_2026_33636/libpng-1.6.55-palette_neon_intrinsics.c")
        fixed = read_pinned_git_blob(
            "tests/fixtures/data_sensitive/cve_2026_33636/libpng-1.6.56-palette_neon_intrinsics.c")

        self.assertEqual("3068e9b6e62be16bee2a8f1ff8271a02f32be97f", git_blob_sha1(vulnerable))
        self.assertEqual("0967ea1aebd718907fda1e767957deeddbe676b3", git_blob_sha1(fixed))
        self.assertEqual("d58734a03a91df0f2c11e3558354281d7613888d85c83887586560a270bffa41",
                         hashlib.sha256(vulnerable).hexdigest())
        self.assertEqual("a844760f611829df29ca583f1b08832cac1440c74a2a22b35bc35a464ddf6b5e",
                         hashlib.sha256(fixed).hexdigest())

        old_run = self.run_source(vulnerable.decode(), "arm/palette_neon_intrinsics.c")
        new_run = self.run_source(fixed.decode(), "arm/palette_neon_intrinsics.c")
        old = [f for f in old_run.findings if f.symbol == "CVE-2026-33636"]
        self.assertEqual(2, len(old))
        self.assertEqual({"CWE-119"}, {finding.candidate_cwe for finding in old})
        self.assertEqual(2, len({finding.line for finding in old}))
        self.assertEqual({hashlib.sha256(vulnerable).hexdigest()},
                         {finding.source_sha256 for finding in old})
        self.assertEqual([], [f for f in new_run.findings if f.symbol == "CVE-2026-33636"])

        loop_only = vulnerable.decode().replace(
            "i < row_width; i += pixels_per_chunk",
            "i + pixels_per_chunk <= row_width; i += pixels_per_chunk",
        )
        pointer_only = vulnerable.decode().replace(
            "*ssp = *ssp - i;",
            "*ddp = *ddp + (pixels_per_chunk * 4 - 1);\n   *ssp = *ssp - i;",
            1,
        ).replace(
            "*ssp = *ssp - i;",
            "*ddp = *ddp + (pixels_per_chunk * 3 - 1);\n   *ssp = *ssp - i;",
            1,
        )
        for incomplete_fix in (loop_only, pointer_only):
            remaining = [f for f in self.run_source(
                incomplete_fix, "arm/palette_neon_intrinsics.c").findings
                if f.symbol == "CVE-2026-33636"
            ]
            self.assertEqual(2, len(remaining))

        unrelated = """void png_do_expand_palette_rgba8_neon(void) { for (i=0; i<row_width; i++) scalar_copy(); }
        void png_do_expand_palette_rgb8_neon(void) { return; }"""
        self.assertNotIn("CVE-2026-33636", {f.symbol for f in self.run_source(unrelated, "other.c").findings})

    def test_cjson_json_patch_unbounded_recursion_candidate(self):
        vulnerable = """static int apply_patch(node *object,node *patch){ node *value=cJSON_Duplicate(patch,1); if(!value)return 0; cleanup: if(value)cJSON_Delete(value); return 0; }
        int cJSONUtils_ApplyPatches(node *object,node *patches){ while(patches){ apply_patch(object,patches); patches=patches->next; } return 0; }"""
        fixed = """static int apply_patch(node *object,node *patch,int depth){ if(depth >= MAX_PATCH_DEPTH)return 0; node *value=cJSON_Duplicate(patch,1); if(!value)return 0; cleanup: if(value)cJSON_Delete(value); return 0; }
        int cJSONUtils_ApplyPatches(node *object,node *patches){ while(patches){ apply_patch(object,patches,0); patches=patches->next; } return 0; }"""
        self.assertIn("CVE-2026-67215", {f.symbol for f in self.run_source(vulnerable, "cJSON_Utils.c").findings})
        self.assertNotIn("CVE-2026-67215", {f.symbol for f in self.run_source(fixed, "cJSON_Utils.c").findings})

    def test_pasteboard_disclosed_cves_and_guarded_controls(self):
        vulnerable = """void AddPasteboardChangedObserver(Observer *observer) {
            if (!observer) return;
            auto userId = GetUserId();
            auto it = observerMap_.find(userId);
            std::shared_ptr<std::set<Observer *>> observers;
            if (it != observerMap_.end()) observers = it->second;
            else { observers = std::make_shared<std::set<Observer *>>(); observerMap_.insert({userId, observers}); }
            observers->insert(observer); // exact repeated-growth statement; std::set only deduplicates identical handles
        }
        PasteboardServiceStub::PasteboardServiceStub(){ memberFuncMap_[GET_PASTE_DATA] = &PasteboardServiceStub::OnGetPasteData; }
        int OnRemoteRequest(int code){ auto it=memberFuncMap_.find(code); if(it!=memberFuncMap_.end()) return (this->*it->second)(); return 0; }
        int OnGetPasteData(){ GetPasteData(); reply.WriteParcelable(data); return 0; }"""
        fixed = """void AddPasteboardChangedObserver(Observer *observer) {
            int pid = GetCallingPid();
            auto it = observerMap_.find(pid);
            std::shared_ptr<std::set<Observer *>> observers;
            if (it != observerMap_.end()) observers = it->second;
            else { observers = std::make_shared<std::set<Observer *>>(); observerMap_.insert({pid, observers}); }
            if (observers->size() >= MAX_OBSERVERS_PER_PID) return;
            observers->insert(observer);
        }
        PasteboardServiceStub::PasteboardServiceStub(){ memberFuncMap_[GET_PASTE_DATA] = &PasteboardServiceStub::OnGetPasteData; }
        int OnRemoteRequest(int code){ auto it=memberFuncMap_.find(code); if(it!=memberFuncMap_.end()) return (this->*it->second)(); return 0; }
        int OnGetPasteData(){ CheckPermission(); GetPasteData(); reply.WriteParcelable(data); return 0; }"""
        vulnerable_run = self.run_source(vulnerable, "pasteboard_service.cpp")
        findings = {f.symbol for f in vulnerable_run.findings}
        self.assertIn("CVE-2025-25212", findings)
        self.assertIn("CVE-2025-27247", findings)
        observer_finding = next(f for f in vulnerable_run.findings if f.symbol == "CVE-2025-25212")
        expected_line = vulnerable[:vulnerable.index("observers->insert(observer)")].count("\n") + 1
        self.assertEqual(expected_line, observer_finding.line)
        self.assertEqual((), self.run_source(fixed, "pasteboard_service.cpp").findings)

    def test_pasteboard_quota_helper_and_unrelated_growth_controls(self):
        helper_quota = """bool IsObserverQuotaExceeded(ObserverSet *observers) {
            if (observers->size() >= MAX_OBSERVERS_PER_PID) return true;
            return false;
        }
        void AddPasteboardChangedObserver(Observer *observer) {
            auto it = observerMap_.find(GetUserId());
            auto observers = it->second;
            if (IsObserverQuotaExceeded(observers)) return;
            observers->insert(observer);
        }"""
        ignored_helper = """bool IsObserverQuotaExceeded(ObserverSet *observers) {
            if (observers->size() >= MAX_OBSERVERS_PER_PID) return true;
            return false;
        }
        void AddPasteboardChangedObserver(Observer *observer) {
            auto it = observerMap_.find(GetUserId());
            auto observers = it->second;
            IsObserverQuotaExceeded(observers);
            observers->insert(observer);
        }"""
        nonblocking_guard = """void AddPasteboardChangedObserver(Observer *observer) {
            auto it = observerMap_.find(GetUserId());
            auto observers = it->second;
            if (observers->size() >= MAX_OBSERVERS_PER_PID) { LogQuota(); }
            observers->insert(observer);
        }"""
        unrelated = """void AddHistoryRecord(Record *record) {
            historyMap_.find(GetUserId());
            historyMap_.insert(record);
        }"""
        self.assertNotIn("CVE-2025-25212", {f.symbol for f in self.run_source(helper_quota, "pasteboard_service.cpp").findings})
        self.assertIn("CVE-2025-25212", {f.symbol for f in self.run_source(ignored_helper, "pasteboard_service.cpp").findings})
        self.assertIn("CVE-2025-25212", {f.symbol for f in self.run_source(nonblocking_guard, "pasteboard_service.cpp").findings})
        self.assertNotIn("CVE-2025-25212", {f.symbol for f in self.run_source(unrelated, "other.cpp").findings})

    def test_pasteboard_partial_parse_keeps_bound_observer_candidate_blocked(self):
        source = """void AddPasteboardChangedObserver(Observer *observer) {
            auto it = observerMap_.find(GetUserId());
            auto observers = it->second;
            observers->insert(observer);
        }"""
        run = self.run_source(source, "services/core/src/pasteboard_service.cpp", parse_status="partial")
        finding = next(f for f in run.findings if f.symbol == "CVE-2025-25212")
        self.assertEqual("blocked", run.status)
        self.assertEqual(4, finding.line)

    def test_partial_parse_retains_lexical_candidate_but_blocks_coverage(self):
        source="void f(png_structp p,png_infop i){png_read_info(p,i);png_read_end(p,i);}"
        run=self.run_source(source, parse_status="partial")
        self.assertEqual("blocked", run.status)
        self.assertIn("CVE-2026-46675", {f.symbol for f in run.findings})
        self.assertTrue(any("remaining coverage is unknown" in item for item in run.limitations))
        self.assertNotIn("ohscanner.known_disclosed_cves", default_detector_ids())
        self.assertFalse(catalog_metadata()["ohscanner.known_disclosed_cves"]["default_enabled"])
        self.assertEqual("ohscanner.known_disclosed_cves", build_registry(("ohscanner.known_disclosed_cves",)).detectors()[0].detector_id)

    def test_webview_flowbuffer_cve_vulnerable_fixed_and_unrelated_shapes(self):
        vulnerable = """char *FlowbufStrAtIndex(void *mem, int i, int *argIndex, size_t *strLen) {
            char *header = (char *)mem;
            size_t offset = header[i * INDEX_SIZE];
            *strLen = *(header + (i * INDEX_SIZE) + 1) - 1;
            *argIndex = header[i * INDEX_SIZE + 2];
            return (char *)mem + HEADER_SIZE + offset;
        }
        int ProcessNativeProxyResultNewFlowbuf(Args *args, int flowbufSize, int flowbufIndex, int argIndex) {
            size_t argsSize = args->GetSize();
            std::vector<std::vector<uint8_t>> dataList(argsSize +
                static_cast<size_t>(flowbufSize));
            size_t curIndex = 0;
            char *flowbufStr = FlowbufStrAtIndex(nullptr, flowbufIndex, &argIndex, &strLen);
            while (argIndex == curIndex) {
                std::string value(flowbufStr, strLen);
                dataList[curIndex] = std::vector<uint8_t>(value.begin(), value.end());
            }
            return 0;
        }"""
        fixed = vulnerable.replace(
            "*strLen = *(header + (i * INDEX_SIZE) + 1) - 1;",
            "*strLen = *(header + (i * INDEX_SIZE) + 1) - 1;\n"
            "            if ((offset + *strLen) > MAX_FLOWBUF_DATA_SIZE) return nullptr;")
        fixed = fixed.replace(
            "size_t curIndex = 0;",
            "size_t dataListSize = argsSize + static_cast<size_t>(flowbufSize);\n"
            "            size_t curIndex = 0;")
        fixed = fixed.replace("while (argIndex == curIndex)",
                              "while (curIndex < dataListSize && argIndex == curIndex)")
        unrelated = vulnerable.replace("FlowbufStrAtIndex", "UnrelatedStringAtIndex")
        partial_fix = vulnerable.replace(
            "while (argIndex == curIndex)",
            "while (curIndex < dataListSize && argIndex == curIndex)").replace(
            "size_t curIndex = 0;",
            "size_t dataListSize = argsSize + static_cast<size_t>(flowbufSize);\n"
            "            size_t curIndex = 0;")
        findings = {f.symbol for f in self.run_source(vulnerable, "nweb_handler_delegate.cc").findings}
        self.assertIn("CVE-2026-27648", findings)
        candidate = next(f for f in self.run_source(vulnerable, "nweb_handler_delegate.cc").findings
                         if f.symbol == "CVE-2026-27648")
        self.assertIn("unchecked shared-memory offset/length", candidate.message)
        self.assertIn("without a destination-size loop bound", candidate.message)
        self.assertNotIn("CVE-2026-27648", {f.symbol for f in self.run_source(fixed, "nweb_handler_delegate.cc").findings})
        self.assertIn("CVE-2026-27648", {f.symbol for f in self.run_source(partial_fix, "nweb_handler_delegate.cc").findings})
        self.assertNotIn("CVE-2026-27648", {f.symbol for f in self.run_source(unrelated, "nweb_handler_delegate.cc").findings})

    def test_webview_flowbuffer_candidate_survives_partial_parse(self):
        source = """char *FlowbufStrAtIndex(void *mem, int i, int *argIndex, size_t *strLen) {
            char *header = (char *)mem; size_t offset = header[i * INDEX_SIZE];
            *strLen = *(header + (i * INDEX_SIZE) + 1) - 1;
            return (char *)mem + HEADER_SIZE + offset;
        }
        int ProcessNativeProxyResultNewFlowbuf(Args *args, int flowbufSize, int argIndex) {
            size_t argsSize = args->GetSize();
            std::vector<std::vector<uint8_t>> dataList(argsSize + static_cast<size_t>(flowbufSize));
            size_t curIndex = 0; char *value = FlowbufStrAtIndex(nullptr, 0, &argIndex, &strLen);
            while (argIndex == curIndex) { dataList[curIndex] = {}; }
            return 0;
        }"""
        run = self.run_source(source, "nweb_handler_delegate.cc", parse_status="partial")
        self.assertEqual("blocked", run.status)
        self.assertIn("CVE-2026-27648", {f.symbol for f in run.findings})
        finding = next(f for f in run.findings if f.symbol == "CVE-2026-27648")
        self.assertEqual("CWE-787", finding.candidate_cwe)
        self.assertEqual("missing", next(o.status for o in finding.evidence_obligations if o.kind == "product_build"))

    def test_all_matches_remain_candidate_obligated(self):
        source="void f(png_structp p,png_infop i){png_read_info(p,i);png_read_end(p,i);}"
        run=self.run_source(source)
        self.assertTrue(run.findings)
        for finding in run.findings:
            self.assertEqual("partial", finding.identity_quality)
            self.assertIn("reachability", finding.message.lower())
            self.assertTrue(finding.evidence_obligations)

if __name__ == "__main__": unittest.main()
