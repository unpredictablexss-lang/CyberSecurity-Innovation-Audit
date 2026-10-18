from __future__ import annotations
import hashlib
import unittest
from pathlib import Path
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.catalog import build_registry, catalog_metadata, default_detector_ids
from src.ohscanner.detectors.known_cves import KnownDisclosedCveDetector
from src.ohscanner.fixture import snapshot_digest

class KnownDisclosedCveTests(unittest.TestCase):
    def run_source(self, source, path="sample.c", parse_status="complete"):
        unit=SourceUnit(path=path, language="c", text=source, sha256=hashlib.sha256(source.encode()).hexdigest(), parse_status=parse_status)
        request=ScanRequest(request_id="test:known-cves", repository="fixture/known-cves", commit="a"*40, snapshot_sha256=snapshot_digest((unit,)), target_id="current-component:fixture/known-cves", profile_id="fixture-no-build", provenance="fixture")
        run=KnownDisclosedCveDetector().detect(ScanContext(request=request, units=(unit,)), (unit,))
        return run

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
        fixture = Path(__file__).parent / "../fixtures/data_sensitive/cve_2026_33636"
        vulnerable_path = (fixture / "libpng-1.6.55-palette_neon_intrinsics.c").resolve()
        fixed_path = (fixture / "libpng-1.6.56-palette_neon_intrinsics.c").resolve()
        vulnerable = vulnerable_path.read_bytes()
        fixed = fixed_path.read_bytes()

        def git_blob_sha1(blob):
            return hashlib.sha1(b"blob " + str(len(blob)).encode() + b"\0" + blob).hexdigest()

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
        vulnerable = """void AddPasteboardChangedObserver(Observer *observer){ if(!observer)return; observers->insert(observer); }
        PasteboardServiceStub::PasteboardServiceStub(){ memberFuncMap_[GET_PASTE_DATA] = &PasteboardServiceStub::OnGetPasteData; }
        int OnRemoteRequest(int code){ auto it=memberFuncMap_.find(code); if(it!=memberFuncMap_.end()) return (this->*it->second)(); return 0; }
        int OnGetPasteData(){ GetPasteData(); reply.WriteParcelable(data); return 0; }"""
        fixed = """void AddPasteboardChangedObserver(Observer *observer){ int pid=GetCallingPid(); if(observers->size() >= MAX_OBSERVERS_PER_PID)return; observers->insert(observer); }
        PasteboardServiceStub::PasteboardServiceStub(){ memberFuncMap_[GET_PASTE_DATA] = &PasteboardServiceStub::OnGetPasteData; }
        int OnRemoteRequest(int code){ auto it=memberFuncMap_.find(code); if(it!=memberFuncMap_.end()) return (this->*it->second)(); return 0; }
        int OnGetPasteData(){ CheckPermission(); GetPasteData(); reply.WriteParcelable(data); return 0; }"""
        findings = {f.symbol for f in self.run_source(vulnerable, "pasteboard_service.cpp").findings}
        self.assertIn("CVE-2025-25212", findings)
        self.assertIn("CVE-2025-27247", findings)
        self.assertEqual((), self.run_source(fixed, "pasteboard_service.cpp").findings)

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
