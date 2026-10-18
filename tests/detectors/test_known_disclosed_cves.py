from __future__ import annotations
import hashlib
import unittest
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.catalog import build_registry, default_detector_ids
from src.ohscanner.detectors.known_cves import KnownDisclosedCveDetector
from src.ohscanner.fixture import snapshot_digest

class KnownDisclosedCveTests(unittest.TestCase):
    def run_source(self, source, path="sample.c", parse_status="complete"):
        unit=SourceUnit(path=path, language="c", text=source, sha256=hashlib.sha256(source.encode()).hexdigest(), parse_status=parse_status)
        request=ScanRequest(request_id="test:known-cves", repository="fixture/known-cves", commit="a"*40, snapshot_sha256=snapshot_digest((unit,)), target_id="current-component:fixture/known-cves", profile_id="fixture-no-build", provenance="fixture")
        run=KnownDisclosedCveDetector().detect(ScanContext(request=request, units=(unit,)), (unit,))
        return run

    def test_libtiff_vulnerable_and_fixed_shapes(self):
        bad="int f(TIFFRGBAImage *img,uint32_t *raster,uint32_t rwidth,uint32_t rheight){ return TIFFRGBAImageGet(&img,raster + (rheight - img->height) * rwidth,rwidth,img->height); }".replace("img->height", "img.height")
        fixed="int f(TIFFRGBAImage *img,uint32_t *raster,uint32_t rwidth,uint32_t rheight){ if (rwidth < img.width || rheight < img.height) return 0; return TIFFRGBAImageGet(&img,raster,rwidth,rheight); }"
        self.assertIn("CVE-2025-9900", {f.symbol for f in self.run_source(bad).findings})
        self.assertEqual((), self.run_source(fixed).findings)

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

    def test_partial_parse_retains_lexical_candidate_but_blocks_coverage(self):
        source="void f(png_structp p,png_infop i){png_read_info(p,i);png_read_end(p,i);}"
        run=self.run_source(source, parse_status="partial")
        self.assertEqual("blocked", run.status)
        self.assertIn("CVE-2026-46675", {f.symbol for f in run.findings})
        self.assertTrue(any("remaining coverage is unknown" in item for item in run.limitations))
        self.assertIn("ohscanner.known_disclosed_cves", default_detector_ids())
        self.assertEqual("ohscanner.known_disclosed_cves", build_registry(("ohscanner.known_disclosed_cves",)).detectors()[0].detector_id)

    def test_all_matches_remain_candidate_obligated(self):
        source="void f(png_structp p,png_infop i){png_read_info(p,i);png_read_end(p,i);}"
        run=self.run_source(source)
        self.assertTrue(run.findings)
        for finding in run.findings:
            self.assertEqual("partial", finding.identity_quality)
            self.assertIn("reachability", finding.message.lower())
            self.assertTrue(finding.evidence_obligations)

if __name__ == "__main__": unittest.main()
