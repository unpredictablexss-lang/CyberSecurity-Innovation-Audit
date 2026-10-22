import unittest
from src.workbench.smart_audit import source_review_dimensions
class Ops:
 def __init__(self,result): self.value=result
 def result(self,_): return self.value
class SourceDimensionsTest(unittest.TestCase):
 def test_bound_source_claim_is_not_runtime_reproduction(self):
  for repository in ['contacts','other-repository']:
   job={'id':'job','report_sha256':'report'}; candidate={'id':'candidate','source_sha256':'source'}; report={'commit':'commit','repository':repository}
   result={'binding':{'job_id':'job','candidate_id':'candidate','report_sha256':'report','source_sha256':'source','commit':'commit'},'structured_answer_validation':'accepted','citation_integrity':{'quote_presence':'verified_for_all_citations'},'agent_assessment':{'supported_claims':[{'claim':'source claim','citations':[{}]}],'unknowns':['entry unresolved'],'obligation_reviews':[]}}
   operations=[{'id':'op','candidate_id':'candidate','status':'completed_with_limitations','result_sha256':'hash'}]
   row=source_review_dimensions(Ops(result),job,report,candidate,operations,'further_validation')
   self.assertEqual(row['source_confidence_label'],'已有源码支持（待补证）')
   self.assertEqual(row['source_evidence_gaps'],['entry unresolved'])
   self.assertEqual(row['reproduction_status'],'not_recorded')
   result['binding']['commit']='different'
   self.assertEqual(source_review_dimensions(Ops(result),job,report,candidate,operations,'further_validation')['source_supported_claims'],[])
 def test_verified_path_source_chain_can_be_high_while_obligations_stay_open(self):
  job={'id':'job','report_sha256':'report'}; candidate={'id':'candidate','source_sha256':'source','file':'src/candidate.cpp','line':100,'rule_id':'cpp-path-traversal'}; report={'commit':'commit'}
  citation=lambda file,start,end,quote:{'evidence_id':file+str(start),'file':file,'line_start':start,'line_end':end,'quote':quote}
  result={'binding':{'job_id':'job','candidate_id':'candidate','report_sha256':'report','source_sha256':'source','commit':'commit'},'structured_answer_validation':'accepted','citation_integrity':{'quote_presence':'verified_for_all_citations'},'agent_assessment':{'supported_claims':[
   {'claim':'字段取值经过检查','citations':[citation('src/candidate.cpp',80,110,'read field')]},
   {'claim':'将路径拼接','citations':[citation('src/candidate.cpp',95,105,'srcFilePath = root + name')]},
   {'claim':'sink','citations':[citation('src/file.cpp',20,22,'unlink(path.c_str())')]}], 'unknowns':['caller authorization unresolved'],'obligation_reviews':[{'disposition':'unresolved'}]}}
  operations=[{'id':'op','candidate_id':'candidate','status':'completed_with_limitations','result_sha256':'hash'}]
  row=source_review_dimensions(Ops(result),job,report,candidate,operations,'further_validation')
  self.assertEqual(row['source_chain_confidence'],'high')
  self.assertEqual(row['source_confidence_label'],'高可信源码链（漏洞仍待验证）')
  self.assertEqual(row['reproduction_status'],'not_recorded')
  result['citation_integrity']['quote_presence']='unverified'
  row=source_review_dimensions(Ops(result),job,report,candidate,operations,'further_validation')
  self.assertIsNone(row['source_chain_confidence'])

 def test_high_source_confidence_does_not_confirm_runtime(self):
  row=source_review_dimensions(Ops({}),{}, {}, {}, [],'high_confidence_candidate')
  self.assertEqual(row['source_confidence_label'],'高可信源码风险')
  self.assertEqual(row['reproduction_status'],'not_recorded')
if __name__=='__main__': unittest.main()
