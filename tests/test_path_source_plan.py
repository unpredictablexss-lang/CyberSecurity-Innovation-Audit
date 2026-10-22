import json
import copy
import unittest
from src.workbench import agent

class PathSourcePlanTests(unittest.TestCase):
    def test_prioritizes_actual_sink_without_repository_specific_rules(self):
        for name in ('any/repo', 'openharmony/applications_contacts_data', 'other/project'):
            candidate={'repository':name,'rule_id':'ohcpp-path-traversal-source-to-file-sink-candidate-001','file':'src/file.cpp','line':2}
            before=copy.deepcopy(candidate)
            plan=agent._path_source_investigation_plan(candidate,{'text':'void run() {\n util.RemoveFile(path);\n}\n'})
            self.assertEqual(plan['priority_source_lookups'][0]['arguments'], {'symbol':'RemoveFile'})
            self.assertIn('already supplied',plan['steps'][0])
            self.assertIn('no vulnerability verdict',plan['steps'][-1])
            self.assertEqual(candidate,before)
    def test_unrelated_rules_have_no_path_plan(self):
        self.assertIsNone(agent._path_source_investigation_plan({'rule_id':'null-dereference'}, {'text':'int f() {}'}))
    def test_no_identifiable_call_remains_a_question(self):
        plan=agent._path_source_investigation_plan({'rule_id':'path-traversal','file':'src/a.cpp','line':1}, {'text':'// no call here'})
        self.assertEqual(plan['priority_source_lookups'],[])
        self.assertNotIn('assessment',plan)

class SameFileHelperCitationTests(unittest.TestCase):
    def test_explicit_range_can_cite_read_helper_lines_without_widening_initial_window(self):
        file='src/main.cpp'
        initial={file:{10:'void candidate() {',11:'  helper();',12:'}',30:'void helper() {',31:'  remove(path);',32:'}'}}
        limited=agent._restrict_source_lines_to_function(initial, {'file':file,'start_line':10,'end_line':12})
        self.assertNotIn(31,limited[file])
        explicit=agent._source_evidence_lines('read_fixed_source_range',{'file':file,'text':'30: void helper() {\n31:   remove(path);\n32: }'})
        value={'summary':'Source evidence only','assessment':'likely_true_positive','supported_claims':[{'claim':'The helper invokes remove(path).','obligation_indices':[0],'citations':[{'evidence_id':'ev-helper','file':file,'line_start':31,'line_end':31}]}],'obligation_reviews':[{'obligation_index':0,'disposition':'evidence_found','citations':[{'evidence_id':'ev-helper','file':file,'line_start':31,'line_end':31}]}],'unsupported_claims':[],'unknowns':['Product execution not tested'],'next_steps':['Human/runtime review']}
        result=agent._validate_final(json.dumps(value), {'ev-helper':['30: void helper() {\n31:   remove(path);\n32: }']}, [{'kind':'source_trace_review'}], [0], {'ev-helper':explicit})
        self.assertEqual(result['supported_claims'][0]['citations'][0]['quote'],'  remove(path);')
        value['supported_claims'][0]['citations'][0]['line_start']=29
        with self.assertRaises(ValueError):
            agent._validate_final(json.dumps(value), {'ev-helper':['source']}, [{'kind':'source_trace_review'}], [0], {'ev-helper':explicit})
        self.assertIn('Explicit fixed-source range reads',agent._INSTRUCTIONS)
if __name__=='__main__': unittest.main()