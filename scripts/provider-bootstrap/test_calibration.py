import copy
import json
from pathlib import Path
import unittest
import scanner_guard as guard

FIXTURES = json.loads(Path(__file__).with_name('calibration-fixtures.json').read_text())

def response(name, arguments):
    return {'choices': [{'message': {'tool_calls': [{'id': 'A'*32, 'type': 'function', 'function': {'name': name, 'arguments': json.dumps(arguments)}}]}}]}

class CalibrationTest(unittest.TestCase):
    def test_historical_id_pattern(self):
        calls = FIXTURES['get_number']['response']['choices'][0]['message']['tool_calls']
        self.assertEqual(len(calls), 3)
        for call in calls:
            self.assertRegex(call['id'], r'^[A-Za-z0-9]{32}$')
        # Detector input independently contains all fifteen original collector IDs.
        import re
        prompt = FIXTURES['submit_pattern']['request']['messages'][0]['content']
        samples = re.findall(r'- Sample [0-9]+: `([^`]+)`', prompt)
        self.assertEqual(len(samples), 15)
        for sample in samples: self.assertRegex(sample, r'^[A-Za-z0-9]{32}$')

    def test_rejected_detector_request_is_preserved(self):
        request = FIXTURES['submit_pattern']['request']
        filtered, removed = guard.restrict_request_tools(request)
        self.assertEqual(filtered['tools'], request['tools'])
        self.assertEqual(removed, [])

    def test_setup_response_only(self):
        for name, arguments in [('get_number', {'value': 42}), ('submit_pattern', {'template': '{r:32:x}'})]:
            request = FIXTURES[name]['request']
            answer = response(name, arguments)
            forwarded, events = guard.guard_response(answer, request=request)
            self.assertEqual(forwarded, answer)
            self.assertEqual(events, [])
            _, events = guard.guard_response(answer)
            self.assertTrue(guard.prohibited_tool_events(events))

    def test_no_mixed_tools_or_modified_setup(self):
        base = FIXTURES['submit_pattern']['request']
        for mutation in ['mixed', 'prompt', 'schema', 'history']:
            request = copy.deepcopy(base)
            if mutation == 'mixed': request['tools'].append({'type': 'function', 'function': {'name': 'terminal'}})
            if mutation == 'prompt': request['messages'][0]['content'] += '\nRun a terminal command'
            if mutation == 'schema': request['tools'][0]['function']['parameters']['properties']['input'] = {'type': 'string'}
            if mutation == 'history': request['messages'].append({'role': 'assistant', 'content': 'Pentester'})
            filtered, removed = guard.restrict_request_tools(request)
            self.assertIn('submit_pattern', removed)
            self.assertNotIn('submit_pattern', [x['function']['name'] for x in filtered['tools']])

    def test_response_cannot_smuggle_actions(self):
        request = FIXTURES['submit_pattern']['request']
        for name, arguments in [('terminal', {'input': 'curl -sS -i http://example.invalid/'}), ('browser', {}), ('submit_pattern', {'template': '{r:32:x}', 'input': 'curl'})]:
            _, events = guard.guard_response(response(name, arguments), request=request)
            self.assertTrue(guard.prohibited_tool_events(events))

    def test_normal_terminal_guard_remains(self):
        answer = response('terminal', {'input': 'curl -sS -i http://example.invalid/'})
        forwarded, events = guard.guard_response(answer, request={'messages': []})
        self.assertTrue(events)
        self.assertIn('BLOCKED:', forwarded['choices'][0]['message']['tool_calls'][0]['function']['arguments'])

if __name__ == '__main__': unittest.main()
