import unittest
from unittest.mock import patch
from scripts import rp23ogs_uac_msi_event_probe as p

SAMPLE="""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System><Provider Name='MsiInstaller'/><EventID>11707</EventID>
<TimeCreated SystemTime='2026-11-22T15:24:00.000Z'/></System>
<EventData><Data Name='User'>DO-NOT-ECHO</Data></EventData></Event>"""

class EventProbeTests(unittest.TestCase):
    def test_target(self):
        p.ensure_target(p.HOST,'Windows','AMD64')
        for a,b,c in [('NOTERI','Windows','AMD64'),(p.HOST,'Linux','AMD64'),(p.HOST,'Windows','ARM64')]:
            with self.assertRaisesRegex(p.ProbeBlocked,'HOST_OR_PLATFORM_DENIED'):
                p.ensure_target(a,b,c)

    def test_xml_only_system(self):
        row=p.parse_system_xml(SAMPLE)
        self.assertEqual(row['event_id'],11707)
        self.assertEqual(row['utc'],'2026-11-22T15:24:00+00:00')
        self.assertNotIn('DO-NOT-ECHO',str(row))

    def test_wrong_provider_fails(self):
        with self.assertRaisesRegex(p.ProbeBlocked,'EVENT_XML_INVALID'):
            p.parse_system_xml(SAMPLE.replace('MsiInstaller','FakeProvider'))

    def test_invalid_xml_fails(self):
        with self.assertRaisesRegex(p.ProbeBlocked,'EVENT_XML_INVALID'):
            p.parse_system_xml('<Event>')

    def test_events_do_not_claim_install_success(self):
        r=p.make_result([p.parse_system_xml(SAMPLE)])
        self.assertEqual(r['result'],'MSI_INSTALLER_EVENTS_IN_WINDOW')
        self.assertFalse(r['installation_executed'])
        self.assertEqual(r['uac_prompt_status'],'NOT_OBSERVED')

    def test_zero_events_not_uac_proof(self):
        r=p.make_result([])
        self.assertEqual(r['result'],'NO_MSI_INSTALLER_EVENTS_IN_WINDOW')
        self.assertEqual(r['uac_prompt_status'],'NOT_OBSERVED')

    def test_main_denies_other_host(self):
        with patch.object(p.socket,'gethostname',return_value='OTHER'):
            self.assertEqual(p.main(),20)

if __name__=='__main__':
    unittest.main()
