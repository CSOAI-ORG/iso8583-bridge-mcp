import sys,os
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server

def test_parse():
    p=server.parse_iso8583("0200 financial request"); assert p.mti=="0200"; assert p.is_financial
def test_govern():
    assert any("PCI" in f for f in server.govern_card("0100").frameworks)
