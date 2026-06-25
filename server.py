#!/usr/bin/env python3
"""
ISO 8583 (card payments) Bridge MCP — CSOAI Layer-0 legacy-bridge family.
Parse ISO 8583 card/ATM/POS messages (MTI + processing), map, govern (PCI-DSS / scheme rules).
Sibling of cobol-bridge-mcp.
Tools: parse_iso8583 · map_to_modern · govern_card
"""
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import re

mcp = FastMCP("ISO 8583 Bridge", instructions="Bridge ISO 8583 card-payment messages to ONE OS — parse, map, govern (PCI-DSS).")

# ── SIGIL: every governed action → one signed hash-chained hop (SIGIL_LOG unifies all layers) ──
import hashlib as _hl, time as _t, json as _j, os as _os
_SIGIL_LOG = _os.environ.get("SIGIL_LOG", _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "bridge_sigil.log"))
def _sigil(op, body):
    try:
        prev = ""
        if _os.path.exists(_SIGIL_LOG):
            with open(_SIGIL_LOG) as f:
                ls = f.readlines()
                if ls: prev = _j.loads(ls[-1]).get("digest", "")
        ts = int(_t.time()); dg = _hl.sha256(f"{op}|{ts}|{prev[:8]}|{body}".encode()).hexdigest()[:16]
        _os.makedirs(_os.path.dirname(_SIGIL_LOG), exist_ok=True)
        with open(_SIGIL_LOG, "a") as f: f.write(_j.dumps({"ts": ts, "op": op, "body": body, "prev_digest": prev, "digest": dg}) + "\n")
        return dg
    except Exception: return ""

MTI = {
    "0100": "Authorization Request", "0110": "Authorization Response",
    "0200": "Financial Request", "0210": "Financial Response",
    "0400": "Reversal Request", "0410": "Reversal Response",
    "0420": "Reversal Advice", "0800": "Network Management Request",
    "0810": "Network Management Response",
}


class ISO8583Parsed(BaseModel):
    mti: Optional[str] = None
    message_class: Optional[str] = None
    description: str = "ISO 8583 message"
    is_financial: bool = False
    is_reversal: bool = False


class Governance(BaseModel):
    risk_flags: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    attestable: bool = True
    note: str = ""


def _mti(message: str) -> Optional[str]:
    m = re.match(r"\s*(\d{4})", message or "")
    return m.group(1) if m else None


@mcp.tool()
def parse_iso8583(message: str) -> ISO8583Parsed:
    """Parse the ISO 8583 MTI (message type indicator) and classify the transaction."""
    mti = _mti(message)
    if not mti:
        return ISO8583Parsed(description="unrecognised — no 4-digit MTI")
    cls = {"0": "Authorization", "1": "Authorization", "2": "Financial", "4": "Reversal", "8": "Network mgmt"}.get(mti[1] if len(mti) > 1 else mti[0], "Other")
    return ISO8583Parsed(
        mti=mti, message_class=cls, description=MTI.get(mti, "ISO 8583 " + cls),
        is_financial=mti.startswith("02"), is_reversal=mti.startswith("04"),
    )


@mcp.tool()
def map_to_modern(message: str) -> Dict[str, Any]:
    """Map an ISO 8583 message to a modern card-transaction event for ONE OS."""
    p = parse_iso8583(message)
    return {"source": "ISO 8583", "mti": p.mti, "type": p.description,
            "kind": "financial" if p.is_financial else ("reversal" if p.is_reversal else "auth/network"),
            "target": "modern card-transaction event"}


@mcp.tool()
def govern_card(message: str) -> Governance:
    """Governance: card-data + scheme surface — PCI-DSS, PAN handling (attestable for CSOAI)."""
    _sigil("G", "iso8583|govern_card")
    p = parse_iso8583(message)
    flags = ["Never log/store full PAN or track data — PCI-DSS Req 3 (mask/tokenise)"]
    if p.is_financial:
        flags.append("Financial message — strong customer authentication (PSD2 SCA) + clearing controls")
    if p.is_reversal:
        flags.append("Reversal — match to original + dispute/chargeback governance")
    return Governance(risk_flags=flags,
                      frameworks=["PCI-DSS", "EMVCo", "Visa/Mastercard scheme rules", "PSD2 SCA", "DORA"],
                      note="CSOAI governs the bridge: card-transaction lineage attestable (PAN never stored).")


def main():
    mcp.run()


if __name__ == "__main__":
    main()
