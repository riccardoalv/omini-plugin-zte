"""The device's answers: XML whose objects hold instances of name/value pairs.

```xml
<ajax_response_xml_root>
  <IF_ERRORSTR>SUCC</IF_ERRORSTR>
  <OBJ_DEVINFO_ID>
    <Instance><ParaName>_InstID</ParaName><ParaValue>IGD</ParaValue>
              <ParaName>ModelName</ParaName><ParaValue>F670L</ParaValue></Instance>
  </OBJ_DEVINFO_ID>
  <encode>KeyPassphrase</encode>   <!-- secret fields of the object before it -->
</ajax_response_xml_root>
```

An empty object (no instance) is an empty list. ``IF_ERRORSTR`` is ``SUCC``,
``SessionTimeout`` (signed out) or ``FAIL`` with the refused field in
``IF_ERRORPARAM``.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

Row = dict[str, str]


@dataclass
class Answer:
    objects: dict[str, list[Row]] = field(default_factory=dict)
    values: dict[str, str] = field(default_factory=dict)
    # Fields the device sent encrypted (secrets): never kept in clear.
    encoded: set[str] = field(default_factory=set)

    @property
    def status(self) -> str:
        return self.values.get("IF_ERRORSTR", "SUCC") or "SUCC"

    @property
    def ok(self) -> bool:
        return self.status == "SUCC"

    @property
    def expired(self) -> bool:
        return self.status == "SessionTimeout"

    def rows(self, obj: str) -> list[Row]:
        return self.objects.get(obj, [])

    def row(self, obj: str) -> Row:
        rows = self.rows(obj)
        return rows[0] if rows else {}


def parse(text: str) -> Answer:
    try:
        root = ET.fromstring(text.strip())
    except ET.ParseError as e:
        raise ValueError(f"not an answer of the device: {e}") from e
    answer = Answer()
    for child in root:
        instances = child.findall("Instance")
        if child.tag == "encode":
            answer.encoded.update(x for x in (child.text or "").split(",") if x)
        elif instances or child.tag.startswith("OBJ_") or child.tag == "ALLDNSHOST":
            rows = []
            for inst in instances:
                row: Row = {}
                name = None
                for e in inst:
                    if e.tag == "ParaName":
                        name = e.text or ""
                    elif e.tag == "ParaValue" and name is not None:
                        row[name] = e.text or ""
                        name = None
                rows.append(row)
            answer.objects[child.tag] = rows
        else:
            answer.values[child.tag] = (child.text or "").strip()
    return answer
