import os
import re
import sys
import xml.etree.ElementTree as ET


MANIFEST_NS = "http://schemas.microsoft.com/win/2004/08/events"
EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
ET.register_namespace("", MANIFEST_NS)
ET.register_namespace("win", "http://manifests.microsoft.com/win/2004/08/windows/events")
ET.register_namespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")
ET.register_namespace("xs", "http://www.w3.org/2001/XMLSchema")
ET.register_namespace("trace", "http://schemas.microsoft.com/win/2004/08/events/trace")


EVENT_FIELD_TABLES = {
    "ProcessCreate": (1,),
    "FileCreateTime": (2,),
    "NetworkConnect": (3,),
    "ServiceState": (4,),
    "ProcessTerminate": (5,),
    "DriverLoad": (6,),
    "ImageLoad": (7,),
    "CreateRemoteThread": (8,),
    "RawAccessRead": (9,),
    "ProcessAccess": (10,),
    "FileCreate": (11,),
    "RegistryEvent": (12,),
    "RegistryValueSet": (13,),
    "RegistryRename": (14,),
    "FileCreateStreamHash": (15,),
    "ConfigChange": (16,),
    "PipeCreated": (17,),
    "PipeConnected": (18,),
    "WmiFilter": (19,),
    "WmiConsumer": (20,),
    "WmiConsumerToFilter": (21,),
    "DnsQuery": (22,),
    "FileDelete": (23,),
    "ClipboardChange": (24,),
    "ProcessTampering": (25,),
    "FileBlock": (26, 28),
    "FileHash": (27, 29),
}


def manifest_tag(name: str) -> str:
    return f"{{{MANIFEST_NS}}}{name}"


def event_tag(name: str) -> str:
    return f"{{{EVENT_NS}}}{name}"


def parse_field_constants(header_path: str) -> dict[str, str]:
    text = open(header_path, "r", encoding="utf-8", errors="ignore").read()
    constants = {
        match.group(1): match.group(2)
        for match in re.finditer(r'#define\s+(EVT_FIELD_[A-Za-z0-9_]+)\s+L"([^"]+)"', text)
    }
    constants["EVT_FIELD_SOURCE_PROCESS_GUID_CAPS"] = "SourceProcessGUID"
    constants["EVT_FIELD_TARGET_PROCESS_GUID_CAPS"] = "TargetProcessGUID"
    return constants


def parse_event_field_tables(tables_path: str, field_constants: dict[str, str]) -> dict[int, list[str]]:
    text = open(tables_path, "r", encoding="utf-8", errors="ignore").read()
    table_pattern = re.compile(
        r"SYSMON_DEFINE_EVENT_FIELD_TABLE\(\s*([A-Za-z0-9]+)\s*,\s*[^,]+,\s*(.*?)\n\);",
        re.S,
    )
    entry_pattern = re.compile(
        r"FIELD_DESC\([^,]+,\s*(?:L\"([^\"]+)\"|([A-Za-z0-9_]+)),\s*([A-Za-z0-9_]+),"
    )

    schemas: dict[int, list[str]] = {}
    for table_name, body in table_pattern.findall(text):
        event_ids = EVENT_FIELD_TABLES.get(table_name)
        if event_ids is None:
            continue

        fields: list[str] = []
        for literal_name, const_name, render_kind in entry_pattern.findall(body):
            field_name = literal_name or field_constants.get(const_name, const_name)
            fields.append(field_name)

        for event_id in event_ids:
            schemas[event_id] = fields

    return schemas


def parse_event_xmls(events_dir: str) -> dict[int, dict[str, object]]:
    ns = {"e": EVENT_NS}
    result: dict[int, dict[str, object]] = {}

    for name in os.listdir(events_dir):
        if not name.endswith(".xml"):
            continue

        match = re.search(r"event_(\d+)_", name)
        if match is None:
            continue

        event_id = int(match.group(1))
        root = ET.parse(os.path.join(events_dir, name)).getroot()
        version = int(root.find("./e:System/e:Version", ns).text)
        fields = [
            data.attrib["Name"]
            for data in root.findall("./e:EventData/e:Data", ns)
        ]
        result[event_id] = {"version": version, "fields": fields}

    return result


def parse_schema_events(schema_path: str) -> dict[int, dict[str, object]]:
    root = ET.parse(schema_path).getroot()
    result: dict[int, dict[str, object]] = {}

    for event_node in root.findall("event"):
        event_id = int(event_node.attrib["value"])
        fields = []
        for data_node in event_node.findall("data"):
            fields.append({
                "name": data_node.attrib["name"],
                "inType": data_node.attrib["inType"],
                "outType": data_node.attrib.get("outType"),
            })

        result[event_id] = {
            "name": event_node.attrib["name"],
            "level": event_node.attrib["level"],
            "template": event_node.attrib["template"],
            "version": int(event_node.attrib["version"]),
            "fields": fields,
        }

    return result


def extract_string_id(reference: str) -> str:
    match = re.search(r"\$\(string\.([^)]+)\)", reference or "")
    if match is None:
        raise ValueError(f"Unsupported localization reference: {reference}")
    return match.group(1)


def get_or_create_template(templates_node: ET.Element, template_id: str) -> ET.Element:
    for template in templates_node.findall(manifest_tag("template")):
        if template.attrib.get("tid") == template_id:
            return template

    template = ET.SubElement(templates_node, manifest_tag("template"))
    template.set("tid", template_id)
    return template


def set_event_message(string_table: ET.Element, string_id: str, title: str, fields: list[str]) -> None:
    message = title + ":"
    for index, field in enumerate(fields, start=1):
        message += f"%n{field}: %{index}!s!"

    for string_node in string_table.findall(manifest_tag("string")):
        if string_node.attrib.get("id") == string_id:
            string_node.set("value", message)
            return

    string_node = ET.SubElement(string_table, manifest_tag("string"))
    string_node.set("id", string_id)
    string_node.set("value", message)


def main() -> int:
    repo_root = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.getcwd()
    header_path = os.path.join(repo_root, "SysmonUser", "include", "event.h")
    tables_path = os.path.join(repo_root, "SysmonUser", "include", "event_field_tables.inc")
    schema_path = os.path.join(repo_root, "schema_events.xml")
    events_dir = os.path.join(repo_root, "events")
    manifest_path = os.path.join(repo_root, "SysmonUser", "resources", "sysmon_provider.man")

    field_constants = parse_field_constants(header_path)
    code_schemas = parse_event_field_tables(tables_path, field_constants)
    schema_events = parse_schema_events(schema_path)
    event_xmls = parse_event_xmls(events_dir)

    tree = ET.parse(manifest_path)
    root = tree.getroot()
    provider = root.find(f".//{manifest_tag('provider')}")
    events_node = provider.find(manifest_tag("events"))
    templates_node = provider.find(manifest_tag("templates"))
    string_table = root.find(f".//{manifest_tag('stringTable')}")

    if provider is None or events_node is None or templates_node is None or string_table is None:
        raise RuntimeError("Manifest structure is missing provider/events/templates/stringTable nodes")

    for event_node in events_node.findall(manifest_tag("event")):
        event_id = int(event_node.attrib["value"])
        if event_id not in schema_events:
            continue

        schema_info = schema_events[event_id]
        schema_fields = [field["name"] for field in schema_info["fields"]]
        if event_id in event_xmls:
            xml_info = event_xmls[event_id]
            xml_fields = xml_info["fields"]
            if schema_fields != xml_fields:
                raise RuntimeError(
                    f"Event {event_id} schema mismatch: schema_events={schema_fields} xml={xml_fields}"
                )

        if event_id in code_schemas and schema_fields != code_schemas[event_id]:
            raise RuntimeError(
                f"Event {event_id} schema mismatch: schema_events={schema_fields} code={code_schemas[event_id]}"
            )

        template_id = schema_info["template"]
        event_node.set("template", template_id)
        event_node.set("version", str(schema_info["version"]))
        event_node.set("level", f"win:{schema_info['level']}")
        template_node = get_or_create_template(templates_node, template_id)
        template_node[:] = []
        for field in schema_info["fields"]:
            data_node = ET.SubElement(template_node, manifest_tag("data"))
            data_node.set("name", field["name"])
            data_node.set("inType", field["inType"])
            out_type = field["outType"]
            if out_type is not None:
                data_node.set("outType", out_type)

        event_string_id = extract_string_id(event_node.attrib["message"])
        set_event_message(string_table, event_string_id, template_id, schema_fields)

    ET.indent(tree, space="    ")
    tree.write(manifest_path, encoding="utf-8", xml_declaration=True)

    text = open(manifest_path, "r", encoding="utf-8").read()
    text = text.replace(' xmlns:ns2="http://www.w3.org/2000/xmlns/"', "")
    text = text.replace(" ns2:win=", " xmlns:win=")
    text = text.replace(" ns2:xs=", " xmlns:xs=")
    text = text.replace(" ns2:trace=", " xmlns:trace=")
    if "xmlns:win=" not in text:
        text = text.replace(
            '<instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
            '<instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events" xmlns:win="http://manifests.microsoft.com/win/2004/08/windows/events" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:trace="http://schemas.microsoft.com/win/2004/08/events/trace"',
            1,
        )
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
