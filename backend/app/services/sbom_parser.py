import json
import hashlib
from typing import Dict, Any, List, Tuple
import defusedxml.ElementTree as ET

class SBOMParser:
    """
    Enterprise-grade hardened SBOM Parser.
    Supports:
    - CycloneDX 1.4 / 1.5 JSON
    - CycloneDX 1.4 / 1.5 XML (hardened via defusedxml against XXE and entity expansion)
    - SPDX 2.2 / 2.3 JSON
    """

    @staticmethod
    def compute_sha256(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    @staticmethod
    def parse_sbom(content_bytes: bytes, filename: str) -> Dict[str, Any]:
        sha256_hash = SBOMParser.compute_sha256(content_bytes)
        text_content = content_bytes.decode('utf-8', errors='replace').strip()

        if text_content.startswith('{'):
            try:
                data = json.loads(text_content)
                if "bomFormat" in data and data.get("bomFormat") == "CycloneDX":
                    return SBOMParser._parse_cyclonedx_json(data, sha256_hash, filename, text_content)
                elif "spdxVersion" in data:
                    return SBOMParser._parse_spdx_json(data, sha256_hash, filename, text_content)
                elif "components" in data:
                    return SBOMParser._parse_cyclonedx_json(data, sha256_hash, filename, text_content)
            except Exception as e:
                pass

        if text_content.startswith('<'):
            try:
                root = ET.fromstring(text_content)
                return SBOMParser._parse_cyclonedx_xml(root, sha256_hash, filename, text_content)
            except Exception as e:
                raise ValueError(f"Malformed or unsafe XML SBOM: {str(e)}")

        raise ValueError("Unsupported SBOM format. Expected valid CycloneDX (JSON/XML) or SPDX (JSON).")

    @staticmethod
    def _normalize_ecosystem(purl: str, comp_type: str = "") -> str:
        if purl.startswith("pkg:maven"):
            return "Maven"
        elif purl.startswith("pkg:npm"):
            return "npm"
        elif purl.startswith("pkg:pypi"):
            return "PyPI"
        elif purl.startswith("pkg:golang"):
            return "Go"
        elif purl.startswith("pkg:cargo"):
            return "crates.io"
        elif purl.startswith("pkg:nuget"):
            return "NuGet"
        return "Generic"

    @staticmethod
    def _parse_cyclonedx_json(data: Dict[str, Any], sha256: str, filename: str, raw: str) -> Dict[str, Any]:
        spec_version = data.get("specVersion", "1.4")
        serial_number = data.get("serialNumber", "")
        version = data.get("version", 1)
        raw_components = data.get("components", [])
        raw_dependencies = data.get("dependencies", [])

        components = []
        comp_ref_map = {} # bom-ref -> component index / purl

        for idx, rc in enumerate(raw_components):
            name = rc.get("name", f"component-{idx}")
            version_str = rc.get("version", "0.0.0")
            bom_ref = rc.get("bom-ref", f"ref-{idx}")
            purl = rc.get("purl", f"pkg:generic/{name}@{version_str}")
            ecosystem = SBOMParser._normalize_ecosystem(purl)

            # License extraction
            licenses = rc.get("licenses", [])
            lic_str = "NOASSERTION"
            if licenses and isinstance(licenses, list):
                first_lic = licenses[0]
                if isinstance(first_lic, dict):
                    if "license" in first_lic and "id" in first_lic["license"]:
                        lic_str = first_lic["license"]["id"]
                    elif "license" in first_lic and "name" in first_lic["license"]:
                        lic_str = first_lic["license"]["name"]

            # Supplier extraction
            supplier_name = "Open Source Community"
            supplier_data = rc.get("supplier", {})
            if isinstance(supplier_data, dict) and "name" in supplier_data:
                supplier_name = supplier_data["name"]

            comp_obj = {
                "bom_ref": bom_ref,
                "name": name,
                "version": version_str,
                "purl": purl,
                "ecosystem": ecosystem,
                "license_declared": lic_str,
                "supplier_name": supplier_name,
                "is_direct": True, # Determined during dependency linking
                "depth": 1
            }
            components.append(comp_obj)
            comp_ref_map[bom_ref] = comp_obj
            comp_ref_map[name] = comp_obj

        # Relationship parsing
        relationships = []
        referenced_children = set()

        for dep in raw_dependencies:
            ref = dep.get("ref")
            depends_on = dep.get("dependsOn", [])
            for child_ref in depends_on:
                relationships.append({
                    "parent_ref": ref,
                    "child_ref": child_ref,
                    "type": "DEPENDS_ON"
                })
                referenced_children.add(child_ref)

        # Mark transitive vs direct
        for comp in components:
            if comp["bom_ref"] in referenced_children or comp["name"] in referenced_children:
                comp["is_direct"] = False
                comp["depth"] = 2

        return {
            "format": "CYCLONEDX_JSON",
            "spec_version": str(spec_version),
            "serial_number": serial_number,
            "version": version,
            "file_hash_sha256": sha256,
            "file_name": filename,
            "raw_content": raw,
            "components": components,
            "relationships": relationships,
            "warnings": []
        }

    @staticmethod
    def _parse_cyclonedx_xml(root: Any, sha256: str, filename: str, raw: str) -> Dict[str, Any]:
        # Strip XML namespaces
        for elem in root.iter():
            if '}' in elem.tag:
                elem.tag = elem.tag.split('}', 1)[1]

        spec_version = root.attrib.get("version", "1.4")
        serial_number = root.attrib.get("serialNumber", "")
        
        components = []
        comp_ref_map = {}

        components_elem = root.find("components")
        if components_elem is not None:
            for idx, c in enumerate(components_elem.findall("component")):
                name_elem = c.find("name")
                ver_elem = c.find("version")
                purl_elem = c.find("purl")

                name = name_elem.text if name_elem is not None and name_elem.text else f"comp-{idx}"
                version_str = ver_elem.text if ver_elem is not None and ver_elem.text else "0.0.0"
                bom_ref = c.attrib.get("bom-ref", f"ref-{idx}")
                purl = purl_elem.text if purl_elem is not None and purl_elem.text else f"pkg:generic/{name}@{version_str}"
                ecosystem = SBOMParser._normalize_ecosystem(purl)

                comp_obj = {
                    "bom_ref": bom_ref,
                    "name": name,
                    "version": version_str,
                    "purl": purl,
                    "ecosystem": ecosystem,
                    "license_declared": "NOASSERTION",
                    "supplier_name": "Open Source Community",
                    "is_direct": True,
                    "depth": 1
                }
                components.append(comp_obj)
                comp_ref_map[bom_ref] = comp_obj

        # Dependencies
        relationships = []
        dependencies_elem = root.find("dependencies")
        if dependencies_elem is not None:
            for dep in dependencies_elem.findall("dependency"):
                parent_ref = dep.attrib.get("ref", "")
                for sub in dep.findall("dependency"):
                    child_ref = sub.attrib.get("ref", "")
                    if child_ref:
                        relationships.append({
                            "parent_ref": parent_ref,
                            "child_ref": child_ref,
                            "type": "DEPENDS_ON"
                        })
                        if child_ref in comp_ref_map:
                            comp_ref_map[child_ref]["is_direct"] = False
                            comp_ref_map[child_ref]["depth"] = 2

        return {
            "format": "CYCLONEDX_XML",
            "spec_version": str(spec_version),
            "serial_number": serial_number,
            "version": 1,
            "file_hash_sha256": sha256,
            "file_name": filename,
            "raw_content": raw,
            "components": components,
            "relationships": relationships,
            "warnings": []
        }

    @staticmethod
    def _parse_spdx_json(data: Dict[str, Any], sha256: str, filename: str, raw: str) -> Dict[str, Any]:
        spec_version = data.get("spdxVersion", "SPDX-2.3")
        serial_number = data.get("SPDXID", "")
        packages = data.get("packages", [])
        relationships_raw = data.get("relationships", [])

        components = []
        spdx_map = {}

        for idx, pkg in enumerate(packages):
            spdx_id = pkg.get("SPDXID", f"SPDXRef-{idx}")
            name = pkg.get("name", f"package-{idx}")
            version_str = pkg.get("versionInfo", "0.0.0")
            
            # PURL in externalRefs
            purl = f"pkg:generic/{name}@{version_str}"
            ecosystem = "Generic"
            for ext in pkg.get("externalRefs", []):
                if ext.get("referenceType") == "purl":
                    purl = ext.get("referenceLocator", purl)
                    ecosystem = SBOMParser._normalize_ecosystem(purl)
                    break

            license_concluded = pkg.get("licenseConcluded", "NOASSERTION")
            supplier = pkg.get("supplier", "Organization: Open Source")

            comp_obj = {
                "bom_ref": spdx_id,
                "name": name,
                "version": version_str,
                "purl": purl,
                "ecosystem": ecosystem,
                "license_declared": license_concluded,
                "supplier_name": supplier.replace("Organization: ", "").replace("Person: ", ""),
                "is_direct": True,
                "depth": 1
            }
            components.append(comp_obj)
            spdx_map[spdx_id] = comp_obj

        relationships = []
        for rel in relationships_raw:
            rel_type = rel.get("relationshipType", "")
            elem_id = rel.get("spdxElementId", "")
            related_elem_id = rel.get("relatedSpdxElement", "")

            if rel_type in ("DEPENDS_ON", "DEPENDENCY_OF", "CONTAINS"):
                relationships.append({
                    "parent_ref": elem_id,
                    "child_ref": related_elem_id,
                    "type": rel_type
                })
                if related_elem_id in spdx_map:
                    spdx_map[related_elem_id]["is_direct"] = False
                    spdx_map[related_elem_id]["depth"] = 2

        return {
            "format": "SPDX_JSON",
            "spec_version": str(spec_version),
            "serial_number": serial_number,
            "version": 1,
            "file_hash_sha256": sha256,
            "file_name": filename,
            "raw_content": raw,
            "components": components,
            "relationships": relationships,
            "warnings": []
        }
