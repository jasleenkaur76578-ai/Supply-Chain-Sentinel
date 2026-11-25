import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.sbom_parser import SBOMParser

samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "samples"))

def test_parse_cyclonedx_json():
    filepath = os.path.join(samples_dir, "payment_gateway_vulnerable_cyclonedx.json")
    with open(filepath, "rb") as f:
        content_bytes = f.read()

    result = SBOMParser.parse_sbom(content_bytes, "payment_gateway_vulnerable_cyclonedx.json")
    assert result["format"] == "CYCLONEDX_JSON"
    assert len(result["components"]) >= 5
    
    # Verify component extraction
    comp_names = [c["name"] for c in result["components"]]
    assert "log4j-core" in comp_names
    assert "spring-boot-starter-web" in comp_names

def test_parse_cyclonedx_xml_anti_xxe():
    filepath = os.path.join(samples_dir, "payment_gateway_vulnerable_cyclonedx.xml")
    with open(filepath, "rb") as f:
        content_bytes = f.read()

    result = SBOMParser.parse_sbom(content_bytes, "payment_gateway_vulnerable_cyclonedx.xml")
    assert result["format"] == "CYCLONEDX_XML"
    assert len(result["components"]) >= 3
    comp_names = [c["name"] for c in result["components"]]
    assert "log4j-core" in comp_names

def test_parse_spdx_json():
    filepath = os.path.join(samples_dir, "customer_portal_spdx.json")
    with open(filepath, "rb") as f:
        content_bytes = f.read()

    result = SBOMParser.parse_sbom(content_bytes, "customer_portal_spdx.json")
    assert result["format"] == "SPDX_JSON"
    assert len(result["components"]) >= 2
    comp_names = [c["name"] for c in result["components"]]
    assert "spring-beans" in comp_names
    assert "lodash" in comp_names
