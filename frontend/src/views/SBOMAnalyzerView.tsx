import React, { useState, useEffect } from 'react';
import {
  UploadCloud,
  FileCode2,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Download,
  ShieldCheck,
  Search,
  Layers,
  Sparkles
} from 'lucide-react';
import { Badge } from '../components/common/Badge';
import { api } from '../api/client';
import { Application, Component } from '../types';

interface SBOMAnalyzerViewProps {
  initialAppId?: string;
  onNavigate: (view: string, targetId?: string) => void;
}

export const SBOMAnalyzerView: React.FC<SBOMAnalyzerViewProps> = ({ initialAppId, onNavigate }) => {
  const [apps, setApps] = useState<Application[]>([]);
  const [selectedAppId, setSelectedAppId] = useState<string>(initialAppId || '');
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState<any | null>(null);
  const [report, setReport] = useState<any | null>(null);
  const [loadingReport, setLoadingReport] = useState(false);
  const [searchComp, setSearchComp] = useState('');

  useEffect(() => {
    loadApps();
  }, []);

  useEffect(() => {
    if (initialAppId) {
      setSelectedAppId(initialAppId);
    }
  }, [initialAppId]);

  useEffect(() => {
    if (selectedAppId) {
      const app = apps.find((a) => a.id === selectedAppId);
      if (app && app.active_sbom_id) {
        loadReport(app.active_sbom_id);
      } else {
        setReport(null);
      }
    }
  }, [selectedAppId, apps]);

  const loadApps = async () => {
    try {
      const data = await api.getApplications();
      setApps(data);
      if (!selectedAppId && data.length > 0) {
        setSelectedAppId(data[0].id);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const loadReport = async (sbomId: string) => {
    try {
      setLoadingReport(true);
      const rep = await api.getSbomReport(sbomId);
      setReport(rep);
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingReport(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
    }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file || !selectedAppId) return;

    try {
      setUploading(true);
      const res = await api.uploadSbom(selectedAppId, file);
      setUploadResult(res);
      await loadApps();
      await loadReport(res.sbom_id);
    } catch (err: any) {
      alert(err.message || 'SBOM Upload failed');
    } finally {
      setUploading(false);
    }
  };

  const handleLoadSample = async (isVulnerable: boolean) => {
    if (!selectedAppId) return;

    // Synthetic CycloneDX 1.4 JSON matching real Log4j Log4Shell or remediated
    const sampleBom = isVulnerable
      ? {
          bomFormat: "CycloneDX",
          specVersion: "1.4",
          serialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
          version: 1,
          components: [
            {
              "bom-ref": "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.5.4",
              type: "library",
              name: "spring-boot-starter-web",
              version: "2.5.4",
              purl: "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.5.4",
              licenses: [{ license: { id: "Apache-2.0" } }]
            },
            {
              "bom-ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
              type: "library",
              name: "log4j-core",
              version: "2.14.1",
              purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
              licenses: [{ license: { id: "Apache-2.0" } }]
            },
            {
              "bom-ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.12.4",
              type: "library",
              name: "jackson-databind",
              version: "2.12.4",
              purl: "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.12.4",
              licenses: [{ license: { id: "Apache-2.0" } }]
            }
          ],
          dependencies: [
            {
              ref: "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.5.4",
              dependsOn: ["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"]
            }
          ]
        }
      : {
          bomFormat: "CycloneDX",
          specVersion: "1.4",
          serialNumber: "urn:uuid:7b912345-456b-42f5-b30f-b58921a69c88",
          version: 2,
          components: [
            {
              "bom-ref": "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.5.4",
              type: "library",
              name: "spring-boot-starter-web",
              version: "2.5.4",
              purl: "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.5.4",
              licenses: [{ license: { id: "Apache-2.0" } }]
            },
            {
              "bom-ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
              type: "library",
              name: "log4j-core",
              version: "2.17.1", // Remediated version!
              purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
              licenses: [{ license: { id: "Apache-2.0" } }]
            },
            {
              "bom-ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.12.4",
              type: "library",
              name: "jackson-databind",
              version: "2.12.4",
              purl: "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.12.4",
              licenses: [{ license: { id: "Apache-2.0" } }]
            }
          ],
          dependencies: [
            {
              ref: "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.5.4",
              dependsOn: ["pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"]
            }
          ]
        };

    const fileName = isVulnerable ? 'sample-vulnerable-cyclonedx.json' : 'sample-remediated-cyclonedx.json';
    const blob = new Blob([JSON.stringify(sampleBom, null, 2)], { type: 'application/json' });
    const sampleFile = new File([blob], fileName, { type: 'application/json' });

    try {
      setUploading(true);
      const res = await api.uploadSbom(selectedAppId, sampleFile);
      setUploadResult(res);
      await loadApps();
      await loadReport(res.sbom_id);
    } catch (err: any) {
      alert(err.message || 'Sample load failed');
    } finally {
      setUploading(false);
    }
  };

  const filteredComponents = report?.components?.filter((c: Component) => {
    return c.name.toLowerCase().includes(searchComp.toLowerCase()) || c.purl.toLowerCase().includes(searchComp.toLowerCase());
  }) || [];

  return (
    <div className="space-y-6">
      {/* Upload & Ingestion Section */}
      <div className="p-6 rounded-xl bg-[#111C30] border border-slate-800">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-6 pb-5 border-b border-slate-800/80">
          <div>
            <h2 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
              <FileCode2 className="w-4 h-4 text-sky-400" />
              <span>Ingest Software Bill of Materials (SBOM)</span>
            </h2>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Secure static ingestion supporting CycloneDX 1.4/1.5 (JSON/XML) & SPDX 2.3 (JSON)
            </p>
          </div>

          <div className="flex items-center gap-3">
            <label className="text-xs font-mono text-slate-400">Target Application:</label>
            <select
              value={selectedAppId}
              onChange={(e) => setSelectedAppId(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500 font-mono"
            >
              {apps.map((app) => (
                <option key={app.id} value={app.id}>
                  {app.name} ({app.environment})
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Dropzone & Quick Samples */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <form onSubmit={handleUpload} className="lg:col-span-2 space-y-4">
            <div className="border-2 border-dashed border-slate-700 hover:border-sky-500 rounded-xl p-6 text-center transition-colors bg-slate-900/40">
              <input
                type="file"
                id="sbomUpload"
                accept=".json,.xml"
                onChange={handleFileChange}
                className="hidden"
              />
              <label htmlFor="sbomUpload" className="cursor-pointer flex flex-col items-center gap-2">
                <UploadCloud className="w-10 h-10 text-sky-400" />
                <span className="text-sm font-semibold text-white">
                  {file ? file.name : 'Choose an SBOM file or drag & drop here'}
                </span>
                <span className="text-xs text-slate-500 font-mono">
                  Supported: CycloneDX JSON/XML (defused anti-XXE), SPDX JSON • Max 25MB
                </span>
              </label>
            </div>

            <div className="flex justify-end gap-3">
              <button
                type="submit"
                disabled={!file || uploading}
                className="px-5 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-slate-950 font-bold text-xs transition-colors flex items-center gap-2 shadow-lg shadow-sky-500/10"
              >
                {uploading ? 'Parsing & Checking Threat Feeds...' : 'Parse & Cross-Check Vulnerabilities'}
              </button>
            </div>
          </form>

          {/* Quick Demonstration Samples Card */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3 flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-2 text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
                <Sparkles className="w-3.5 h-3.5 text-sky-400" />
                <span>Instant Demo Scenarios</span>
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Inject verified synthetic SBOMs to demonstrate end-to-end detection and dual-SBOM verification.
              </p>
            </div>

            <div className="space-y-2">
              <button
                type="button"
                onClick={() => handleLoadSample(true)}
                disabled={uploading}
                className="w-full text-left px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/30 hover:bg-red-500/20 text-red-300 text-xs transition-colors"
              >
                <div className="font-bold flex items-center justify-between">
                  <span>Load Log4Shell Vulnerable SBOM</span>
                  <span className="text-[10px] font-mono">CVE-2021-44228</span>
                </div>
                <div className="text-[10px] text-red-400/80 mt-0.5">Injects log4j-core@2.14.1</div>
              </button>

              <button
                type="button"
                onClick={() => handleLoadSample(false)}
                disabled={uploading}
                className="w-full text-left px-3 py-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 hover:bg-emerald-500/20 text-emerald-300 text-xs transition-colors"
              >
                <div className="font-bold flex items-center justify-between">
                  <span>Load Remediated Clean SBOM</span>
                  <span className="text-[10px] font-mono">2.17.1 (Patched)</span>
                </div>
                <div className="text-[10px] text-emerald-400/80 mt-0.5">Verifies CVE eradication</div>
              </button>
            </div>
          </div>
        </div>

        {/* Upload Result Banner */}
        {uploadResult && (
          <div className="mt-4 p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              <div>
                <span className="text-xs font-bold text-white font-mono">
                  SBOM Successfully Ingested: {uploadResult.components_parsed} components, {uploadResult.dependencies_parsed} dependencies
                </span>
                <p className="text-xs text-slate-400">
                  Detected {uploadResult.vulnerabilities_detected} potential CVE exposure(s) ({uploadResult.critical_count} Critical)
                </p>
              </div>
            </div>
            <button
              onClick={() => onNavigate('graph', selectedAppId)}
              className="px-3 py-1.5 rounded-lg bg-sky-500/20 text-sky-300 border border-sky-500/40 text-xs font-mono font-semibold hover:bg-sky-500/30 transition-colors"
            >
              Visualize Graph
            </button>
          </div>
        )}
      </div>

      {/* SBOM Components & Report Table */}
      {report && (
        <div className="p-6 rounded-xl bg-[#111C30] border border-slate-800 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-bold text-white tracking-wide">
                Component Inventory ({report.component_count} Total)
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                {report.format} • Spec {report.spec_version} • File: {report.file_name}
              </p>
            </div>

            <div className="relative w-full sm:w-64">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search components or PURLs..."
                value={searchComp}
                onChange={(e) => setSearchComp(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
              />
            </div>
          </div>

          <div className="overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#0F172A] text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Component / Package</th>
                  <th className="px-4 py-3">Version</th>
                  <th className="px-4 py-3">Ecosystem</th>
                  <th className="px-4 py-3">Linkage</th>
                  <th className="px-4 py-3">License</th>
                  <th className="px-4 py-3">CVE Exposure</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredComponents.map((comp: Component) => (
                  <tr key={comp.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="px-4 py-3">
                      <div className="font-bold text-white">{comp.name}</div>
                      <div className="text-[10px] text-slate-500 truncate max-w-xs">{comp.purl}</div>
                    </td>
                    <td className="px-4 py-3 text-slate-300">{comp.version}</td>
                    <td className="px-4 py-3 text-slate-400">{comp.ecosystem}</td>
                    <td className="px-4 py-3">
                      {comp.is_direct ? (
                        <Badge variant="DIRECT">Direct (Depth 1)</Badge>
                      ) : (
                        <Badge variant="TRANSITIVE">Transitive (Depth {comp.depth})</Badge>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-400">{comp.license_declared}</td>
                    <td className="px-4 py-3">
                      {comp.vulnerability_count && comp.vulnerability_count > 0 ? (
                        <div className="flex items-center gap-1.5">
                          <Badge variant={comp.max_severity as any || 'CRITICAL'}>
                            {comp.vulnerability_count} Vuln ({comp.max_severity})
                          </Badge>
                        </div>
                      ) : (
                        <span className="text-emerald-400 font-mono text-[11px] flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          Clean
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
