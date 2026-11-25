import React, { useEffect, useState } from 'react';
import {
  Wrench,
  CheckCircle2,
  Clock,
  ShieldCheck,
  AlertTriangle,
  FileCheck2,
  Calendar,
  Layers,
  ArrowRight,
  Filter
} from 'lucide-react';
import { Badge } from '../components/common/Badge';
import { Modal } from '../components/common/Modal';
import { api } from '../api/client';
import { RemediationTask, Application } from '../types';

export const RemediationView: React.FC = () => {
  const [tasks, setTasks] = useState<RemediationTask[]>([]);
  const [apps, setApps] = useState<Application[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('ALL');

  // Verification Modal State
  const [isVerifyModalOpen, setIsVerifyModalOpen] = useState(false);
  const [selectedTask, setSelectedTask] = useState<RemediationTask | null>(null);
  const [verifyAppId, setVerifyAppId] = useState('');
  const [verifySbomId, setVerifySbomId] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<any | null>(null);

  useEffect(() => {
    loadData();
  }, [statusFilter]);

  const loadData = async () => {
    try {
      setLoading(true);
      const [tasksData, appsData] = await Promise.all([
        api.getRemediationTasks(statusFilter !== 'ALL' ? statusFilter : undefined),
        api.getApplications(),
      ]);
      setTasks(tasksData);
      setApps(appsData);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateStatus = async (taskId: string, newStatus: string) => {
    try {
      await api.updateRemediationTask(taskId, { status: newStatus as any });
      loadData();
    } catch (err: any) {
      alert(err.message || 'Failed to update task');
    }
  };

  const openVerifyModal = (task: RemediationTask) => {
    setSelectedTask(task);
    setVerifyAppId(task.application_id);
    const app = apps.find((a) => a.id === task.application_id);
    setVerifySbomId(app?.active_sbom_id || '');
    setVerificationResult(null);
    setIsVerifyModalOpen(true);
  };

  const handleExecuteVerification = async () => {
    if (!selectedTask || !verifyAppId || !verifySbomId) return;

    try {
      setVerifying(true);
      const res = await api.verifyRemediation({
        application_id: verifyAppId,
        new_sbom_id: verifySbomId,
        target_vulnerability_id: selectedTask.vulnerability_id,
      });
      setVerificationResult(res);
      await loadData();
    } catch (err: any) {
      alert(err.message || 'Verification execution failed');
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Action Header */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
            <Wrench className="w-4 h-4 text-sky-400" />
            <span>Remediation Management & Dual-SBOM Verification</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Track patch SLAs, compensating controls, and mathematically verify resolution via updated SBOMs
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-[#111C30] border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-sky-500 font-mono"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="IN_PROGRESS">In Progress</option>
            <option value="RESOLVED">Resolved</option>
            <option value="RISK_ACCEPTED">Risk Accepted</option>
          </select>
        </div>
      </div>

      {/* Remediation Tasks Table / Cards */}
      {loading ? (
        <div className="p-12 text-center text-slate-500 font-mono text-xs">Loading Remediation Tasks...</div>
      ) : (
        <div className="space-y-4">
          {tasks.map((task) => (
            <div
              key={task.id}
              className={`p-5 rounded-xl bg-[#111C30] border transition-all ${
                task.status === 'RESOLVED'
                  ? 'border-emerald-500/30'
                  : task.priority === 'URGENT'
                  ? 'border-red-500/30'
                  : 'border-slate-800'
              }`}
            >
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div className="space-y-2 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-sm font-bold text-white">{task.title}</span>
                    <Badge variant={task.status as any}>{task.status}</Badge>
                    <Badge variant={task.priority as any}>{task.priority} SLA</Badge>
                    <Badge variant="INFO">{task.vulnerability_id}</Badge>
                  </div>

                  <p className="text-xs text-slate-300 font-mono">{task.description}</p>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 text-xs font-mono text-slate-400">
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block font-bold">Target Application</span>
                      <span className="text-white font-semibold">{task.application_name}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block font-bold">Vulnerable Component</span>
                      <span className="text-red-400 font-semibold">{task.component_name}@{task.component_version}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block font-bold">Verified Fix Version</span>
                      <span className="text-emerald-400 font-semibold">{task.recommended_version || 'Latest Verified Patch'}</span>
                    </div>
                  </div>

                  {task.compensating_controls && (
                    <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 text-[11px] font-mono text-slate-400">
                      <strong className="text-slate-300">Active Compensating Controls:</strong> {task.compensating_controls}
                    </div>
                  )}
                </div>

                {/* Task Actions */}
                <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 shrink-0">
                  <button
                    onClick={() => openVerifyModal(task)}
                    className="px-3.5 py-2 rounded-lg bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/25 text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-colors"
                  >
                    <FileCheck2 className="w-4 h-4 text-emerald-400" />
                    <span>Verify with New SBOM</span>
                  </button>

                  <select
                    value={task.status}
                    onChange={(e) => handleUpdateStatus(task.id, e.target.value)}
                    className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-sky-500 font-mono"
                  >
                    <option value="OPEN">Mark Open</option>
                    <option value="IN_PROGRESS">Mark In Progress</option>
                    <option value="RESOLVED">Mark Resolved</option>
                    <option value="RISK_ACCEPTED">Risk Accepted</option>
                  </select>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Dual-SBOM Verification Modal */}
      <Modal
        isOpen={isVerifyModalOpen}
        onClose={() => setIsVerifyModalOpen(false)}
        title="Dual-SBOM Remediation Verification"
        subtitle="Mathematically prove vulnerability eradication by comparing pre- and post-remediation SBOMs"
        maxWidth="xl"
      >
        <div className="space-y-4 font-mono text-xs">
          {selectedTask && (
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Target CVE:</span>
                <span className="font-bold text-white">{selectedTask.vulnerability_id}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Component:</span>
                <span className="font-bold text-red-400">{selectedTask.component_name}@{selectedTask.component_version}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Application:</span>
                <span className="font-bold text-sky-400">{selectedTask.application_name}</span>
              </div>
            </div>
          )}

          <div>
            <label className="block text-slate-400 uppercase font-bold text-[10px] mb-1">
              Select Rescanned / Updated SBOM Document
            </label>
            <p className="text-[11px] text-slate-500 mb-2">
              The engine will parse the updated component tree to confirm {selectedTask?.vulnerability_id} is completely absent.
            </p>
            <input
              type="text"
              readOnly
              value={verifySbomId || 'Active Verified Application SBOM Artifact'}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-300 text-xs"
            />
          </div>

          <div className="p-3 rounded-lg bg-sky-950/20 border border-sky-500/20 text-sky-300 text-[11px] leading-relaxed">
            💡 <strong>Verification Principle:</strong> Supply Chain Sentinel requires verified artifact proof. A ticket cannot be closed based on verbal assurance; the updated SBOM must be statically verified clean.
          </div>

          {/* Verification Result Banner */}
          {verificationResult && (
            <div
              className={`p-4 rounded-xl border space-y-2 ${
                verificationResult.verified
                  ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-300'
                  : 'bg-red-950/20 border-red-500/30 text-red-300'
              }`}
            >
              <div className="flex items-center gap-2 font-bold text-sm">
                {verificationResult.verified ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-red-400" />
                )}
                <span>{verificationResult.verified ? 'REMEDIATION VERIFIED SUCCESSFUL' : 'VERIFICATION FAILED'}</span>
              </div>
              <p className="text-xs">{verificationResult.message}</p>
              <div className="text-[11px] text-slate-400 pt-1">
                Residual Risk: <strong>{verificationResult.residual_risk}</strong> • Status: <strong>{verificationResult.status}</strong>
              </div>
            </div>
          )}

          <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
            <button
              onClick={() => setIsVerifyModalOpen(false)}
              className="px-4 py-2 text-slate-400 hover:text-white"
            >
              Close
            </button>
            <button
              onClick={handleExecuteVerification}
              disabled={verifying}
              className="px-5 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs transition-colors flex items-center gap-2"
            >
              {verifying ? 'Scanning Dependency Tree...' : 'Execute Mathematical Verification'}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
