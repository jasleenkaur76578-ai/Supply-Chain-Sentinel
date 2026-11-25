import React, { useState, useEffect } from 'react';
import { Layout } from './components/layout/Layout';
import { DashboardView } from './views/DashboardView';
import { AssetInventoryView } from './views/AssetInventoryView';
import { SBOMAnalyzerView } from './views/SBOMAnalyzerView';
import { VulnerabilityView } from './views/VulnerabilityView';
import { DependencyGraphView } from './views/DependencyGraphView';
import { AttackPropagationView } from './views/AttackPropagationView';
import { RiskIntelligenceView } from './views/RiskIntelligenceView';
import { AIAssistantView } from './views/AIAssistantView';
import { RemediationView } from './views/RemediationView';
import { SupplierRiskView } from './views/SupplierRiskView';
import { AlertsView } from './views/AlertsView';
import { ReportsView } from './views/ReportsView';
import { AdminView } from './views/AdminView';
import { AuthView } from './views/AuthView';
import { User } from './types';
import { api, alertsApi } from './api/client';

export const App: React.FC = () => {
  const [isAdminRoute, setIsAdminRoute] = useState<boolean>(() =>
    window.location.pathname.startsWith('/admin')
  );
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [authChecking, setAuthChecking] = useState<boolean>(true);
  const [currentView, setCurrentView] = useState<string>('dashboard');
  const [navTarget, setNavTarget] = useState<string | undefined>(undefined);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [alertCount, setAlertCount] = useState<number>(0);

  const isAdminUser = (user: User | null) =>
    user?.role === 'super_admin' || user?.role === 'org_admin';

  const fetchAlertCount = async () => {
    try {
      const data = await alertsApi.getAlerts();
      if (Array.isArray(data)) {
        const unack = data.filter((a: any) => !a.is_acknowledged).length;
        setAlertCount(unack);
      }
    } catch {
      setAlertCount(0);
    }
  };

  useEffect(() => {
    const handleUnauthorized = () => {
      setCurrentUser(null);
      setCurrentView('dashboard');
      setAlertCount(0);
    };
    window.addEventListener('sentinel:unauthorized', handleUnauthorized);

    const token = localStorage.getItem('sentinel_jwt_token');
    if (!token) {
      setAuthChecking(false);
      return () => window.removeEventListener('sentinel:unauthorized', handleUnauthorized);
    }

    api
      .getMe()
      .then((user) => {
        setCurrentUser(user);
        if (window.location.pathname.startsWith('/admin') && isAdminUser(user)) {
          setCurrentView('admin');
        }
      })
      .catch(() => {
        api.logout();
        setCurrentUser(null);
      })
      .finally(() => {
        setAuthChecking(false);
      });

    return () => window.removeEventListener('sentinel:unauthorized', handleUnauthorized);
  }, []);

  useEffect(() => {
    if (currentUser) {
      fetchAlertCount();
    }
  }, [currentUser]);

  const handleAuthenticated = (user: User, fromAdminPortal: boolean) => {
    setCurrentUser(user);
    if (fromAdminPortal && isAdminUser(user)) {
      setCurrentView('admin');
      window.history.replaceState({}, '', '/admin');
    } else {
      setCurrentView('dashboard');
      window.history.replaceState({}, '', '/');
    }
  };

  const handleSwitchPortal = (admin: boolean) => {
    setIsAdminRoute(admin);
    window.history.replaceState({}, '', admin ? '/admin' : '/');
  };

  const handleLogout = () => {
    api.logout();
    setCurrentUser(null);
    setAlertCount(0);
    setCurrentView('dashboard');
    if (window.location.pathname.startsWith('/admin')) {
      setIsAdminRoute(true);
    }
  };

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await fetchAlertCount();
    setTimeout(() => {
      setIsRefreshing(false);
    }, 600);
  };

  const handleNavigate = (view: string, targetId?: string) => {
    if (view === 'admin' && !isAdminUser(currentUser)) {
      return;
    }
    setNavTarget(targetId);
    setCurrentView(view);
  };

  if (authChecking) {
    return (
      <div className="min-h-screen bg-[#0B1120] text-slate-300 flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-sky-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-xs font-mono tracking-wider text-slate-400">
            Verifying Security Session...
          </span>
        </div>
      </div>
    );
  }

  if (!currentUser) {
    return (
      <AuthView
        isAdminPortal={isAdminRoute}
        onAuthenticated={handleAuthenticated}
        onSwitchPortal={handleSwitchPortal}
      />
    );
  }

  const renderActiveView = () => {
    switch (currentView) {
      case 'dashboard':
        return <DashboardView onNavigate={handleNavigate} />;
      case 'assets':
        return <AssetInventoryView onNavigate={handleNavigate} />;
      case 'sbom':
        return <SBOMAnalyzerView initialAppId={navTarget} onNavigate={handleNavigate} />;
      case 'vulnerabilities':
        return <VulnerabilityView onNavigate={handleNavigate} />;
      case 'graph':
        return <DependencyGraphView initialAppId={navTarget} onNavigate={handleNavigate} />;
      case 'propagation':
        return <AttackPropagationView initialTarget={navTarget} onNavigate={handleNavigate} />;
      case 'risk':
        return <RiskIntelligenceView />;
      case 'ai-analyst':
        return <AIAssistantView />;
      case 'remediation':
        return <RemediationView />;
      case 'suppliers':
        return <SupplierRiskView />;
      case 'alerts':
        return <AlertsView />;
      case 'reports':
        return <ReportsView />;
      case 'admin':
        return <AdminView currentUser={currentUser} onNavigate={handleNavigate} />;
      default:
        return <DashboardView onNavigate={handleNavigate} />;
    }
  };

  return (
    <Layout
      currentView={currentView}
      onSelectView={(view) => {
        if (view === 'admin' && !isAdminUser(currentUser)) return;
        setNavTarget(undefined);
        setCurrentView(view);
      }}
      user={currentUser}
      onRefresh={handleRefresh}
      isRefreshing={isRefreshing}
      onLogout={handleLogout}
      alertCount={alertCount}
    >
      {renderActiveView()}
    </Layout>
  );
};

export default App;
