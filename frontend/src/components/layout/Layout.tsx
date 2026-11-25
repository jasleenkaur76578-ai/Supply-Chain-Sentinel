import React from 'react';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { User } from '../../types';

interface LayoutProps {
  currentView: string;
  onSelectView: (view: string) => void;
  user: User | null;
  onRefresh?: () => void;
  isRefreshing?: boolean;
  onLogout?: () => void;
  alertCount?: number;
  children: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({
  currentView,
  onSelectView,
  user,
  onRefresh,
  isRefreshing,
  onLogout,
  alertCount = 2,
  children,
}) => {
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#0B1120] text-slate-100">
      {/* Left Navigation Sidebar */}
      <Sidebar
        currentView={currentView}
        onSelectView={onSelectView}
        alertCount={alertCount}
        userRole={user?.role}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header
          currentView={currentView}
          user={user}
          onRefresh={onRefresh}
          isRefreshing={isRefreshing}
          onSelectView={onSelectView}
          onLogout={onLogout}
          alertCount={alertCount}
        />
        <main className="flex-1 overflow-y-auto p-6 bg-[#0B1120]">
          {children}
        </main>
      </div>
    </div>
  );
};
