import { useState } from 'react';
import { api } from './api/client';
import type { Finding, User } from './types';
import { Layout } from './components/layout/Layout';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { Findings } from './pages/Findings';
import { FindingDetail } from './pages/FindingDetail';
import { AttackPaths } from './pages/AttackPaths';
import { Repositories } from './pages/Repositories';
import { PullRequestSecurity } from './pages/PullRequestSecurity';
import {
  ApisPage,
  AuditPage,
  CompliancePage,
  DependenciesPage,
  HistoryPage,
  PoliciesPage,
  RegressionsPage,
  ReportsPage,
  ServicesPage,
  SettingsPage,
} from './pages/ExtraPages';

export function App() {
  const [user, setUser] = useState<User | null>(
    api.getToken() ? { id: 'usr-1', username: 'secops', role: 'Security Engineer', email: 'secops@pythonhunter.io' } : null
  );
  const [currentRoute, setCurrentRoute] = useState<string>('/dashboard');
  const [filterSeverity, setFilterSeverity] = useState<string>('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  if (!user) {
    return <Login onLoginSuccess={(u) => setUser(u)} />;
  }

  const handleNavigate = (route: string, severity?: string) => {
    setCurrentRoute(route);
    if (severity !== undefined) {
      setFilterSeverity(severity);
    }
    setSelectedFinding(null);
  };

  const renderContent = () => {
    if (selectedFinding) {
      return <FindingDetail finding={selectedFinding} onBack={() => setSelectedFinding(null)} />;
    }

    switch (currentRoute) {
      case '/dashboard':
        return <Dashboard onNavigate={handleNavigate} />;
      case '/repositories':
        return <Repositories onNavigate={handleNavigate} />;
      case '/pull-requests':
        return <PullRequestSecurity />;
      case '/scans':
        return <Repositories onNavigate={handleNavigate} />;
      case '/findings':
        return <Findings initialSeverity={filterSeverity} onSelectFinding={(f) => setSelectedFinding(f)} />;
      case '/attack-paths':
        return <AttackPaths />;
      case '/dependencies':
        return <DependenciesPage />;
      case '/services':
        return <ServicesPage />;
      case '/apis':
        return <ApisPage />;
      case '/history':
        return <HistoryPage />;
      case '/regressions':
        return <RegressionsPage />;
      case '/policies':
        return <PoliciesPage />;
      case '/compliance':
        return <CompliancePage />;
      case '/reports':
        return <ReportsPage />;
      case '/audit':
        return <AuditPage />;
      case '/settings':
        return <SettingsPage />;
      default:
        return <Dashboard onNavigate={handleNavigate} />;
    }
  };

  return (
    <Layout
      currentRoute={currentRoute}
      onNavigate={handleNavigate}
      user={user}
      onLogout={() => {
        api.setToken(null);
        setUser(null);
      }}
    >
      {renderContent()}
    </Layout>
  );
}

export default App;
