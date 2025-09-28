import axios from 'axios';

// Types
export interface DashboardData {
  totalRequests: number;
  blockedRequests: number;
  uniqueIPs: number;
  requestsPerMinute: Array<{ time: string; value: number }>;
  attacksByType: Array<{ type: string; count: number }>;
  verdictDistribution: Array<{ name: string; value: number; color: string }>;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  sourceIP: string;
  destinationIP: string;
  protocol: string;
  verdict: 'Allowed' | 'Blocked';
  reason: string;
}

export interface PolicyRule {
  id: string;
  name: string;
  sourceIP: string;
  destinationIP: string;
  protocol: string;
  action: 'Allow' | 'Block';
  enabled: boolean;
  createdAt: string;
}

// Mock data generators
const generateMockDashboard = (): DashboardData => {
  const now = new Date();
  const requestsPerMinute = Array.from({ length: 20 }, (_, i) => {
    const time = new Date(now.getTime() - (19 - i) * 60000);
    return {
      time: time.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
      value: Math.floor(Math.random() * 500) + 100,
    };
  });

  const totalRequests = Math.floor(Math.random() * 50000) + 10000;
  const blockedRequests = Math.floor(totalRequests * (Math.random() * 0.3 + 0.1));

  return {
    totalRequests,
    blockedRequests,
    uniqueIPs: Math.floor(Math.random() * 1000) + 200,
    requestsPerMinute,
    attacksByType: [
      { type: 'DDoS', count: Math.floor(Math.random() * 1000) + 100 },
      { type: 'SQL Injection', count: Math.floor(Math.random() * 500) + 50 },
      { type: 'XSS', count: Math.floor(Math.random() * 300) + 30 },
      { type: 'Brute Force', count: Math.floor(Math.random() * 800) + 80 },
      { type: 'Port Scan', count: Math.floor(Math.random() * 600) + 60 },
    ],
    verdictDistribution: [
      { name: 'Allowed', value: totalRequests - blockedRequests, color: 'hsl(142, 70%, 45%)' },
      { name: 'Blocked', value: blockedRequests, color: 'hsl(0, 84%, 55%)' },
    ],
  };
};

const generateMockLogs = (page: number = 1, pageSize: number = 10): { data: LogEntry[]; total: number } => {
  const total = 500;
  const logs: LogEntry[] = [];
  const protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS'];
  const reasons = [
    'Suspicious pattern detected',
    'IP on blocklist',
    'Rate limit exceeded',
    'Invalid protocol',
    'Geographic restriction',
    'Normal traffic',
    'Whitelisted IP',
  ];

  for (let i = 0; i < pageSize; i++) {
    const verdict = Math.random() > 0.3 ? 'Allowed' : 'Blocked';
    logs.push({
      id: `log-${page}-${i}`,
      timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString(),
      sourceIP: `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
      destinationIP: `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
      protocol: protocols[Math.floor(Math.random() * protocols.length)],
      verdict,
      reason: verdict === 'Blocked' 
        ? reasons[Math.floor(Math.random() * 5)]
        : reasons[Math.floor(Math.random() * 2) + 5],
    });
  }

  return { data: logs, total };
};

const generateMockPolicies = (): PolicyRule[] => {
  return [
    {
      id: 'pol-1',
      name: 'Block suspicious IPs',
      sourceIP: '192.168.1.0/24',
      destinationIP: 'Any',
      protocol: 'Any',
      action: 'Block',
      enabled: true,
      createdAt: new Date(Date.now() - 86400000).toISOString(),
    },
    {
      id: 'pol-2',
      name: 'Allow internal network',
      sourceIP: '10.0.0.0/8',
      destinationIP: '10.0.0.0/8',
      protocol: 'Any',
      action: 'Allow',
      enabled: true,
      createdAt: new Date(Date.now() - 172800000).toISOString(),
    },
    {
      id: 'pol-3',
      name: 'Block ICMP',
      sourceIP: 'Any',
      destinationIP: 'Any',
      protocol: 'ICMP',
      action: 'Block',
      enabled: false,
      createdAt: new Date(Date.now() - 259200000).toISOString(),
    },
    {
      id: 'pol-4',
      name: 'Allow HTTPS',
      sourceIP: 'Any',
      destinationIP: 'Any',
      protocol: 'HTTPS',
      action: 'Allow',
      enabled: true,
      createdAt: new Date(Date.now() - 345600000).toISOString(),
    },
    {
      id: 'pol-5',
      name: 'Rate limit protection',
      sourceIP: 'Any',
      destinationIP: 'Any',
      protocol: 'HTTP',
      action: 'Block',
      enabled: true,
      createdAt: new Date(Date.now() - 432000000).toISOString(),
    },
  ];
};

// Mock API client
class MockApiClient {
  private policies: PolicyRule[] = generateMockPolicies();

  async getDashboard(): Promise<DashboardData> {
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 500));
    return generateMockDashboard();
  }

  async getLogs(page: number = 1, pageSize: number = 10, search?: string): Promise<{ data: LogEntry[]; total: number }> {
    await new Promise(resolve => setTimeout(resolve, 500));
    let result = generateMockLogs(page, pageSize);
    
    if (search) {
      result.data = result.data.filter(log => 
        log.sourceIP.includes(search) || 
        log.destinationIP.includes(search) ||
        log.protocol.toLowerCase().includes(search.toLowerCase()) ||
        log.reason.toLowerCase().includes(search.toLowerCase())
      );
    }
    
    return result;
  }

  async getPolicies(): Promise<PolicyRule[]> {
    await new Promise(resolve => setTimeout(resolve, 500));
    return [...this.policies];
  }

  async addPolicy(policy: Omit<PolicyRule, 'id' | 'createdAt'>): Promise<PolicyRule> {
    await new Promise(resolve => setTimeout(resolve, 500));
    const newPolicy: PolicyRule = {
      ...policy,
      id: `pol-${Date.now()}`,
      createdAt: new Date().toISOString(),
    };
    this.policies.push(newPolicy);
    return newPolicy;
  }

  async updatePolicy(id: string, updates: Partial<PolicyRule>): Promise<PolicyRule> {
    await new Promise(resolve => setTimeout(resolve, 500));
    const index = this.policies.findIndex(p => p.id === id);
    if (index === -1) throw new Error('Policy not found');
    
    this.policies[index] = { ...this.policies[index], ...updates };
    return this.policies[index];
  }

  async deletePolicy(id: string): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, 500));
    const index = this.policies.findIndex(p => p.id === id);
    if (index === -1) throw new Error('Policy not found');
    
    this.policies.splice(index, 1);
  }
}

export const mockApi = new MockApiClient();