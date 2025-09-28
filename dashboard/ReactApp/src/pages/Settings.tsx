import { useState } from 'react';
import { motion } from 'framer-motion';
import { 
  Settings as SettingsIcon,
  Bell,
  Shield,
  Globe,
  Database,
  Zap,
  Mail,
  Lock,
  Save,
  AlertTriangle
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast } from '@/hooks/use-toast';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

export default function Settings() {
  const { toast } = useToast();
  
  const [settings, setSettings] = useState({
    // Security Settings
    autoBlockThreats: true,
    enableIDS: true,
    enableIPS: true,
    ddosProtection: true,
    geoBlocking: false,
    
    // Notifications
    emailAlerts: true,
    smsAlerts: false,
    criticalOnly: false,
    dailyReport: true,
    
    // System
    dataRetention: '30',
    logLevel: 'info',
    apiRateLimit: '1000',
    sessionTimeout: '30',
    
    // Advanced
    deepPacketInspection: false,
    aiThreatDetection: true,
    behavioralAnalysis: false,
    sandboxing: false,
  });

  const handleSaveSettings = () => {
    // Simulate saving settings
    toast({
      title: 'Settings Saved',
      description: 'Your configuration has been updated successfully',
    });
  };

  const handleToggle = (key: string) => {
    setSettings(prev => ({
      ...prev,
      [key]: !prev[key as keyof typeof settings],
    }));
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="p-6 space-y-6"
    >
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Settings</h2>
          <p className="text-muted-foreground">Manage system configuration and preferences</p>
        </div>
        <Button onClick={handleSaveSettings} className="gap-2">
          <Save className="h-4 w-4" />
          Save Changes
        </Button>
      </div>

      <Tabs defaultValue="security" className="space-y-6">
        <TabsList className="grid grid-cols-4 w-full max-w-2xl glass">
          <TabsTrigger value="security" className="gap-2">
            <Shield className="h-4 w-4" />
            Security
          </TabsTrigger>
          <TabsTrigger value="notifications" className="gap-2">
            <Bell className="h-4 w-4" />
            Notifications
          </TabsTrigger>
          <TabsTrigger value="system" className="gap-2">
            <Database className="h-4 w-4" />
            System
          </TabsTrigger>
          <TabsTrigger value="advanced" className="gap-2">
            <Zap className="h-4 w-4" />
            Advanced
          </TabsTrigger>
        </TabsList>

        {/* Security Settings */}
        <TabsContent value="security" className="space-y-6">
          <Card className="glass border-border/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary" />
                Security Configuration
              </CardTitle>
              <CardDescription>
                Configure firewall security features and threat protection
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="autoBlock">Auto-block Threats</Label>
                    <p className="text-sm text-muted-foreground">
                      Automatically block detected threats
                    </p>
                  </div>
                  <Switch
                    id="autoBlock"
                    checked={settings.autoBlockThreats}
                    onCheckedChange={() => handleToggle('autoBlockThreats')}
                  />
                </div>
                
                <Separator />
                
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="ids">Intrusion Detection System (IDS)</Label>
                    <p className="text-sm text-muted-foreground">
                      Monitor network for suspicious activities
                    </p>
                  </div>
                  <Switch
                    id="ids"
                    checked={settings.enableIDS}
                    onCheckedChange={() => handleToggle('enableIDS')}
                  />
                </div>
                
                <Separator />
                
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="ips">Intrusion Prevention System (IPS)</Label>
                    <p className="text-sm text-muted-foreground">
                      Actively prevent detected intrusions
                    </p>
                  </div>
                  <Switch
                    id="ips"
                    checked={settings.enableIPS}
                    onCheckedChange={() => handleToggle('enableIPS')}
                  />
                </div>
                
                <Separator />
                
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="ddos">DDoS Protection</Label>
                    <p className="text-sm text-muted-foreground">
                      Protect against distributed denial-of-service attacks
                    </p>
                  </div>
                  <Switch
                    id="ddos"
                    checked={settings.ddosProtection}
                    onCheckedChange={() => handleToggle('ddosProtection')}
                  />
                </div>
                
                <Separator />
                
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="geo">Geographic Blocking</Label>
                    <p className="text-sm text-muted-foreground">
                      Block traffic from specific countries
                    </p>
                  </div>
                  <Switch
                    id="geo"
                    checked={settings.geoBlocking}
                    onCheckedChange={() => handleToggle('geoBlocking')}
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Notification Settings */}
        <TabsContent value="notifications" className="space-y-6">
          <Card className="glass border-border/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Bell className="h-5 w-5 text-primary" />
                Notification Preferences
              </CardTitle>
              <CardDescription>
                Configure how you receive security alerts and reports
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="email" className="flex items-center gap-2">
                      <Mail className="h-4 w-4" />
                      Email Alerts
                    </Label>
                    <p className="text-sm text-muted-foreground">
                      Receive security alerts via email
                    </p>
                  </div>
                  <Switch
                    id="email"
                    checked={settings.emailAlerts}
                    onCheckedChange={() => handleToggle('emailAlerts')}
                  />
                </div>
                
                <Separator />
                
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="sms">SMS Alerts</Label>
                    <p className="text-sm text-muted-foreground">
                      Get critical alerts via SMS
                    </p>
                  </div>
                  <Switch
                    id="sms"
                    checked={settings.smsAlerts}
                    onCheckedChange={() => handleToggle('smsAlerts')}
                  />
                </div>
                
                <Separator />
                
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="critical" className="flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-destructive" />
                      Critical Alerts Only
                    </Label>
                    <p className="text-sm text-muted-foreground">
                      Only notify for high-severity threats
                    </p>
                  </div>
                  <Switch
                    id="critical"
                    checked={settings.criticalOnly}
                    onCheckedChange={() => handleToggle('criticalOnly')}
                  />
                </div>
                
                <Separator />
                
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="daily">Daily Security Report</Label>
                    <p className="text-sm text-muted-foreground">
                      Receive daily summary of security events
                    </p>
                  </div>
                  <Switch
                    id="daily"
                    checked={settings.dailyReport}
                    onCheckedChange={() => handleToggle('dailyReport')}
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* System Settings */}
        <TabsContent value="system" className="space-y-6">
          <Card className="glass border-border/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-5 w-5 text-primary" />
                System Configuration
              </CardTitle>
              <CardDescription>
                Manage data retention, logging, and system limits
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-2">
                  <Label htmlFor="retention">Data Retention (days)</Label>
                  <Select
                    value={settings.dataRetention}
                    onValueChange={(value) => setSettings({ ...settings, dataRetention: value })}
                  >
                    <SelectTrigger id="retention" className="bg-secondary/50 border-border/50">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="7">7 days</SelectItem>
                      <SelectItem value="30">30 days</SelectItem>
                      <SelectItem value="90">90 days</SelectItem>
                      <SelectItem value="365">1 year</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="logLevel">Log Level</Label>
                  <Select
                    value={settings.logLevel}
                    onValueChange={(value) => setSettings({ ...settings, logLevel: value })}
                  >
                    <SelectTrigger id="logLevel" className="bg-secondary/50 border-border/50">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="error">Error</SelectItem>
                      <SelectItem value="warn">Warning</SelectItem>
                      <SelectItem value="info">Info</SelectItem>
                      <SelectItem value="debug">Debug</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="rateLimit">API Rate Limit (req/min)</Label>
                  <Input
                    id="rateLimit"
                    type="number"
                    value={settings.apiRateLimit}
                    onChange={(e) => setSettings({ ...settings, apiRateLimit: e.target.value })}
                    className="bg-secondary/50 border-border/50"
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="timeout">Session Timeout (minutes)</Label>
                  <Input
                    id="timeout"
                    type="number"
                    value={settings.sessionTimeout}
                    onChange={(e) => setSettings({ ...settings, sessionTimeout: e.target.value })}
                    className="bg-secondary/50 border-border/50"
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Advanced Settings */}
        <TabsContent value="advanced" className="space-y-6">
          <Card className="glass border-border/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Zap className="h-5 w-5 text-primary" />
                Advanced Features
              </CardTitle>
              <CardDescription>
                Configure advanced security and analysis features
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="dpi">Deep Packet Inspection</Label>
                    <p className="text-sm text-muted-foreground">
                      Analyze packet contents for threats
                    </p>
                  </div>
                  <Switch
                    id="dpi"
                    checked={settings.deepPacketInspection}
                    onCheckedChange={() => handleToggle('deepPacketInspection')}
                  />
                </div>
                
                <Separator />
                
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="ai">AI Threat Detection</Label>
                    <p className="text-sm text-muted-foreground">
                      Use machine learning for threat identification
                    </p>
                  </div>
                  <Switch
                    id="ai"
                    checked={settings.aiThreatDetection}
                    onCheckedChange={() => handleToggle('aiThreatDetection')}
                  />
                </div>
                
                <Separator />
                
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="behavioral">Behavioral Analysis</Label>
                    <p className="text-sm text-muted-foreground">
                      Detect anomalies based on behavior patterns
                    </p>
                  </div>
                  <Switch
                    id="behavioral"
                    checked={settings.behavioralAnalysis}
                    onCheckedChange={() => handleToggle('behavioralAnalysis')}
                  />
                </div>
                
                <Separator />
                
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="sandbox">Sandboxing</Label>
                    <p className="text-sm text-muted-foreground">
                      Execute suspicious files in isolated environment
                    </p>
                  </div>
                  <Switch
                    id="sandbox"
                    checked={settings.sandboxing}
                    onCheckedChange={() => handleToggle('sandboxing')}
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}