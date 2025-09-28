import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Plus, 
  Edit2, 
  Trash2, 
  Shield,
  ToggleLeft,
  ToggleRight,
  Save,
  X
} from 'lucide-react';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { mockApi, PolicyRule } from '@/services/mockApi';
import { useToast } from '@/hooks/use-toast';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';

export default function Policies() {
  const [policies, setPolicies] = useState<PolicyRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<PolicyRule | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    sourceIP: '',
    destinationIP: '',
    protocol: 'Any',
    action: 'Allow' as 'Allow' | 'Block',
    enabled: true,
  });
  const { toast } = useToast();

  const fetchPolicies = async () => {
    try {
      setLoading(true);
      const data = await mockApi.getPolicies();
      setPolicies(data);
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to fetch policies',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const handleAddPolicy = () => {
    setEditingPolicy(null);
    setFormData({
      name: '',
      sourceIP: '',
      destinationIP: '',
      protocol: 'Any',
      action: 'Allow',
      enabled: true,
    });
    setIsModalOpen(true);
  };

  const handleEditPolicy = (policy: PolicyRule) => {
    setEditingPolicy(policy);
    setFormData({
      name: policy.name,
      sourceIP: policy.sourceIP,
      destinationIP: policy.destinationIP,
      protocol: policy.protocol,
      action: policy.action,
      enabled: policy.enabled,
    });
    setIsModalOpen(true);
  };

  const handleSavePolicy = async () => {
    try {
      if (editingPolicy) {
        const updated = await mockApi.updatePolicy(editingPolicy.id, formData);
        setPolicies(policies.map(p => p.id === updated.id ? updated : p));
        toast({
          title: 'Policy Updated',
          description: `"${formData.name}" has been updated successfully`,
        });
      } else {
        const newPolicy = await mockApi.addPolicy(formData);
        setPolicies([...policies, newPolicy]);
        toast({
          title: 'Policy Added',
          description: `"${formData.name}" has been added successfully`,
        });
      }
      setIsModalOpen(false);
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to save policy',
        variant: 'destructive',
      });
    }
  };

  const handleDeletePolicy = async (id: string) => {
    try {
      await mockApi.deletePolicy(id);
      setPolicies(policies.filter(p => p.id !== id));
      toast({
        title: 'Policy Deleted',
        description: 'Policy has been removed successfully',
      });
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to delete policy',
        variant: 'destructive',
      });
    }
  };

  const handleTogglePolicy = async (policy: PolicyRule) => {
    try {
      const updated = await mockApi.updatePolicy(policy.id, {
        enabled: !policy.enabled,
      });
      setPolicies(policies.map(p => p.id === updated.id ? updated : p));
      toast({
        title: policy.enabled ? 'Policy Disabled' : 'Policy Enabled',
        description: `"${policy.name}" has been ${policy.enabled ? 'disabled' : 'enabled'}`,
      });
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to toggle policy',
        variant: 'destructive',
      });
    }
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
          <h2 className="text-3xl font-bold tracking-tight">Firewall Policies</h2>
          <p className="text-muted-foreground">Configure and manage security rules</p>
        </div>
        <Button onClick={handleAddPolicy} className="gap-2">
          <Plus className="h-4 w-4" />
          Add Policy
        </Button>
      </div>

      {/* Policies Table */}
      <Card className="glass border-border/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            Active Policies
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="rounded-lg border border-border/50 overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="bg-secondary/50">
                  <TableHead>Status</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Source IP</TableHead>
                  <TableHead>Destination IP</TableHead>
                  <TableHead>Protocol</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  Array.from({ length: 5 }).map((_, i) => (
                    <TableRow key={i}>
                      {Array.from({ length: 8 }).map((_, j) => (
                        <TableCell key={j}>
                          <Skeleton className="h-4 w-full" />
                        </TableCell>
                      ))}
                    </TableRow>
                  ))
                ) : (
                  <AnimatePresence>
                    {policies.map((policy, index) => (
                      <motion.tr
                        key={policy.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: 20 }}
                        transition={{ delay: index * 0.05 }}
                        className={cn(
                          'border-b border-border/50 hover:bg-secondary/20 transition-colors',
                          !policy.enabled && 'opacity-50'
                        )}
                      >
                        <TableCell>
                          <Switch
                            checked={policy.enabled}
                            onCheckedChange={() => handleTogglePolicy(policy)}
                          />
                        </TableCell>
                        <TableCell className="font-medium">{policy.name}</TableCell>
                        <TableCell className="data-font">
                          <code className="text-xs px-2 py-1 rounded bg-secondary/50">
                            {policy.sourceIP}
                          </code>
                        </TableCell>
                        <TableCell className="data-font">
                          <code className="text-xs px-2 py-1 rounded bg-secondary/50">
                            {policy.destinationIP}
                          </code>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">{policy.protocol}</Badge>
                        </TableCell>
                        <TableCell>
                          <Badge 
                            className={cn(
                              'gap-1',
                              policy.action === 'Allow' 
                                ? 'bg-success/10 text-success border-success/20' 
                                : 'bg-destructive/10 text-destructive border-destructive/20'
                            )}
                          >
                            {policy.action === 'Allow' ? (
                              <ToggleRight className="h-3 w-3" />
                            ) : (
                              <ToggleLeft className="h-3 w-3" />
                            )}
                            {policy.action}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {new Date(policy.createdAt).toLocaleDateString()}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-2">
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => handleEditPolicy(policy)}
                            >
                              <Edit2 className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => handleDeletePolicy(policy.id)}
                              className="text-destructive hover:text-destructive"
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </motion.tr>
                    ))}
                  </AnimatePresence>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Add/Edit Policy Modal */}
      <Dialog open={isModalOpen} onOpenChange={setIsModalOpen}>
        <DialogContent className="glass border-border/50">
          <DialogHeader>
            <DialogTitle>
              {editingPolicy ? 'Edit Policy' : 'Add New Policy'}
            </DialogTitle>
            <DialogDescription>
              Configure firewall rules to control network traffic
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div>
              <Label htmlFor="name">Policy Name</Label>
              <Input
                id="name"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="e.g., Block suspicious traffic"
                className="bg-secondary/50 border-border/50"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="sourceIP">Source IP</Label>
                <Input
                  id="sourceIP"
                  value={formData.sourceIP}
                  onChange={(e) => setFormData({ ...formData, sourceIP: e.target.value })}
                  placeholder="e.g., 192.168.1.0/24 or Any"
                  className="bg-secondary/50 border-border/50"
                />
              </div>
              <div>
                <Label htmlFor="destinationIP">Destination IP</Label>
                <Input
                  id="destinationIP"
                  value={formData.destinationIP}
                  onChange={(e) => setFormData({ ...formData, destinationIP: e.target.value })}
                  placeholder="e.g., 10.0.0.0/8 or Any"
                  className="bg-secondary/50 border-border/50"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="protocol">Protocol</Label>
                <Select
                  value={formData.protocol}
                  onValueChange={(value) => setFormData({ ...formData, protocol: value })}
                >
                  <SelectTrigger className="bg-secondary/50 border-border/50">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="Any">Any</SelectItem>
                    <SelectItem value="TCP">TCP</SelectItem>
                    <SelectItem value="UDP">UDP</SelectItem>
                    <SelectItem value="ICMP">ICMP</SelectItem>
                    <SelectItem value="HTTP">HTTP</SelectItem>
                    <SelectItem value="HTTPS">HTTPS</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label htmlFor="action">Action</Label>
                <Select
                  value={formData.action}
                  onValueChange={(value: 'Allow' | 'Block') => 
                    setFormData({ ...formData, action: value })
                  }
                >
                  <SelectTrigger className="bg-secondary/50 border-border/50">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="Allow">Allow</SelectItem>
                    <SelectItem value="Block">Block</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="flex items-center justify-between">
              <Label htmlFor="enabled">Enable Policy</Label>
              <Switch
                id="enabled"
                checked={formData.enabled}
                onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
              />
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setIsModalOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleSavePolicy} className="gap-2">
              <Save className="h-4 w-4" />
              {editingPolicy ? 'Update' : 'Create'} Policy
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </motion.div>
  );
}