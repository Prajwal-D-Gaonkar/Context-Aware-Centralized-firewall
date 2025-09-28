import { Card } from '@/components/ui/card';
import { motion } from 'framer-motion';
import { LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';

interface KPICardProps {
  title: string;
  value: string | number;
  change?: string;
  icon: LucideIcon;
  trend?: 'up' | 'down' | 'neutral';
  color?: 'primary' | 'success' | 'destructive' | 'warning';
  index?: number;
}

export function KPICard({ 
  title, 
  value, 
  change, 
  icon: Icon, 
  trend = 'neutral', 
  color = 'primary',
  index = 0 
}: KPICardProps) {
  const colorClasses = {
    primary: 'text-primary border-primary/20 bg-primary/5',
    success: 'text-success border-success/20 bg-success/5',
    destructive: 'text-destructive border-destructive/20 bg-destructive/5',
    warning: 'text-warning border-warning/20 bg-warning/5',
  };

  const trendClasses = {
    up: 'text-success',
    down: 'text-destructive',
    neutral: 'text-muted-foreground',
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.1 }}
    >
      <Card className={cn(
        'p-6 relative overflow-hidden glass border',
        colorClasses[color],
        'hover:shadow-lg transition-all duration-300'
      )}>
        <div className="flex items-start justify-between">
          <div>
            <p className="text-sm text-muted-foreground mb-1">{title}</p>
            <p className="text-3xl font-bold tracking-tight">{value.toLocaleString()}</p>
            {change && (
              <p className={cn('text-sm mt-2', trendClasses[trend])}>
                {trend === 'up' && '↑'}
                {trend === 'down' && '↓'}
                {change}
              </p>
            )}
          </div>
          <div className={cn(
            'p-3 rounded-lg',
            color === 'primary' && 'bg-primary/10',
            color === 'success' && 'bg-success/10',
            color === 'destructive' && 'bg-destructive/10',
            color === 'warning' && 'bg-warning/10'
          )}>
            <Icon className="h-6 w-6" />
          </div>
        </div>
        
        {/* Animated background gradient */}
        <div className="absolute inset-0 opacity-5">
          <div className={cn(
            'absolute inset-0 animate-pulse',
            color === 'primary' && 'bg-gradient-to-br from-primary to-transparent',
            color === 'success' && 'bg-gradient-to-br from-success to-transparent',
            color === 'destructive' && 'bg-gradient-to-br from-destructive to-transparent',
            color === 'warning' && 'bg-gradient-to-br from-warning to-transparent'
          )} />
        </div>
      </Card>
    </motion.div>
  );
}