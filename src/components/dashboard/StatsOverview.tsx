import React from 'react';
import { TrendingUp, TrendingDown, Users, BarChart3 } from 'lucide-react';

interface StatsOverviewProps {
  data: any[];
}

export function StatsOverview({ data }: StatsOverviewProps) {
  const stats = [
    {
      name: 'Total Records',
      value: data.length.toLocaleString(),
      icon: BarChart3,
      change: '+12%',
      changeType: 'positive',
    },
    {
      name: 'Average Value',
      value: data.length > 0 ? (data.reduce((sum, item) => sum + (item.value || 0), 0) / data.length).toFixed(2) : '0',
      icon: TrendingUp,
      change: '+8.2%',
      changeType: 'positive',
    },
    {
      name: 'Active Categories',
      value: new Set(data.map(item => item.category)).size.toString(),
      icon: Users,
      change: '-2.1%',
      changeType: 'negative',
    },
    {
      name: 'Data Points',
      value: (data.length * 1.5).toFixed(0),
      icon: BarChart3,
      change: '+15.3%',
      changeType: 'positive',
    },
  ];

  return (
    <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
      {stats.map((stat) => (
        <div key={stat.name} className="bg-white overflow-hidden rounded-lg border border-gray-200 shadow-sm">
          <div className="px-6 py-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <stat.icon className="h-8 w-8 text-blue-600" aria-hidden="true" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dt className="text-sm font-medium text-gray-500 truncate">{stat.name}</dt>
                <dd className="text-2xl font-semibold text-gray-900">{stat.value}</dd>
              </div>
            </div>
            <div className="mt-4 flex items-center">
              <div className={`flex items-center text-sm ${
                stat.changeType === 'positive' ? 'text-green-600' : 'text-red-600'
              }`}>
                {stat.changeType === 'positive' ? (
                  <TrendingUp className="h-4 w-4 mr-1" />
                ) : (
                  <TrendingDown className="h-4 w-4 mr-1" />
                )}
                <span className="font-medium">{stat.change}</span>
                <span className="ml-1 text-gray-500">from last month</span>
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}