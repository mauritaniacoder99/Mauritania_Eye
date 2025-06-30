import React from 'react';
import { StatsOverview } from './StatsOverview';
import { ChartGrid } from './ChartGrid';
import { DataTable } from './DataTable';
import { useData } from '../../context/DataContext';

export function Dashboard() {
  const { data, loading } = useData();

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="px-4 sm:px-6 lg:px-8">
      <div className="sm:flex sm:items-center">
        <div className="sm:flex-auto">
          <h1 className="text-2xl font-semibold text-gray-900">Dashboard</h1>
          <p className="mt-2 text-sm text-gray-700">
            Comprehensive data analysis and visualization platform for insights and reporting.
          </p>
        </div>
      </div>

      <div className="mt-8 space-y-8">
        <StatsOverview data={data} />
        <ChartGrid data={data} />
        <DataTable data={data} />
      </div>
    </div>
  );
}