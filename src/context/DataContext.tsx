import React, { createContext, useContext, useState, useEffect } from 'react';
import { generateSampleData } from '../utils/dataGenerator';

interface DataContextType {
  data: any[];
  loading: boolean;
  updateData: (newData: any[]) => void;
  refreshData: () => void;
}

const DataContext = createContext<DataContextType | undefined>(undefined);

export function DataProvider({ children }: { children: React.ReactNode }) {
  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Simulate data loading
    const loadData = async () => {
      setLoading(true);
      await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate API call
      const sampleData = generateSampleData(50);
      setData(sampleData);
      setLoading(false);
    };

    loadData();
  }, []);

  const updateData = (newData: any[]) => {
    setData(newData);
  };

  const refreshData = () => {
    setLoading(true);
    setTimeout(() => {
      const sampleData = generateSampleData(50);
      setData(sampleData);
      setLoading(false);
    }, 1000);
  };

  return (
    <DataContext.Provider value={{ data, loading, updateData, refreshData }}>
      {children}
    </DataContext.Provider>
  );
}

export function useData() {
  const context = useContext(DataContext);
  if (context === undefined) {
    throw new Error('useData must be used within a DataProvider');
  }
  return context;
}