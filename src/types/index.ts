export interface DataPoint {
  id: number;
  name: string;
  value: number;
  category: string;
  date: string;
  status: 'active' | 'inactive' | 'pending';
  region: string;
  type: string;
}

export interface ChartData {
  name: string;
  value: number;
  category?: string;
  date?: string;
}

export interface Statistics {
  count: number;
  sum: number;
  mean: number;
  median: number;
  min: number;
  max: number;
  standardDeviation: number;
  variance: number;
}

export interface FilterOptions {
  category?: string;
  region?: string;
  status?: string;
  dateRange?: {
    start: string;
    end: string;
  };
}