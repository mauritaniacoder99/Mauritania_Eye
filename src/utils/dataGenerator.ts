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

const categories = ['Education', 'Healthcare', 'Infrastructure', 'Agriculture', 'Technology', 'Finance'];
const regions = ['Nouakchott', 'Nouadhibou', 'Rosso', 'Kaédi', 'Zouérat', 'Atar'];
const types = ['Primary', 'Secondary', 'Tertiary', 'Quaternary'];
const statuses: DataPoint['status'][] = ['active', 'inactive', 'pending'];

export function generateSampleData(count: number): DataPoint[] {
  const data: DataPoint[] = [];
  
  for (let i = 1; i <= count; i++) {
    const baseDate = new Date('2024-01-01');
    const randomDays = Math.floor(Math.random() * 365);
    const date = new Date(baseDate.getTime() + randomDays * 24 * 60 * 60 * 1000);
    
    data.push({
      id: i,
      name: `Data Point ${i}`,
      value: Math.floor(Math.random() * 1000) + 10,
      category: categories[Math.floor(Math.random() * categories.length)],
      date: date.toISOString().split('T')[0],
      status: statuses[Math.floor(Math.random() * statuses.length)],
      region: regions[Math.floor(Math.random() * regions.length)],
      type: types[Math.floor(Math.random() * types.length)],
    });
  }
  
  return data;
}

export function calculateStatistics(data: DataPoint[]) {
  if (data.length === 0) return null;
  
  const values = data.map(d => d.value);
  const sum = values.reduce((a, b) => a + b, 0);
  const mean = sum / values.length;
  
  const sortedValues = [...values].sort((a, b) => a - b);
  const median = sortedValues.length % 2 === 0
    ? (sortedValues[sortedValues.length / 2 - 1] + sortedValues[sortedValues.length / 2]) / 2
    : sortedValues[Math.floor(sortedValues.length / 2)];
  
  const variance = values.reduce((sum, value) => sum + Math.pow(value - mean, 2), 0) / values.length;
  const standardDeviation = Math.sqrt(variance);
  
  return {
    count: data.length,
    sum,
    mean,
    median,
    min: Math.min(...values),
    max: Math.max(...values),
    standardDeviation,
    variance,
  };
}