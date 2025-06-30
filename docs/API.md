# API Documentation

## Data Context API

The Mauritania Eye Tool uses React Context for state management. Here's how to interact with the data:

### useData Hook

```typescript
import { useData } from '../context/DataContext';

function MyComponent() {
  const { data, loading, updateData, refreshData } = useData();
  
  // Use the data in your component
  return (
    <div>
      {loading ? (
        <div>Loading...</div>
      ) : (
        <div>Data loaded: {data.length} items</div>
      )}
    </div>
  );
}
```

### Data Structure

Each data point follows this interface:

```typescript
interface DataPoint {
  id: number;
  name: string;
  value: number;
  category: string;
  date: string;
  status: 'active' | 'inactive' | 'pending';
  region: string;
  type: string;
}
```

### Available Methods

- `data: DataPoint[]` - Array of current data points
- `loading: boolean` - Loading state indicator
- `updateData(newData: DataPoint[])` - Update the data set
- `refreshData()` - Refresh data from source

## Utility Functions

### Data Generation

```typescript
import { generateSampleData, calculateStatistics } from '../utils/dataGenerator';

// Generate sample data
const sampleData = generateSampleData(100);

// Calculate statistics
const stats = calculateStatistics(sampleData);
```

### Chart Data Processing

Chart components automatically process data, but you can also manually format:

```typescript
const chartData = data.map(item => ({
  name: item.name,
  value: item.value,
  category: item.category
}));
```

## Component Props

### Dashboard Components

All dashboard components accept a `data` prop:

```typescript
interface ComponentProps {
  data: DataPoint[];
}
```

### Chart Components

Chart components use Recharts library and accept processed data:

```typescript
interface ChartProps {
  data: ChartData[];
  width?: number;
  height?: number;
}
```