# Contributing to Mauritania Eye Tool

Thank you for your interest in contributing to the Mauritania Eye Tool! This document provides guidelines and information for contributors.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/mauritaniacoder99/mauritania-eye-tool.git
   cd mauritania-eye-tool
   ```
3. **Install dependencies**:
   ```bash
   npm install
   ```
4. **Start the development server**:
   ```bash
   npm run dev
   ```

## Development Workflow

### Branch Naming Convention

- `feature/description` - New features
- `bugfix/description` - Bug fixes
- `hotfix/description` - Critical fixes
- `docs/description` - Documentation updates

### Code Style

We use ESLint and Prettier for code formatting. Run these commands before committing:

```bash
npm run lint
npm run format
```

### Commit Messages

Follow conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Examples:
- `feat(dashboard): add new chart component`
- `fix(table): resolve sorting issue`
- `docs(readme): update installation instructions`

## Component Development

### Creating New Components

1. Create component files in appropriate directories:
   ```
   src/components/
   ├── charts/          # Chart components
   ├── dashboard/       # Dashboard components
   ├── data/           # Data handling components
   └── ui/             # Base UI components
   ```

2. Follow the component template:
   ```typescript
   import React from 'react';
   
   interface ComponentProps {
     // Define props
   }
   
   export function Component({ }: ComponentProps) {
     return (
       <div>
         {/* Component JSX */}
       </div>
     );
   }
   ```

3. Export from index file:
   ```typescript
   export { Component } from './Component';
   ```

### Styling Guidelines

- Use Tailwind CSS classes for styling
- Follow the design system colors and spacing
- Ensure responsive design for all screen sizes
- Add hover states and transitions for better UX

## Testing

### Running Tests

```bash
npm test
```

### Writing Tests

Create test files alongside components:
```
src/components/Component.tsx
src/components/Component.test.tsx
```

Use React Testing Library for component tests:
```typescript
import { render, screen } from '@testing-library/react';
import { Component } from './Component';

test('renders component correctly', () => {
  render(<Component />);
  expect(screen.getByText('Expected text')).toBeInTheDocument();
});
```

## Documentation

### Code Documentation

- Add JSDoc comments for complex functions
- Document component props with TypeScript interfaces
- Include usage examples in component documentation

### README Updates

When adding new features:
1. Update the features list
2. Add usage examples
3. Update installation instructions if needed

## Pull Request Process

1. **Create a feature branch** from `main`
2. **Make your changes** following the guidelines above
3. **Test thoroughly** - ensure all tests pass
4. **Update documentation** as needed
5. **Submit a pull request** with:
   - Clear description of changes
   - Screenshots for UI changes
   - Link to related issues

### Pull Request Template

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] Added tests for new functionality
- [ ] Manual testing completed

## Screenshots
(If applicable)

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes
```

## Issue Reporting

### Bug Reports

Include:
- Steps to reproduce
- Expected behavior
- Actual behavior
- Browser/OS information
- Screenshots if applicable

### Feature Requests

Include:
- Use case description
- Proposed solution
- Alternative solutions considered
- Additional context

## Community Guidelines

- Be respectful and inclusive
- Help others learn and grow
- Focus on constructive feedback
- Follow the code of conduct

## Questions?

If you have questions about contributing:
- Check existing issues and discussions
- Create a new issue with the `question` label
- Reach out to maintainers

Thank you for contributing to the Mauritania Eye Tool!
