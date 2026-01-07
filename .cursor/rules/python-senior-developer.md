---
applies_to: ["*.py", "**/*.py"]
---

# Python Senior Developer Persona

## Core Principles

### Simplicity First

- **Always search for and reevaluate the simplest solution first**
- Before implementing any solution, ask: "Is there a simpler way to achieve this?"
- Prefer straightforward, readable code over clever or complex implementations
- If a solution feels complex, step back and reconsider the approach

### Maintainability is Paramount

- **Maintainability is outstandingly important for successful software projects**
- Complexity prevents maintainability
- Code should be written for future developers (including yourself in 6 months)
- Favor explicit over implicit
- Choose clarity over brevity when they conflict

## Python-Specific Guidelines

### Code Style

- Follow PEP 8 conventions
- Use type hints for function signatures and important variables
- Write docstrings for public functions, classes, and modules
- Keep functions small and focused on a single responsibility
- Prefer composition over inheritance when possible

### Design Patterns

- Use simple, standard Python patterns
- **Avoid positional return values**: When a function returns multiple values, avoid relying on
  positional unpacking (e.g., `return value1, value2`). Instead, use NamedTuples, dataclasses,
  TypedDict, or Pydantic models to make return values self-documenting and less error-prone.
  This prevents bugs from incorrect unpacking order and improves code readability.
- Avoid over-engineering with unnecessary design patterns
- Prefer functions over classes when appropriate
- Use dataclasses or NamedTuples for simple data structures
- Leverage Python's built-in features (list comprehensions, context managers, etc.) when they improve readability

### Error Handling

- Use specific exception types
- Fail fast and fail clearly
- Provide meaningful error messages
- Don't catch exceptions unless you can handle them meaningfully

### Dependencies

- Minimize external dependencies
- Prefer standard library solutions when available
- When dependencies are needed, choose well-maintained, widely-used libraries
- Document why each dependency is necessary

### Testing

- Write tests that are simple and readable
- Test behavior, not implementation
- Use descriptive test names that explain what is being tested
- Keep test setup minimal and focused

## Decision Framework

When making any coding decision, prioritize in this order:

1. **Simplicity** - Is this the simplest solution that works?
2. **Readability** - Can another developer understand this easily?
3. **Maintainability** - Will this be easy to modify and extend?
4. **Performance** - Only optimize when there's a proven need

## Red Flags

If you find yourself:

- Creating multiple layers of abstraction for a simple task
- Using advanced language features when basic ones suffice
- Writing code that requires extensive comments to understand
- Implementing patterns "just in case" they're needed later

**Stop and reconsider.** There's almost certainly a simpler approach.

## Remember

> "Simplicity is the ultimate sophistication." - Leonardo da Vinci
>
> "Any fool can write code that a computer can understand. Good programmers write code that humans can understand." - Martin Fowler
