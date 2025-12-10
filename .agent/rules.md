# General Rules

## Testing Best Practices

### 1. Test Behavior, Not Implementation
- **Focus on Public API**: Test what the code *does*, not how it does it.
- **Avoid Tautologies**: Don't write tests that just assert a function was called or returns `True` without verifying the *correctness* of the output.
- **Independence**: Tests must be runnable in any order. Do not rely on shared state modification from previous tests.

### 2. The AAA Pattern
Structure every test clearly:
- **Arrange**: Set up the initial state and inputs.
- **Act**: Execute the function or method under test.
- **Assert**: Verify the result matches expectations.

### 3. Edge Case Checklist
Always consider these scenarios when writing tests or implementation code:
- **Inputs**: None/null, empty strings/collections, single elements, large inputs, boundary values (0, -1, MAX), invalid types.
- **State**: Uninitialized objects, already closed/completed states, concurrent modifications.
- **Resources**: Network timeouts, file system errors, memory exhaustion.

## Anti-Patterns to Avoid
- **Testing Private Members**: Avoid testing `_underscored` definitions unless absolutely necessary.
- **Mocking Everything**: Don't mock the logic you are trying to test. Only mock external boundaries (network, disk, databases).
- **Sleeps**: Avoid `time.sleep()` in tests. Use robust polling or callbacks.
