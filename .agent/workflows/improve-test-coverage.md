---
description: Systematically improve test coverage for existing code, focusing on quality and meaningful tests.
---
// turbo-all

# Phase 1: Analyze Current State

1. Ask the user which module they want to improve coverage for.
2. Run the initial coverage report to establish a baseline.
   ```bash
   pytest tests/test_{module}.py --cov=app/{module} --cov-report=term-missing
   ```
3. Analyze the output to identify specific gaps:
   - Uncovered lines
   - Uncovered branches
   - Missing error handling
   - Missing edge cases
4. (Optional) Measure cyclomatic complexity to find hard-to-test areas.
   ```bash
   radon cc app/{module}.py -s -a
   ```

# Phase 2: Prioritize

5. Create a plan/backlog of tests to write, prioritized by criticality:
   - **P0 - Critical**: Error handling, data corruption prevention.
   - **P1 - High**: Core business logic, high complexity.
   - **P2 - Medium**: Secondary paths, configuration.
   - **P3 - Low**: Logging, metrics.

# Phase 3: Write Missing Tests (Iterative)

6. Pick the highest priority missing test category (start with P0/Error handling).
7. Create the test case following the AAA (Arrange, Act, Assert) pattern.
   *Tip: Use the templates below for guidance.*
8. Run the specific test to verify it works.
9. Fix any bugs discovered by the new test.

# Phase 4: Verify Improvements

10. Run the full coverage report again.
    ```bash
    pytest tests/test_{module}.py --cov=app/{module} --cov-report=term-missing
    ```
11. Compare against the baseline and report the improvement to the user.

---

## Reference: Test Templates

### Happy Path
```python
def test_{function}_valid_input_returns_expected():
    """Test normal operation with valid inputs."""
    # Arrange
    input_data = create_valid_input()
    # Act
    result = function_under_test(input_data)
    # Assert
    assert result == expected_output
```

### Error Handling
```python
def test_{function}_invalid_input_raises_error():
    """Test error handling for invalid inputs."""
    # Arrange
    invalid_input = create_invalid_input()
    # Act & Assert
    with pytest.raises(ExpectedError) as exc_info:
        function_under_test(invalid_input)
    assert "expected message" in str(exc_info.value)
```

### Edge Case Checklist
- [ ] None/null inputs
- [ ] Empty collections
- [ ] Boundary values (0, -1, MAX_INT)
- [ ] Resource exhaustion/timeouts
