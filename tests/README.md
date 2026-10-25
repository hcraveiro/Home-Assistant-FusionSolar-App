# Testing and coverage

Run all tests locally with:

```bash
python -m pip install -r requirements-test.txt
python -m pytest tests -v --cov=custom_components/fusion_solar_app --cov-report=term-missing
```

The CI runs all `tests/test_*.py` discovered by pytest, including `unittest` tests, and fails on any failure, collection error, zero collected tests, or overall coverage below **2%**.

**Initial measurement:** 23 passing tests and approximately **3%** overall integration line coverage on Python 3.13. The intentionally low minimum is a *baseline guard*, **not** an adequate production-quality target. It must be raised with new behavioral tests, especially authentication, CAPTCHA, session renewal, installation discovery, sensor state and config flows. Most existing tests compile selected functions from AST nodes rather than importing and exercising the running integration; consequently coverage is low despite green tests.

`coverage.xml` and `test-results.xml` are uploaded by the workflow to support further reporting. GitHub branch protection must separately require the **PV discovery regression tests** check on `main` if merging should be blocked by failing CI.
