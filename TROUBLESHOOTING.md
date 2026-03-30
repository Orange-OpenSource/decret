# Python environment error: `AssertionError` when running `decret_auto.py`

## Error message example: 
```bash
ERROR: Exception: Traceback (most recent call last): 
...
File ".../pip/_internal/operations/install/wheel.py", line 618, in _install_wheel assert os.path.exists(pyc_path) AssertionError
```
##  When does this happen?
This error, can occur when running `decret_auto.py`.  
If there are some corrupted, old Python cache files in the virtual environment `(venv)`.

## How to fix:
If the `venv` folder is present, don't delete it.  
Instead, clean up the Python cache files and reactivate the environment: 
```bash 
find venv/ -name "*.pyc" -delete
find venv/ -name "__pycache__" -type d -exec rm -r {} +
deactivate
source venv/bin/activate
pip install -r requirements-minimal.txt
```

This should resolve the issue and allow you to run the script without errors.