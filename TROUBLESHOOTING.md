# Firefox environment error: InvalidArgumentException when running tests

## Error message example
````bash
selenium.common.exceptions.InvalidArgumentException: Message: binary is not a Firefox executable
````

## When does this happen?
This error can occur when running DECRET, or its tests (for example, with `pytest` command) if Firefox was installed with `Snap` or if the wrong Firefox binary is being used.  
It often happens when:  
- Firefox is installed with `Snap` instead of `apt`.
- Multiple Firefox installations are present on the system (for example, both `snap` and `apt` versions installed at the same time).
- There are conflicting Firefox installations.  

Having more than one Firefox installation  can cause conflicts and lead to this error.

## How to fix
Don’t reinstall Selenium or try other installations!
Instead, clean up your Firefox installation and make sure you’re using the correct version:
```bash
sudo snap remove firefox
sudo apt update
sudo apt install firefox-esr
snap list | grep firefox # Should display nothing...
apt list --installed | grep firefox
```  

After following the steps above, you can check that everything works by running: `pytest`
