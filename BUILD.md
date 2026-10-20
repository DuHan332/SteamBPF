# Building SteamBPF

## Requirements

- Windows x64.
- 64-bit Python 3. The local packaging tools were installed using Python 3.12.
- PyInstaller and its dependencies in `packaging/build-tools/`.

## Build command

Generated files and local packaging dependencies are excluded from Git. After cloning, restore the packaging tools with your 64-bit Python interpreter:

```powershell
python -m pip install --target packaging/build-tools -r packaging/requirements-build.txt
```

Run from the project directory:

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

The script first looks for the existing Codex Python runtime on this machine, then falls back to `python` on PATH. To select an interpreter explicitly:

```powershell
.\build.ps1 -PythonExe 'C:\Python312\python.exe'
```

Output: `dist/SteamBPF.exe`. The executable uses a windowed interface and requests administrator privileges at startup.

## Build inputs

- `steambpf.py`: core logic.
- `steambpf_gui.py`: graphical interface and translations.
- `packaging/build-tools/`: PyInstaller and dependencies.
- `build.ps1`: packaging script.

Build intermediates and caches are generated in `build/` and can be recreated. A different Python version or machine may require compatible packaging dependencies to be reinstalled. The original executable and reverse-engineering artifacts are not needed for packaging.
