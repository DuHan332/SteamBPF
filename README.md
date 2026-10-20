# SteamBPF

**SteamBPF** stands for **SteamBypassFamilySharing**, a local tool that modifies Steam client checks associated with Family Sharing.

## How it works

The tool locates the running `steam.exe` process and its loaded `steamclient64.dll`. It searches executable memory for specific instruction patterns and replaces two conditional jumps with unconditional jumps, changing the execution paths of the corresponding client checks. Changes affect process memory only: Steam files on disk remain unchanged, and the patches disappear when Steam exits.

It then attempts to disconnect TCP connections owned by Steam and invokes Steam's online and library URIs. These commands are repeated after fixed delays to trigger a client refresh. The progress bar follows the operation sequence and delays; it does not check whether Steam is actually online.

Compatibility and the meaning of the affected checks depend on the Steam version. Matching instruction patterns does not guarantee the intended Family Sharing behavior. The tool does not extract keys or tokens or synchronize data with a cloud service.

## Usage

1. Start Steam.
2. Open `SteamBPF.exe` and allow administrator access.
3. Click **RUN** and wait for the progress bar to finish.

Use the control in the upper-right corner to switch between Chinese and English. The packaged executable does not require Python to be installed.

## Run from source

Requires Windows x64 and 64-bit Python 3:

```powershell
python steambpf_gui.py
```

## Build

```powershell
.\build.ps1
```

Output: `dist/SteamBPF.exe`. See [BUILD.md](BUILD.md) for dependencies and selecting a Python interpreter.

## Project files

- `steambpf.py`: process discovery, memory patching, and refresh logic.
- `steambpf_gui.py`: bilingual console interface.
- `build.ps1`: Windows executable build script.
- `packaging/build-tools/`: local packaging dependencies.
