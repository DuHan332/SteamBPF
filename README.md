# SteamBPF

**SteamBPF** stands for **SteamBypassFamilySharing**.

A Windows tool that loads an independently built module into Steam to adjust family-sharing checks and filter selected game-status messages. Changes last until Steam exits; compatibility depends on the Steam version.

Click **RUN** to enable sharing protection. Check **Silent mode** to additionally filter game-status messages. **Cold start** gracefully restarts Steam before loading the module. The interface supports Chinese and English. No key/token extraction, cloud synchronization, or uploads are included. See [the native module notes](docs/native-module.md) for scope and limitations.

In theory, it may bypass the restriction that only one family member can play a game when the family owns a single copy. This behavior is not guaranteed. The second and any subsequent players should open `SteamBPF.exe` as administrator and click **RUN** before launching the game. Live Steam compatibility has not been verified.

**Use at your own risk.** Although the changes are limited to Steam's process memory, this does not guarantee safety or freedom from account restrictions or other consequences. The author accepts no responsibility for any resulting issues, losses, or account penalties.

For build instructions, see [BUILD.md](BUILD.md).
