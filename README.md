# SteamBPF

**SteamBPF** stands for **SteamBypassFamilySharing**.

A Windows tool that patches two Steam client checks in memory and refreshes Steam's connection. Changes last until Steam exits; compatibility depends on the Steam version.

In theory, it may bypass the restriction that only one family member can play a game when the family owns a single copy. This behavior is not guaranteed. The second and any subsequent players should start Steam, open `SteamBPF.exe` as administrator, and click **RUN** before launching the game. The interface supports Chinese and English.

**Use at your own risk.** Although the changes are limited to Steam's process memory, this does not guarantee safety or freedom from account restrictions or other consequences. The author accepts no responsibility for any resulting issues, losses, or account penalties.

For build instructions, see [BUILD.md](BUILD.md).
