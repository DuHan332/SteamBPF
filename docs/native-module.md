# Native module backend

SteamBPF now builds its own `SteamBPFHook.dll`. The supplied executable and its embedded DLL are analysis inputs only and are not build inputs or distributed payloads.

The controller finds `steamclient64.dll` in `steam.exe`, or in a unique `steamwebhelper.exe` when the main client does not host it. It verifies the packaged module's SHA-256, writes a persistent per-hash cache, checks the target architecture, and loads the DLL using the target's system loader address. Existing incompatible modules require a Steam restart. Injection timeouts never terminate a target thread.

The native worker validates unique executable-section signatures before installing MinHook interceptors for frame sends, UDP sends, packet receives, ownership checks, and the family subscription query. The hooks remain inactive until the controller sends one atomic configuration. An initialization failure is reported instead of successful completion. Configurations travel over a per-process, local-only named pipe whose server PID is checked by the controller. Its ACL permits the process user, SYSTEM, and administrators.

## Implemented behavior

- Sharing protection adjusts the recognized ownership result and family subscription query and removes `running_apps` records from `FamilyGroupsClient.NotifyRunningApps#1` notifications.
- The Silent mode checkbox additionally removes game records from protobuf game-status messages 742 and 5410. It preserves the envelope, unknown fields, and non-game fields, including empty status updates. It does not claim to hide every possible Steam activity signal.
- Unchecking Silent mode and clicking RUN stops future outgoing filtering. It does not replay previously filtered messages or reconstruct presence state.
- Cold start requests a graceful exit, aborts after 20 seconds if Steam remains, launches as the desktop user, and waits up to 90 seconds for the client module. There is no TCP disconnection or online-state polling.

The GUI reaches 100% after the module acknowledges configuration. This is not verification of Steam's online state or a successful sharing bypass. The module stays loaded until its host exits. The control protocol is version 2; after upgrading, restart Steam to clear the earlier module. After changing from the old backend, restart Steam once to clear existing patches.

## Evidence and boundaries

The reconstruction is based on the 2.0.1.0 sample with SHA-256 `fd7099a03e2a72a4f1d3c0d6047b2ae56784ad08d7fff50e916d5d1e04785fd4`. Hook signatures, argument use, ownership result offsets, packet-view offsets, and message IDs were derived from static instructions in that sample. The independent wire reader validates lengths, varints, nested records, and the exact notification method; malformed or unsupported messages pass through.

Protocol field numbers were cross-checked against [SteamDatabase/Protobufs](https://github.com/SteamDatabase/Protobufs/tree/d41b3f85c231c5f52b4b2984a817da68c4f91e67/steam): `CMsgClientGamesPlayed.games_played=1`, `GamePlayed.owner_id=12`, `CMsgProtoBufHeader.target_job_name=12`, and `CFamilyGroupsClient_NotifyRunningApps_Notification.running_apps=2`. Unknown fields are preserved byte for byte.

This is a focused independent reconstruction, not a claim of complete equivalence to the original DLL. The original's custom naming, transport selection overrides, auxiliary stop acknowledgements, and delayed notification resends are not reproduced. No original binary code or protobuf runtime is linked. Signature coverage is intentionally conservative. Live Steam compatibility, ownership structure stability, asynchronous buffer lifetimes, and the complete effect on sharing restrictions still require runtime validation. Offline tests do not establish these properties.

MinHook 1.3.4 is vendored from [TsudaKageyu/minhook](https://github.com/TsudaKageyu/minhook/tree/c3fcafdc10146beb5919319d0683e44e3c30d537), with its license included in the executable bundle. Generated native binaries, compiler dependencies, and packaging output are excluded from Git.

No key extraction, application-token extraction, original server authorization, cloud list download, upload, or automatic network synchronization is implemented. The module has no HTTP or socket client of its own; it processes selected buffers passed through Steam's existing calls.
