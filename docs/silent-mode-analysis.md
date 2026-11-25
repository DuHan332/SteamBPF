# Silent-start artifact analysis

## Identity and scope

Source artifact: `低级家庭共享.exe`, 1,679,872 bytes, SHA-256 `0f93a6f68cdc4b304c7ef8c534bb610721feb9bb9615cab23cacfebc4e515b5c`.

This is a native x64 Windows PE. Analysis used pefile and Capstone without executing the artifact or contacting its server. REA tools and CLI were unavailable in this session. Addresses below refer to the preferred image base `0x140000000`; these are ordinary static-analysis observations, not REA Evidence IDs. The local investigation script and disassembly are kept outside the application repository in `target/inspection/`.

## Findings

| Question | Finding | Evidence |
| --- | --- | --- |
| Shared checks | The familiar two branch changes remain, with a longer context signature for the first check. | Rule construction at `0x1400281e7`–`0x140028285`; first branch offset 60, second offset 4. |
| Silent startup | A third contextual pattern targets `cmp dword ptr [r15+0x2cc],0; jne rel32`. | Rule pattern at `0x1400282c1`, patch offset 35. |
| All-games setting | User mode 2 selects the label “全游戏静默” and sets the all-games flag. Mode 3 disables silent startup; other modes can select an account. | Configuration resolver `0x1400279b0`, especially `0x140027a4d`–`0x140027a57`. |
| All-games implementation | The all-games path emits an unconditional jump to the original JNE destination. Other modes emit a longer trampoline that compares an AccountID. | `0x14002a416`–`0x14002a499`; filtered path continues through `0x14002a74f`. |
| Other patch types | Owner ID and Ownership patterns exist but start disabled in the rule inventory. Their presence does not prove default execution. | Initializer `0x14002834f`–`0x140028421`, enabled/required flags zero. |
| Recovery | The artifact stores original bytes and allocation information for restoration. | Bookkeeping at `0x140028560`; restore flow `0x140028b40`. |
| Network contribution | A separate routine reads local keys/tokens, fetches remote lists, and posts differences to `/api/keys` and `/api/tokens` under the embedded `api.993499094.xyz` base. | Routine at RVA `0x8b80`; endpoint references at `0x1400094b1` and `0x140009b70`, base URL at `0x14000126a`. |
| Other features | Local account discovery, offline/online URI refresh, cold-start/restart handling, and connection-log observation are present. | Account resolver `0x140027bc0`; references to `ActiveUser`, `loginusers.vdf`, Steam URIs and `connection_log.txt`. These paths were not reconstructed completely. |

## SteamBPF integration

The added **Silent start** option implements only the all-games branch behavior. It reuses the existing two shared checks, accepts the newer first-check context, and adds the contextual silent-start check. It does not execute, embed, or depend on the supplied EXE.

For the all-games path, SteamBPF emits a direct, same-destination jump plus padding in the original 14-byte instruction span. For account filtering it uses a separately generated trampoline described below. These are implementation choices, not claims of byte-for-byte reconstruction. Optional Owner ID/Ownership hooks are not implemented.

Every required pattern must match exactly once before any writes. The branch destination must remain in a scanned code section. Another tool's external trampoline is rejected; restart Steam before retrying. Selecting Standard and executing restores the recognizable direct silent-start patch, while retaining the two shared checks. Write failures attempt rollback. Steam exit removes these in-memory changes.

Account labels and IDs are read locally only when account selection is requested. No key/token extraction, cloud downloads, uploads, telemetry, or server calls are included. Steam itself may reconnect normally through the existing refresh action. UI progress remains based on execution phases and fixed refresh delays, not actual online-state detection.

## Account filtering

The artifact's resolver at `0x1400279b0` selects an AccountID from `ActiveUser` and locally saved users. Explicit selection is supported as well. Its code generation at `0x14002a49e`–`0x14002a763` implements this decision:

1. Execute the original `cmp dword ptr [r15+0x2cc],0`; preserve the original taken destination when nonzero.
2. Read the account field using `mov eax,[r15+0x204]` (`0x14002a513`).
3. When this value is zero or equals the selected AccountID, continue at the original fallthrough address.
4. Otherwise, use the original taken destination (the silent path).

The selected account is therefore retained on the normal path, rather than being the only account silenced. Interpreting the field as a game-owner AccountID follows the artifact's labeling and behavior; the exact Steam type is not independently recovered. Selecting an account does not log into it or change Steam credentials.

SteamBPF reads only the local `loginusers.vdf` list and `HKCU\Software\Valve\Steam\ActiveProcess\ActiveUser` for names and IDs. It accepts a manual AccountID or individual-user SteamID64 if the list is unavailable. No account information is uploaded or written to disk by the tool.

The filter is an independently generated 45-byte x64 trampoline allocated near the target, with a versioned 64-byte metadata header. The header binds the original bytes, selected ID, site, module base, and code length. Existing hooks are accepted only if their full generated code and header validate; unrelated hooks are rejected. Required signatures are validated before allocating or publishing a hook. New code is written and checked before the target branch is changed, then protected executable/read-only.

Changing accounts, selecting all-games silent mode, or returning to Standard verifies and replaces/restores the recognized hook. Detached code allocations are retained until Steam exits, rather than freed while another thread may still be executing them; repeated changes consume one small allocation per newly generated filter. Failed writes attempt to restore prior bytes. Unpublished allocations are released on failure.

## Cold start

The artifact's routine at `0x140025b50` first attempts a patch when Steam is running. If that does not complete, it sends `steam://exit` at `0x140025c29`, waits up to about 20 seconds, and may forcibly terminate `steamwebhelper.exe` and `steam.exe`. It launches through the desktop shell, with a user-token fallback at `0x140025810` (`OpenProcessToken`, `DuplicateTokenEx`, `CreateProcessWithTokenW` at `0x140025adf`). It then waits for Steam and repeatedly invokes the patch routine at `0x140026079` and `0x1400260b6`.

SteamBPF's explicit Cold start option always starts a fresh Steam process. It verifies the installed executable first, requests a graceful exit if needed, waits up to 20 seconds, launches `steam.exe` using the interactive shell user's duplicated token, and waits up to 60 seconds for the x64 client module. The selected account is resolved before restart. It does not inherit the tool's administrator token, force-kill Steam/helpers, terminate games, edit autologin settings, or bypass Steam login. A graceful-exit timeout is reported so the user can close games and Steam first. If Steam is initially stopped, it starts it directly.

This narrower startup implementation intentionally omits the artifact's forced-termination fallback. Module discovery is a necessary startup readiness check, not an online/login-state check. Applying immediately after module discovery does not guarantee completion before Steam's automatic login; that timing remains unverified. No cold start was performed on the user's Steam during development.

Implementation references: [CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw) defines launching in the supplied primary token's security context and its privilege requirements; [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) defines target-process allocation and address alignment. These API contracts do not establish successful runtime behavior for this tool.

## Validation and limitations

Offline tests cover destination preservation, account-filter branch destinations, identifier conversion, local account-file parsing, metadata validation, account changes/restoration, graceful startup ordering/timeouts, repeat application, missing/duplicate patterns, unrelated trampoline rejection, legacy signatures, rollback, and bilingual UI mode selection. The artifact and actual Steam memory were not executed or modified during verification. The meaning and behavior of these Steam checks on a particular Steam build cannot be confirmed without that build and runtime verification. A matching signature does not guarantee the intended sharing or silent-start behavior.
