"""Local account labels and the independently reconstructed account filter."""
from dataclasses import dataclass
from pathlib import Path
import re
import struct
import winreg

STEAM_ID_BASE = 76561197960265728
MAGIC = b'SBPFAC01'
HEADER = struct.Struct('<8sQQII14s18x')
CODE_SIZE = 45
BLOCK_SIZE = HEADER.size + CODE_SIZE

def account_id(value):
    value = int(str(value).strip())
    if STEAM_ID_BASE < value <= STEAM_ID_BASE + 0xffffffff:
        value -= STEAM_ID_BASE
    if not 0 < value <= 0xffffffff:
        raise ValueError('Invalid AccountID or SteamID64')
    return value

def steam_directory():
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Valve\Steam') as key:
        try:
            path = Path(winreg.QueryValueEx(key, 'SteamPath')[0])
        except FileNotFoundError:
            path = Path(winreg.QueryValueEx(key, 'SteamExe')[0]).parent
    return path

def parse_vdf(text):
    """Parse bounded quoted KeyValues, preserving Unicode and escaped quotes."""
    tokens = []
    pattern = re.compile(r'\s+|//[^\r\n]*|"((?:\\.|[^"\\])*)"|([{}])')
    position = 0
    for match in pattern.finditer(text):
        if text[position:match.start()].strip():
            raise ValueError('Unsupported account-file syntax')
        position = match.end()
        if match.group(1) is not None:
            value = re.sub(r'\\([\\"])', lambda m: m.group(1), match.group(1))
            tokens.append(('string', value))
        elif match.group(2):
            tokens.append((match.group(2), match.group(2)))
    if text[position:].strip():raise ValueError('Unsupported account-file syntax')
    index = 0
    def object_value(depth=0):
        nonlocal index
        if depth > 16:raise ValueError('Account-file nesting limit exceeded')
        result = {}
        while index < len(tokens) and tokens[index][0] != '}':
            kind, key = tokens[index];index += 1
            if kind != 'string' or index >= len(tokens):raise ValueError('Invalid account file')
            kind, value = tokens[index];index += 1
            if kind == '{':
                value = object_value(depth+1)
                if index >= len(tokens) or tokens[index][0] != '}':raise ValueError('Invalid account file')
                index += 1
            elif kind != 'string':raise ValueError('Invalid account file')
            result[key] = value
        return result
    result = object_value()
    if index != len(tokens):raise ValueError('Invalid account file')
    return result

@dataclass(frozen=True)
class Account:
    id: int
    label: str
    current: bool = False

def local_accounts(directory=None):
    """Read only account labels/IDs, never passwords, keys, or session tokens."""
    directory = Path(directory) if directory is not None else steam_directory()
    active = 0
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Valve\Steam\ActiveProcess') as key:
            active = int(winreg.QueryValueEx(key, 'ActiveUser')[0])
    except OSError:pass
    accounts = []
    path = directory / 'config' / 'loginusers.vdf'
    try:
        with path.open('rb') as stream:data = stream.read(4*1024*1024+1)
    except FileNotFoundError:data = b''
    if len(data) > 4*1024*1024:raise ValueError('Account file is too large')
    users = parse_vdf(data.decode('utf-8-sig')).get('users', {}) if data else {}
    if not isinstance(users, dict):raise ValueError('Invalid account list')
    for identifier, fields in users.items():
        if not isinstance(fields, dict):continue
        try:identifier = account_id(identifier)
        except (ValueError,TypeError):continue
        name = fields.get('PersonaName') or fields.get('AccountName') or str(identifier)
        if not isinstance(name,str):name = str(identifier)
        name = ''.join(c for c in name if c.isprintable())[:64]
        current = identifier == active or not active and fields.get('MostRecent') == '1'
        accounts.append(Account(identifier, name, current))
    if active and not any(a.id == active for a in accounts):
        accounts.append(Account(account_id(active), str(active), True))
    return sorted(accounts, key=lambda a:(not a.current,a.label.casefold(),a.id))

def filter_code(site, entry, original, selected):
    """Keep original flow for the selected account or account zero; silence others."""
    selected = account_id(selected)
    if len(original) != 14 or original[:10] != bytes.fromhex('41 83 BF CC 02 00 00 00 0F 85'):
        raise ValueError('Unexpected account-filter branch')
    fallthrough = site+14
    taken = fallthrough+struct.unpack('<i',original[10:])[0]
    result = bytearray(original[:8])
    def branch(opcode, destination):
        result.extend(opcode)
        result.extend(struct.pack('<i',destination-(entry+len(result)+4)))
    branch(b'\x0f\x85', taken)
    result.extend(bytes.fromhex('41 8B 87 04 02 00 00 85 C0'))
    branch(b'\x0f\x84', fallthrough)
    result.extend(b'\x3d'+struct.pack('<I',selected))
    branch(b'\x0f\x84', fallthrough)
    branch(b'\xe9', taken)
    assert len(result) == CODE_SIZE
    return bytes(result)

def filter_block(site, module_base, allocation, original, selected):
    code = filter_code(site,allocation+HEADER.size,original,selected)
    return HEADER.pack(MAGIC,site,module_base,account_id(selected),len(code),original)+code

def inspect_block(blob, site, module_base, allocation):
    if len(blob) != BLOCK_SIZE:raise ValueError('Unsupported account patch')
    magic,saved_site,saved_base,selected,length,original = HEADER.unpack(blob[:HEADER.size])
    if (magic,saved_site,saved_base,length) != (MAGIC,site,module_base,CODE_SIZE):
        raise ValueError('Unsupported account patch')
    if blob[HEADER.size:] != filter_code(site,allocation+HEADER.size,original,selected):
        raise ValueError('Unsupported account patch')
    return original,selected
