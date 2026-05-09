"""
remove_emojis.py — Strips all emoji characters from frontend and Python source files.
Replaces common emojis with clean text/symbol equivalents.
"""
import re, os
from pathlib import Path

FRONTEND = Path(r'd:\project_related\CloudSentinel_AI\modules\frontend')
CLOUD    = Path(r'd:\project_related\CloudSentinel_AI\modules\cloud-infra')
ROOT     = Path(r'd:\project_related\CloudSentinel_AI')

# Targeted replacements: emoji -> clean alternative
REPLACEMENTS = [
    # Security / Lock
    ('🔒', '[SECURE]'), ('🔓', '[UNLOCKED]'), ('🔑', '[KEY]'), ('🛡', '[SHIELD]'),
    # Status / Indicators
    ('✅', '[OK]'),  ('❌', '[X]'), ('⚠️', '[!]'), ('⚠', '[!]'), ('ℹ️', '[i]'),
    ('✓', 'OK'), ('✗', 'X'),
    # Clouds / Tech
    ('☁️', ''), ('☁', ''), ('⚙️', ''), ('⚙', ''),
    ('🌐', ''), ('📱', ''), ('📊', ''), ('🚀', ''),
    ('🌙', ''), ('☀️', ''), ('☀', ''),
    # Arrows
    ('→', '->'), ('←', '<-'), ('↑', '^'), ('↓', 'v'), ('↗', '->'), ('↘', '->'),
    ('➡', '->'), ('⬅', '<-'), ('⬆', '^'), ('⬇', 'v'),
    ('▶', '>'), ('◀', '<'), ('▼', 'v'), ('▲', '^'),
    # Numbers / bullets
    ('①', '1.'), ('②', '2.'), ('③', '3.'), ('④', '4.'), ('⑤', '5.'),
    ('•', '-'), ('·', '-'),
    # Misc common
    ('🔴', '[HIGH]'), ('🟡', '[MED]'), ('🟢', '[LOW]'),
    ('📌', '-'), ('📋', ''), ('📝', ''), ('💡', ''),
    ('🎯', ''), ('⭐', '*'), ('🏆', ''), ('🎉', ''),
    ('🤖', 'AI'), ('🧠', 'AI'),
    ('⏱', '[TIMER]'), ('⏰', '[TIMER]'), ('🕐', '[TIME]'),
    ('✉️', '[MAIL]'), ('✉', '[MAIL]'), ('📧', '[EMAIL]'),
    ('🔧', ''), ('🔨', ''), ('🛠', ''),
    ('💬', ''), ('💭', ''),
    ('⚡', ''), ('🔥', ''),
    ('\u2019', "'"),   # right single quote -> apostrophe
    ('\u2014', '--'),  # em dash
    ('\u2013', '-'),   # en dash
    ('\u2022', '-'),   # bullet
    ('\u25cf', '-'),   # filled circle
    ('&bull;', '-'),   # HTML bullet entity
    ('&mdash;', '--'), # HTML em dash
    ('&ndash;', '-'),  # HTML en dash
    ('&rarr;', '->'),  # HTML right arrow
    ('&larr;', '<-'),  # HTML left arrow
    ('&uarr;', '^'),   # HTML up arrow
    ('&#9993;', '[MAIL]'),   # envelope
    ('&#128273;', '[KEY]'),  # key
    ('&#10005;', 'X'),       # X mark
    ('&#10148;', '->'),      # arrow
    ('&#8594;', '->'),       # right arrow
    ('&#8592;', '<-'),       # left arrow
]

# Regex to catch any remaining unicode emoji in range U+1F300 to U+1FFFF and common symbol ranges
EMOJI_RE = re.compile(
    '[\U0001F300-\U0001FFFF'   # Misc symbols and pictographs
    '\U00002600-\U000027BF'    # Misc symbols
    '\U0001F900-\U0001F9FF'    # Supplemental symbols
    '\U00002300-\U000023FF'    # Misc technical
    '\U00002B50-\U00002B55'    # Stars
    '\U00002702-\U000027B0'    # Dingbats
    ']+'
)

EXTS = {'.html', '.css', '.js', '.py', '.md', '.txt', '.json'}

changed_files = []

def clean(text):
    for emoji, replacement in REPLACEMENTS:
        text = text.replace(emoji, replacement)
    # Strip any remaining emoji-range chars
    text = EMOJI_RE.sub('', text)
    return text

dirs = [FRONTEND, CLOUD]

for d in dirs:
    for fpath in d.rglob('*'):
        if fpath.is_dir() or fpath.suffix.lower() not in EXTS:
            continue
        try:
            original = fpath.read_text(encoding='utf-8')
        except Exception:
            try:
                original = fpath.read_text(encoding='latin-1')
            except Exception as e:
                print(f'  [SKIP] {fpath.name}: {e}')
                continue
        cleaned = clean(original)
        if cleaned != original:
            fpath.write_text(cleaned, encoding='utf-8')
            diff = sum(1 for a, b in zip(original, cleaned) if a != b)
            print(f'  [CLEANED] {fpath.relative_to(ROOT)}  ({diff} chars changed)')
            changed_files.append(str(fpath))
        else:
            print(f'  [clean]   {fpath.relative_to(ROOT)}')

# Also clean deploy_console.py and chatbot_handler.py
for extra in [ROOT / 'deploy_console.py', CLOUD / 'chatbot_handler.py']:
    if extra.exists():
        original = extra.read_text(encoding='utf-8')
        cleaned  = clean(original)
        if cleaned != original:
            extra.write_text(cleaned, encoding='utf-8')
            print(f'  [CLEANED] {extra.relative_to(ROOT)}')
            changed_files.append(str(extra))

print()
print(f'Done. {len(changed_files)} files modified.')
