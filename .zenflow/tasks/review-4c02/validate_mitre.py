import re
from pathlib import Path

# Known valid MITRE ATT&CK for ICS techniques
valid_techniques = {
    'T0800', 'T0801', 'T0802', 'T0803', 'T0804', 'T0805', 'T0806', 'T0807', 'T0808', 'T0809',
    'T0810', 'T0811', 'T0812', 'T0813', 'T0814', 'T0815', 'T0816', 'T0817', 'T0818', 'T0819',
    'T0820', 'T0821', 'T0822', 'T0823', 'T0824', 'T0825', 'T0826', 'T0827', 'T0828', 'T0829',
    'T0830', 'T0831', 'T0832', 'T0833', 'T0834', 'T0835', 'T0836', 'T0837', 'T0838', 'T0839',
    'T0840', 'T0841', 'T0842', 'T0843', 'T0844', 'T0845', 'T0846', 'T0847', 'T0848', 'T0849',
    'T0850', 'T0851', 'T0852', 'T0853', 'T0854', 'T0855', 'T0856', 'T0857', 'T0858', 'T0859',
    'T0860', 'T0861', 'T0862', 'T0863', 'T0864', 'T0865', 'T0866', 'T0867', 'T0868', 'T0869',
    'T0870', 'T0871', 'T0872', 'T0873', 'T0874', 'T0875', 'T0876', 'T0877', 'T0878', 'T0879',
    'T0880', 'T0881', 'T0882', 'T0883', 'T0884', 'T0885', 'T0886', 'T0887', 'T0888', 'T0889',
    'M0800', 'M0801', 'M0802', 'M0803', 'M0804', 'M0805', 'M0806', 'M0807', 'M0808', 'M0809',
    'M0810', 'M0811', 'M0812', 'M0813', 'M0814', 'M0815', 'M0816', 'M0817', 'M0818', 'M0819'
}

# Find all MITRE technique references
techniques = set()
base_path = Path('../../../')
for path in base_path.rglob('*'):
    if path.is_file() and path.suffix in ['.py', '.md', '.rules', '.zeek']:
        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
            matches = re.findall(r'[TM]0\d{3}', content)
            techniques.update(matches)
        except:
            pass

# Validate
invalid = techniques - valid_techniques
valid = techniques & valid_techniques

print(f'Total unique techniques found: {len(techniques)}')
print(f'Valid techniques: {len(valid)}')
print(f'Invalid techniques: {len(invalid)}')
if invalid:
    print(f'Invalid: {sorted(invalid)}')
else:
    print('✓ All MITRE techniques are valid!')

# Print statistics
print(f'\nMost referenced techniques:')
technique_counts = {}
base_path = Path('../../../')
for path in base_path.rglob('*'):
    if path.is_file() and path.suffix in ['.py', '.md', '.rules', '.zeek']:
        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
            matches = re.findall(r'[TM]0\d{3}', content)
            for t in matches:
                technique_counts[t] = technique_counts.get(t, 0) + 1
        except:
            pass

for t, count in sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f'  {t}: {count} references')
