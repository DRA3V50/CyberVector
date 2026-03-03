import sys

if len(sys.argv) < 2:
    print("Usage: python3 log_parser.py <logfile>")
    sys.exit(1)

file = sys.argv[1]

with open(file) as f:
    lines = f.readlines()

print(f"Total Lines: {len(lines)}")
print("First 5 Lines:")
for line in lines[:5]:
    print(line.strip())
