from random import choices
from string import ascii_lowercase, digits, ascii_uppercase

results = []
for i in range(0, 100):
    characters = ascii_lowercase + digits + ascii_uppercase
    results.append(f"\"{''.join(choices(characters, k=i))}\"")

print(f"[{', '.join(results)}]")
