import os
import json


downloads_path = os.path.join(os.path.expanduser("/Users/ayasantandreu/"), "Downloads")
input_filename = "100k-most-used-passwords-NCSC.txt"
input_path = os.path.join(downloads_path, input_filename)

output_path = "passwords_50k.json"

passwords_list = []

try:
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as infile:
        for i in range(50000):
            line = infile.readline()
            if not line:
                break
            passwords_list.append(line.strip())


    with open(output_path, 'w', encoding='utf-8') as outfile:
        json.dump(passwords_list, outfile, indent=4, ensure_ascii=False)
    
    print(f"Success! Created {output_path} with {len(passwords_list)} passwords.")

except FileNotFoundError:
    print(f"Error: Could not find the file at {input_path}")