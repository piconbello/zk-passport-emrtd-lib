import duckdb
import json
import base64
import struct

# First, read the JSON file
with open('files/masterlist_284.json', 'r') as f:
    data = json.load(f)

# Create a table from the data
query = """
WITH json_data AS (
    SELECT *
    FROM data
)
SELECT
    pubkey->>'exponent' as exponent,
    COUNT(*) as count
FROM json_data
WHERE pubkey->>'type' = 'RSA'
GROUP BY pubkey->>'exponent'
ORDER BY count DESC;
"""

# Execute the query
result = duckdb.sql(query)
print("\nExponent distribution:")
print(result.df())

# To also show the actual decimal values of the exponents
def b64_to_int(b64_str):
    try:
        decoded = base64.b64decode(b64_str)
        # Convert bytes to integer
        return int.from_bytes(decoded, 'big')
    except:
        return None

print("\nDecimal values of exponents:")
for row in result.fetchall():
    b64_exp = row[0]
    count = row[1]
    decimal_value = b64_to_int(b64_exp)
    print(f"Base64: {b64_exp}, Decimal: {decimal_value}, Count: {count}")
