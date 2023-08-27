import json
import ida_dbg
import ida_bytes
import idaapi

path = idaapi.ask_file(False, '.json', 'POI file')
with open(path, 'r') as json_poi:
    data = json.load(json_poi)

poi_counter = 0
for poi in data:
    type = poi["poi_type"]
    address = int(poi["address"], 16)
    details = f"{type}:{poi['confidence_score']} - {poi['extractor']} - {poi['details']}"

    try:
        ida_dbg.add_bpt(address, 0, 4)
        ida_dbg.disable_bpt(address)

        ida_bytes.set_cmt(address, details, True)
    except Exception as E:
        print("Could not set POI. Are the address ranges valid?", E)
        poi_counter += 1

print(f"Could successfully set {poi_counter} of {len(data)} POIs")
