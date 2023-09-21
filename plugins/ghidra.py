#Importing POIs from POI analyzer output (poi.json)
#@author Maximilian Gehring, August See
#@category Binary-Analyzer
#@keybinding 
#@menupath 
#@toolbar

import json
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address


class AddBookmarksFromJson(GhidraScript):
    def run(self):
        # Prompt the user to select a JSON file
        json_file = askFile("Select JSON File", "Select")
        
        if json_file:
            try:
                with open(json_file.getAbsolutePath(), 'r') as file:
                    data = json.load(file)
                    program = getCurrentProgram()

                    for entry in data:
                        if "address" in entry:
                            address = entry["address"]
                            cs = entry["confidence_score"]
                            extr = entry["extractor"]
                            details = entry["details"]
                            
                            if address:
                                comment = address + ": " + cs  + " - " + extr + " - " + str(details)
                                bm = program.getBookmarkManager()
                                address = toAddr(address)
                                bm.setBookmark(address, "Analysis", "POI",  comment)
                                print("Added bookmark at", address, "with message:",  comment)
                            else:
                                print("Invalid address:", address)
                        else:
                            print("Invalid JSON entry.")
            except Exception as e:
                print("Error:", e)

# Create and run the script
script = AddBookmarksFromJson()
script.run()