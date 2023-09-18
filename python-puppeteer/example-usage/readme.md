This is an example without malware to try the tool.

The binary is compiled for 32bit, but runs on Windows 10 and 11 64 bit. It takes user input and xored it with a key. Then it takes input and xored output. The source can be seen in main.c.

First you have to start the binary with intel pin.
We already provide a pin binary here. Otherwise this is tested under pin 1.19.

Here the command and the output of the binary:

```
pin.exe -t .\PuppeteeringPintool32.dll -trace exampleAppTrace -ins_log exampleAppInsLog -- .\testapp-O032.exe
Enter a string: helloacsacfrombinary
Original string: helloacsacfrombinary
Original string as Hex: 68 65 6C 6C 6F 61 63 73 61 63 66 72 6F 6D 62 69 6E 61 72 79 00
XORed string:   

XORed string as Hex: 09 06 1F 0D 0C 00 00 00 00 00 07 11 1C 0C 01 08 0D 12 13 1A 00
```
Goal:
Identify location of encryption function.

We have the following data that are interesting and we want to trace:
Ciphertext: `09 06 1F 0D 0C 00 00 00 00 00 07 11 1C 0C 01 08 0D 12 13 1A 00`


Command to analyze the POIs (executed from `python-puppeteer`). We take only the first 4 bytes here:
`python -m puppeteering.poi.memory_pattern_extractor add 09061f0d ciphertext file D:\files\acsac-submission\src\python-puppeteer\example-usage\exampleAppTrace.24276 1 exampleAppPois.json examplePoisDetails.log`

Using the instruction log exclude POIs that are located in known modules, e.g, *ntdll.dll*.
Here the anotated `./example-results/testpois.json`
```json
[
    {
        "poi_type": "MemoryPoi",
        "address": "0x76c4dff0", // This POI is located in a Windows Module. Thus likely not interesting
        "confidence_score": "36/104 ",
        "extractor": "CLIContiguousPoiExtractor",
        "details": "r"
    },
    {
        "poi_type": "MemoryPoi",
        "address": "0x192ac6", // General purpose puts function (confirmed via disassembler)
        "confidence_score": "26/25 ",
        "extractor": "CLIContiguousPoiExtractor",
        "details": "r"
    },
    {
        "poi_type": "MemoryPoi",
        "address": "0x19167a", // PrintHex function (confirmed via disassembler)
        "confidence_score": "10/42 ",
        "extractor": "CLIContiguousPoiExtractor",
        "details": "r"
    },
    {
        "poi_type": "MemoryPoi",
        "address": "0x191651", // XorWithKey function (confirmed via disassembler). Further, it is the only function that writes bytes (details: w)
        "confidence_score": "4/20 ",
        "extractor": "CLIContiguousPoiExtractor",
        "details": "w"
    }
]
```
