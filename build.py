from pathlib import Path
import json,sys
d=Path(__file__).resolve().parent
script='const CATALOG='+json.dumps((d/'catalog.txt').read_text())+';\n'+(d/'core.js').read_text()+'\n'+(d/'ui.js').read_text()
fragment=(d/'view.html').read_text()+'<script>\n'+script+'\n</script>\n'
(d/'index.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Nmap command workbook</title><body>'+fragment+'</body></html>')
if len(sys.argv)>1:Path(sys.argv[1]).write_text(fragment)
