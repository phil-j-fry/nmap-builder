from pathlib import Path
import json,sys
d=Path(__file__).resolve().parent
# Embedded data: '</' is escaped so text such as '</script>' inside it cannot end the script element.
data=lambda s:s.replace('</','<\\/')
script=('const CATALOG='+data(json.dumps((d/'catalog.txt').read_text()))+';\n'
  +'const STARTER_DATA='+data(json.dumps(json.loads((d/'tests'/'fixtures'/'ccsf-examples.json').read_text()),indent=1,ensure_ascii=False))+';\n'
  +'\n'.join((d/f).read_text() for f in ('core.js','library.js','ui.js')))
fragment=(d/'view.html').read_text()+'<script>\n'+script+'\n</script>\n'
(d/'index.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Nmap command workbook</title><body>'+fragment+'</body></html>')
if len(sys.argv)>1:Path(sys.argv[1]).write_text(fragment)
