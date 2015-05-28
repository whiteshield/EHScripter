#!/usr/bin/env python3
# -*- coding: utf-8 -*-

try:
    import EHScripter
except ImportError:
    print("\n[CAUTION] EHScripter is not found")
except:
    raise
    exit(1)

try:
    import io
except ImportError:
    print("\n[CAUTION] io is not found")
except:
    raise
    exit(1)

try:
    import yaml
except ImportError:
    print("\n[CAUTION] yaml (pyyaml) is not found")
except:
    raise
    exit(1)

try:
    import tkinter
except ImportError:
    print("\n[CAUTION] tkinter is not found")
except:
    raise
    exit(1)

try:
    import unicodedata
except ImportError:
    print("\n[CAUTION] unicodedata is not found")
except:
    raise
    exit(1)

try:
    from lxml import etree
except ImportError:
    print("\n[CAUTION] lxml.etree is not found")
except:
    raise
    exit(1)

try:
    import pygal
except ImportError:
    print("\n[CAUTION] pygal is not found")
except:
    raise
    exit(1)

try:
    import cairosvg
except ImportError:
    print("\n[CAUTION] cairosvg is not found")
except:
    raise
    exit(1)

try:
    import cssselect
except ImportError:
    print("\n[CAUTION] cssselect is not found")
except:
    raise
    exit(1)

try:
    import tinycss
except ImportError:
    print("\n[CAUTION] tinycss is not found")
except:
    raise
    exit(1)

try:
    import html2text
except ImportError:
    print("\n[CAUTION] html2text is not found")
except:
    raise
    exit(1)


app = EHScripter.EHScripterApplication()
app.mainloop()
exit(0)
