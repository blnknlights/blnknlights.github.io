# -- Project information -----------

project = "blnkn"
copyright = "2023, blnkn"
author = "blnkn"

# -- General configuration ---------

templates_path = ["_templates"]
extensions = [
    "sphinxcontrib.googleanalytics",
    "myst_parser",
    "sphinx_favicon"
]
exclude_patterns = [
    "htb/machines/hard/gofer/gofer*",
    "htb/machines/hard/mailroom/mailroom*",
    "htb/machines/hard/intensions/intensions*",
    "htb/ctf/*"
]

# -- Options for HTML output -------

html_static_path = ["_static"]
html_theme = "furo"
html_logo = "img/lazer_fox.png"
html_title = "blnkn's notes"

# -- Options for favicon -----------
favicons = ["lazer_fox.png"]

# -- Options for Google Analytics --
googleanalytics_id = 'G-2TCTE0JE23'
