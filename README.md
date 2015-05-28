#EHScripter

Ethical Hacking Scripter - Python3 GUI converter and docx/odt generator for ethical hacking.

Input formats:
- Nessus 
- Burp 
- Acunetx
- any markdown file

Output formats:
- docx
- odt


#Steps - How to use it

1. Create a docx/odt with some default formatting (like headings, captions)
2. Convert to Nessus/Burp/Acunetix to markdown with EHScripter
3. Manually edit the results (if needed)
4. Add findings like the converted ones
5. Convert to docx or odt with EHScripter
6. Open result in office and click through the errors ;)
7. Run the macro (copy it from GUI)
8. Adjust the styles (numbering of "Headings" and "Source Code" style)
9. Done!

#Screenshots

![GUI](screenshots/gui.png)

![Result sample](screenshots/sample.png)


#ChangeLog

- v0.6 - Netsparker support added (detailed html reports renamed to *.netsparker)

- v0.5 - Small improvements

- v0.4 - Read multiple files from dirs (*.nessus, *.burp, *.acunetix)

- v0.3 - Nessus CVSS score and vector, all type of risk factor to title case, KALI setup instruction in README.md

- v0.2 - Nessus "None" risk factor to "Info", rename to EHScripter

- v0.1 - Initial release

#Requirements

##Linux packages:

    sudo apt-get install python3 python3-tk python3-yaml python3-setuptools libyaml-dev python3-dev libffi-dev pandoc libxslt-dev libxml2-dev texlive-full
    easy_install3 pip

###KALI users need to upgrade pandoc manually:

    apt-get remove pandoc
    apt-get install haskell-platform texlive
    cabal update
    cabal install pandoc

Add .cabal/bin dir to your path:
    
    PATH="$HOME/.cabal/bin:$PATH"

##OSX

With [Homebrew](http://brew.sh/) install python3.

    brew install python3 

Add correct locale info to ~/.bash_profile if you don't have already (and don't forget te open new terminal or `source ~/.bash_profile`):

    export LC_ALL=en_US.UTF-8
    export LANG=en_US.UTF-8

For cairo dependencies, install XQuartz, and finally cairo.

    brew install Caskroom/cask/xquartz
    sudo chown -R $USER:admin /usr/local/share/man/man5
    brew link libpng fontconfig
    brew install py3cairo

Install [Pandoc](https://github.com/jgm/pandoc/releases).



##Python3 packages:

    pip3 install pyyaml lxml pygal cairosvg cssselect tinycss html2text

#License

GNU GPL V2


