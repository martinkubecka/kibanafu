<p align="center">
<img src="https://github.com/martinkubecka/kibanafu/blob/main/docs/banner.png" alt="Logo">
<p align="center"><b>Parse IP IOCs and build a search query for Kibana with defined parameters.</b><br>
</p>

---
<h2 id="table-of-contents">Table of Contents</h2>

- [Pre-requisites](#notebook_with_decorative_cover-pre-requisites)
  - [Installing Required Packages](#package-installing-required-packages)
- [Usage](#speech_balloon-usage)
- [Development](#toolbox-development)
  - [Virtual environment](#office-virtual-environment)

---
## :notebook_with_decorative_cover: Pre-requisites

- clone this project with the following command

```
$ git clone https://github.com/martinkubecka/mailo.git
```
- create `config.yml` based on the `example.yml` file inside `config` directory

### :package: Installing Required Packages

```
$ pip install -r requirements.txt
```

---
## :speech_balloon: Usage

```
usage: kibanafu.py [-h] [-q] [-n NAME] [-i FILENAME] [-c NAME] [-p FILENAME] [-o FILENAME] [-x NAME] [-f NAME] [-t TIME] [-a ACTION]

Parse IP IOCs and build a search query for Kibana with defined parameters.

options:
  -h, --help                      show this help message and exit
  -q, --quiet                     do not print banner
  -n NAME, --name NAME            analysis keyword (e.g. Trickbot, Mirai, Zeus, ...)
  -i FILENAME, --input FILENAME   input xls/xslx file containing IOCs
  -c NAME, --column NAME          column name containing IPs (required for --input)
  -p FILENAME, --parsed FILENAME  input txt file containing parsed IPs
  -o FILENAME, --output FILENAME  output file for Kibana query (default: kibana_query.txt)
  -x NAME, --index NAME           index name [events/syslog] (default: syslog)
  -f NAME, --field NAME           field name [source/destination] (default: source)
  -t TIME, --time TIME            time frame [15m/30m/1h/24h/7d/30d/90d/1y] (default: 7d)
  -a ACTION, --action ACTION      action to execute [browser/file] (default: browser)
```

---
## :toolbox: Development

### :office: Virtual environment

1. use your package manager to install `python-pip` if it is not present on your system
3. install `virtualenv`
4. verify installation by checking the `virtualenv` version
5. inside the project directory create a virtual environment called `venv`
6. activate it by using the `source` command
7. you can deactivate the virtual environment from the parent folder of `venv` directory with the `deactivate` command

```
$ sudo apt-get install python-pip
$ pip install virtualenv
$ virtualenv --version
$ virtualenv --python=python3 venv
$ source venv/bin/activate
$ deactivate
```

---

<div align="right">
<a href="#table-of-contents">[ Table of Contents ]</a>
</div>