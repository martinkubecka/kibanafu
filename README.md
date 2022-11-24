<p align="center">
<img src="https://github.com/martinkubecka/kibanafu/blob/main/docs/banner.png" alt="Logo">
<p align="center"><b>Parse IP IOCs and build a search query for Kibana with defined parameters.</b><br>
</p>

---
## :notebook_with_decorative_cover: Pre-requisites

- Python3.X ([download](https://www.python.org/downloads/release/python-3102/))
- create `config.yml` based on the `example.yml` file inside `config` directory

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
