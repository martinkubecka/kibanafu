<p align="center">
<img src="https://github.com/martinkubecka/kibanafu/blob/main/images/banner.png" alt="Logo">
<p align="center"><b>Parse IP IOCs and build a search query for Kibana with defined parameters.</b><br>
</p>

---
## :notebook_with_decorative_cover: Pre-requisites

- Python3.X ([download](https://www.python.org/downloads/release/python-3102/))
- create `config.yml` based on the `example.yml` file inside `.config` directory

```
$ pip install -r requirements.txt
```

---
## :speech_balloon: Usage

```
usage: kibanafu.py [-h] [--name NAME] [--input FILENAME] [--column NAME] [--parsed FILENAME] [--output FILENAME] [--index NAME] [--field NAME] [--time TIME] [--action ACTION]

Kibanafu parses IP IOCs and builds a search query with defined parameters for Kibana.

options:
  -h, --help         show this help message and exit
  --name NAME        analysis keyword (e.g. Trickbot, Mirai, Zeus, ...)
  --input FILENAME   input xls/xslx file containing IOCs
  --column NAME      column name containing IPs (required for --input)
  --parsed FILENAME  input txt file containing parsed IPs
  --output FILENAME  output file for Kibana query (default: kibana_query.txt)
  --index NAME       index name [events/syslog] (default: syslog)
  --field NAME       field name [source/destination] (default: source)
  --time TIME        time frame [15m/30m/1h/24h/7d/30d/90d/1y] (default: 7d)
  --action ACTION    action to execute [browser/file] (default: browser)
```
