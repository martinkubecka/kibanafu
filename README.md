<p align="center">
<img src="https://github.com/martinkubecka/kibanafu/blob/main/images/banner.png" alt="Logo">
<p align="center"><b>Parse IP IOCs and build a query for Kibana with defined parameters.</b><br>
</p>

---
---
## :notebook_with_decorative_cover: Pre-requisites


- Python3.X ([download](https://www.python.org/downloads/release/python-3102/))
- PyYAML (`pip install pyyaml`)
- create `config.yml` based on the `example.yml` file inside `.config` directory

---
## :speech_balloon: Usage

```
usage: kibanafu.py [-h] [--index NAME] [--field NAME] [--time TIME] [--input FILENAME] [--output FILENAME] [--action ACTION]

Kibanafu parses IP IOCs and builds a query with defined parameters for Kibana.

options:
  -h, --help         show this help message and exit
  --index NAME       index name [events/syslog] (default: syslog)
  --field NAME       field name [source/destination] (default: source)
  --time TIME        time frame [15m/30m/1h/24h/7d/30d/90d/1y] (default: 7d)
  --input FILENAME   input file containg IPs (default: ips.txt)
  --output FILENAME  output file for Kibana query (default: kibana_query.txt)
  --action ACTION    action to execute [browser/file] (default: browser)

```
