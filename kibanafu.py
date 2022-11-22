#!/bin/bash/env python3

import sys
import webbrowser
import argparse
import platform
import yaml
import pandas as pd


def banner():
    print(r"""
    __    _  __                    ___
   / /__ (_)/ /  ___ _ ___  ___ _ / _/__ __
  /  '_// // _ \/ _ `// _ \/ _ `// _// // /
 /_/\_\/_//_.__/\_,_//_//_/\_,_//_/  \_,_/

    """)


def configurate(index, param):
    if index == "events":
        if param == "source":
            query_parameter = "source.ip : "
        elif param == "destination":
            query_parameter = "destination.ip : "
        else:
            print("[!] Error occurred: Invalid paramter.")
    elif index == "syslog":
        if param == "source":
            query_parameter = "extra.event.src_ip : "
        elif param == "destination":
            query_parameter = "extra.event.dest_ip : "
        else:
            print("[!] Error occurred: Invalid paramter.")
    else:
        print("[!] Error occurred: Invalid index.")

    return query_parameter


def open_browser(domain, index, config_indexes, kibana_query, time_param):
    if index == "events":
        index_param = config_indexes[0]
        url = "{}/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-{},to:now))&_a=(columns:!(extra.context,source.ip,source.port,destination.ip,destination.port,classification.taxonomy),filters:!(),{},interval:auto,query:(language:kuery,query:'{}'),sort:!(!('@timestamp',desc),!(time.source,desc)))".format(domain, time_param, index_param, kibana_query)
        webbrowser.open(url, new=2)
    elif index == "syslog":
        index_param = config_indexes[1]
        url = "{}/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-{},to:now))&_a=(columns:!(env_name,extra.event.src_ip,extra.event.src_port,extra.event.dest_ip,extra.event.dest_port,extra.event.alert.signature),filters:!(),{},interval:auto,query:(language:kuery,query:'{}'),sort:!(!('@timestamp',desc),!(time.source,desc)))".format(domain, time_param, index_param, kibana_query)
        webbrowser.open(url, new=2)
    else:
        print("[!] Error occurred")


def parse_ips(filename):
    with open(filename, 'r') as input_file:
        lines = [line.strip() for line in input_file if line.strip()]
    return lines


def build_query(lines, query_parameter):
    query_builder = []
    for line in lines:
        query = query_parameter + line
        query_builder.append(query)

    return " OR ".join(query_builder)


def save_query_to_file(filename, kibana_query):
    with open(filename, 'w') as output_file:
        output_file.write(kibana_query)


def load_config(filename):
    with open(filename, "r") as ymlfile:
        config = yaml.safe_load(ymlfile)
    return config


def parse_args():
    parser = argparse.ArgumentParser(
        description='Kibanafu parses IP IOCs and builds a search query with defined parameters for Kibana.')

    parser.add_argument('--name', metavar="NAME",
                        help='analysis keyword (e.g. Trickbot, Mirai, Zeus, ...)')
    parser.add_argument('--input', metavar="FILENAME",
                        help='input xls/xslx file containing IOCs')
    parser.add_argument('--column', metavar="NAME", required='--input' in sys.argv,
                        help='column name containing IPs (required for --input)')
    parser.add_argument('--parsed', metavar="FILENAME",
                        help='input txt file containing parsed IPs')
    parser.add_argument('--output', metavar="FILENAME", default="kibana_query.txt",
                        help='output file for Kibana query (default: kibana_query.txt)')
    parser.add_argument('--index', metavar="NAME", default="syslog",
                        help='index name [events/syslog] (default: syslog)')
    parser.add_argument('--field', metavar="NAME", default="source",
                        help='field name [source/destination] (default: source)')
    parser.add_argument('--time', metavar="TIME", default="7d",
                        help='time frame [15m/30m/1h/24h/7d/30d/90d/1y] (default: 7d)')
    parser.add_argument('--action', metavar="ACTION", default="browser",
                        help='action to execute [browser/file] (default: browser)')

    args = parser.parse_args()
    return args


def main():
    banner()

    machine_platfrom = platform.system()
    if machine_platfrom == "Darwin":    # Mac
        print(
            "\n[!] Mac is not a supported platform. Please, use Windows or Linux instead.")
        print("\nExiting program ...\n")
        exit(1)

    args = parse_args()

    config_path = ".config/config.yml"
    config = load_config(config_path)
    domain = config['app']['domain']
    config_events = config['indexes']['events']
    config_syslog = config['indexes']['syslog']
    config_indexes = []
    config_indexes.append(config_events)
    config_indexes.append(config_syslog)
    config_arguments = config['arguments']
    
    config_state = config['arguments']['state']

    if config_state == "enabled":
        print(f"[*] Loading arguments from '.config/config.yml'")
        try:
            analysis_name = config['arguments']['name']
            file_name = config['arguments']['input']
            target_column = config['arguments']['column']
            input_file = config['arguments']['parsed']
            output_file = config['arguments']['output'] or "kibana_query.txt"
            index = config['arguments']['index'] or "syslog"
            param = config['arguments']['field'] or "source"
            time_frame = config['arguments']['time'] or "7d"
            action = config['arguments']['action'] or "browser"
        except KeyError:
            print(f"[!] Error encountered while loading '{config_path}'. Missing argument(s).")
            print(f"\nExiting program ...\n")
            exit(1)  
    elif config_state == "disabled":
        analysis_name = args.name
        file_name = args.input
        target_column = args.column
        input_file = args.parsed
        output_file = args.output
        index = args.index
        param = args.field
        time_frame = args.time
        action = args.action

    if not analysis_name is None:
        print(f"\n[ Analyzing {analysis_name} ]\n")

    ips = []
    some_input = False
    if not file_name is None and not target_column is None:
        some_input = True
        try:
            xls_file = pd.ExcelFile(file_name)
            sheet_names = xls_file.sheet_names
            print(
                f"[*] Loading IPs from '{file_name}', column '{target_column}'")

            try:
                for sheet_name in sheet_names:
                    df = pd.read_excel(file_name, sheet_name=sheet_name)
                    ips_column = df[target_column].tolist()
                    for ip in ips_column:
                        ips.append(ip)
            except KeyError:
                print(f"\n[!] No such file or directory: '{xls_file}'")
                print(f"\nExiting program ...\n")
                exit(1)       
        except FileNotFoundError:
            print(f"\n[!] No such file or directory: '{xls_file}'")
            print(f"\nExiting program ...\n")
            exit(1)

    if not input_file is None:  # already parsed IPs in txt file
        some_input = True
        try:
            print(f"[*] Loading IPs from '{input_file}'")
            ips = parse_ips(input_file)
        except FileNotFoundError:
            print(f"\n[!] No such file or directory: '{input_file}'")
            print(f"\nExiting program ...\n")
            exit(1)


    if some_input:
        print(f"[*] Configurating '{index}' index with '{param}' field")
        query_parameter = configurate(index, param)

        print(f"[*] Building Kibana query with defined options")
        ip_iocs_holder = set(ips)
        ips = (list(ip_iocs_holder))
        kibana_query = build_query(ips, query_parameter)

        if action == "browser":
            times = {
                "15m": "15m",
                "30m": "30m",
                "1h": "1h",
                "24h": "24h/h",
                "7d": "7d/d",
                "30d": "30d/d",
                "90d": "90d/d",
                "1y": "1y/d"
            }
            time_param = times[time_frame]
            print(f"[*] Opening browser session with built Kibana query")
            open_browser(domain, index, config_indexes,
                         kibana_query, time_param)
        else:
            print(f"[*] Saving Kibana query to '{output_file}'")
            save_query_to_file(output_file, kibana_query)
    else:
        print(f"[!] No input file was provided")
        print(f"\nExiting program ...\n")
        exit(1)

    print("\n")


if __name__ == "__main__":
    main()