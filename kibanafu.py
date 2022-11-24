import os
import sys
import webbrowser
import time
import logging
import argparse
import platform
import yaml
import pandas as pd

# TODO: rework logging to support Windows

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
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Invalid paramter")
            # logging.error("Invalid paramter")
    elif index == "syslog":
        if param == "source":
            query_parameter = "extra.event.src_ip : "
        elif param == "destination":
            query_parameter = "extra.event.dest_ip : "
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Invalid paramter")
            # logging.error("Invalid paramter")
    else:
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR]  Invalid index")
        # logging.error("Invalid index")

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


def init_logger():
    logging_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/logs"
    if not os.path.isdir(logging_path):
        os.mkdir(logging_path)
    logging.basicConfig(format='%(created)f; %(asctime)s; %(levelname)s; %(name)s; %(message)s',
                        filename=f"{logging_path}/{(os.path.splitext(__file__)[0]).split('/')[-1]}.log", level=logging.DEBUG)
    logger = logging.getLogger('__name__')


def arg_formatter():
    def formatter(prog): return argparse.HelpFormatter(
        prog, max_help_position=52)
    return formatter


def parse_args():
    parser = argparse.ArgumentParser(formatter_class=arg_formatter(
    ), description='Parse IP IOCs and build a search query for Kibana with defined parameters.')

    parser.add_argument('-q', '--quiet', help="do not print banner", action='store_true')
    parser.add_argument('-n', '--name', metavar="NAME",
                        help='analysis keyword (e.g. Trickbot, Mirai, Zeus, ...)')
    parser.add_argument('-i', '--input', metavar="FILENAME",
                        help='input xls/xslx file containing IOCs')
    parser.add_argument('-c', '--column', metavar="NAME", required='--input' in sys.argv,
                        help='column name containing IPs (required for --input)')
    parser.add_argument('-p', '--parsed', metavar="FILENAME",
                        help='input txt file containing parsed IPs')
    parser.add_argument('-o', '--output', metavar="FILENAME", default="kibana_query.txt",
                        help='output file for Kibana query (default: kibana_query.txt)')
    parser.add_argument('-x', '--index', metavar="NAME", default="syslog",
                        help='index name [events/syslog] (default: syslog)')
    parser.add_argument('-f', '--field', metavar="NAME", default="source",
                        help='field name [source/destination] (default: source)')
    parser.add_argument('-t', '--time', metavar="TIME", default="7d",
                        help='time frame [15m/30m/1h/24h/7d/30d/90d/1y] (default: 7d)')
    parser.add_argument('-a', '--action', metavar="ACTION", default="browser",
                        help='action to execute [browser/file] (default: browser)')

    args = parser.parse_args()
    return args


def main():
    # init_logger()

    machine_platfrom = platform.system()
    if machine_platfrom == "Darwin":    # Mac
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Unsupported platform")
        # logging.error("Unsupported platform")
        print("\nExiting program ...\n")
        exit(1)

    args = parse_args()

    if not args.quiet:
        banner()

    config_path = "config/config.yml"
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
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Loading arguments from '{config_path}'")
        # logging.info(f"Loading arguments from '{config_path}'")

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
            print(
                f"[{time.strftime('%H:%M:%S')}] [ERROR] Missing argument(s) in '{config_path}'")
            # logging.error(f"Missing argument(s) in '{config_path}'")
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
        # logging.info(f"Analyzing {analysis_name}")

    ips = []
    some_input = False
    if not file_name is None and not target_column is None:
        some_input = True
        try:
            xls_file = pd.ExcelFile(file_name)
            sheet_names = xls_file.sheet_names
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Loading IPs from '{file_name}', column '{target_column}'")
            # logging.info(f"Loading IPs from '{file_name}', column '{target_column}'")

            try:
                for sheet_name in sheet_names:
                    df = pd.read_excel(file_name, sheet_name=sheet_name)
                    ips_column = df[target_column].tolist()
                    for ip in ips_column:
                        ips.append(ip)
            except KeyError:
                print(
                    f"[{time.strftime('%H:%M:%S')}] [ERROR] No such file or directory: '{file_name}'")
                # logging.error(f"No such file or directory: '{file_name}'")
                print(f"\nExiting program ...\n")
                exit(1)
        except FileNotFoundError:
            print(
                f"[{time.strftime('%H:%M:%S')}] [ERROR] No such file or directory: '{file_name}'")
            # logging.error(f"No such file or directory: '{file_name}'")
            print(f"\nExiting program ...\n")
            exit(1)

    if not input_file is None:  # already parsed IPs in txt file
        some_input = True
        try:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Loading IPs from '{input_file}'")
            # logging.info(f"Loading IPs from '{input_file}'")
            ips = parse_ips(input_file)
        except FileNotFoundError:
            print(
                f"[{time.strftime('%H:%M:%S')}] [ERROR] No such file or directory: '{input_file}'")
            # logging.error(f"No such file or directory: '{input_file}'")
            print(f"\nExiting program ...\n")
            exit(1)

    if some_input:
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Configurating '{index}' index with '{param}' field")
        # logging.info(f"Configurating '{index}' index with '{param}' field")

        query_parameter = configurate(index, param)

        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Building Kibana query with defined options")
        # logging.info(f"Building Kibana query with defined options")

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
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Opening browser session with built search query\n")
            # logging.info(f"Opening browser session with built search query")
            open_browser(domain, index, config_indexes,
                         kibana_query, time_param)
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Saving search query to '{output_file}'\n")
            # logging.info(f"Saving search query to '{output_file}'")
            save_query_to_file(output_file, kibana_query)
    else:
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] No input file was provided")
        # logging.error(f"No input file was provided")
        print(f"\nExiting program ...\n")
        exit(1)


if __name__ == "__main__":
    main()
