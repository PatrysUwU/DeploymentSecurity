import argparse

from deployment_scanner import api


def scan():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proj_path", required=True, type=str, default="")
    args = parser.parse_args()
    api.scan(args.proj_path)


def remediate():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proj_path", required=True, type=str, default="")
    args = parser.parse_args()
    api.remediate_repo(args.proj_path)
