import os
import argparse

def get_args():
    parser = argparse.ArgumentParser(
        description='hexrecon')
    parser.add_argument(
        '-d', '--domain', type=str, help='Domain', required=False, default=False)
    parser.add_argument(
        '--install', help='Install', nargs='?', default=False)
    parser.add_argument(

    return parser.parse_args()

if __name__ == "__main__":
    args = get_args()
    install = args.install

