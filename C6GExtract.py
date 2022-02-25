#!/usr/bin/env python3

__author__ = "executionByFork"
__version__ = "1.3.0"
__license__ = "idc"

import os
import re
import csv
import argparse

parser = argparse.ArgumentParser(description='Converts a CyberSixGill formatted csv into various lists.')
parser.add_argument('-v', '--version', action='version', version=__version__)
parser.add_argument('-o', '--output-dir', dest='out_dir', default='C6G_output',
                    help='output directory to write files')
parser.add_argument('input_files', type=str, nargs='+',
                    help='CyberSixGill input csv file')
args = parser.parse_args()


hexpattern = re.compile('[0-9a-fA-F]+')
def isPossiblePassword(string):
  if not string:  # Remove blank lines
    return False
  if string[0:4] == '$2a$':  # Remove bcrypt hashes
    return False
  if string[0:11] == '\\_\\_SEC\\_\\_':  # Remove unknown SEC hashes
    return False
  if hexpattern.match(string):
    if len(string) == 32:  # Remove MD5 / MD4 hashes
      return False
    if len(string) == 40:  # Remove SHA1 hashes
      return False

  return True  # Otherwise, string is a possible password


def main():
  if not args.input_files:
    print("Error: Please specify an input file. See --help")
    exit()

  emailList = []
  credList = []
  for item in args.input_files:
    with open(item, newline='') as csvfile:
      dialect = csv.Sniffer().sniff(csvfile.read(1024))
      csvfile.seek(0)
      reader = csv.reader(csvfile, dialect)
      next(reader) # Skip header line

      for row in reader:
        # CyberSixGill is pretty terrible at properly differentiating passwords from hashes and junk
        # Instead of relying on the unreliable "Hash" column, we differentiate the two ourselves
        if isPossiblePassword(row[1]):
          credList.append([row[0], row[1]])
        emailList.append(row[0])

  if not os.path.exists(args.out_dir):
    os.makedirs(args.out_dir)

  dictCount = {}
  # Sort credList by length of password descending
  # CyberSixGill tends to label hashes as plain text passwords
  # This makes the hashes bubble up to the top for easy manual deletion
  # Also, super short, likely invalid passwords fall to the bottom for similar clean up
  credList = sorted(
    set(tuple(item) for item in credList),
    key=lambda x: int(len(x[1])),
    reverse=True
  )

  # Write out all emails with associated passwords
  with open(args.out_dir + '/C6G_credList.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['EMAIL','PASSWORD'])
    for row in credList:
      writer.writerow(row)
      # Keep count of number of credentials listed per email
      if row[0] in dictCount.keys():
        dictCount[row[0]] += 1
      else:
        dictCount[row[0]] = 1

  # Write out a list of all unique emails (includes those without associated passwords)
  emailList = sorted(set(emailList))
  with open(args.out_dir + '/C6G_emailList.txt', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    for row in emailList:
      writer.writerow([row])

  # Write all emails with at least one password, plus a count of available passwords for that email
  dictCount = dict(sorted(dictCount.items(), reverse=True, key=lambda item: item[1]))
  with open(args.out_dir + '/C6G_metadata.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['NUM_CREDS','EMAIL'])
    for email,count in dictCount.items():
      writer.writerow([count,email])

  with open(args.out_dir + '/version.txt', 'w', newline='') as txtfile:
    txtfile.write('Parsed with C6GExtract version ' + __version__)


main()
