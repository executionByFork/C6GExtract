#!/usr/bin/env python3

__author__ = "executionByFork"
__version__ = "1.1.0"
__license__ = "idc"

import csv
import argparse

parser = argparse.ArgumentParser(description='Converts a CyberSixGill formatted csv into various lists.')
parser.add_argument('-v', '--version', action='version', version=__version__)

parser.add_argument('input_file', type=str,
                    help='CyberSixGill input csv')
#parser.add_argument('-i', '--input-file', dest='inputfile')
args = parser.parse_args()

def main():
  if args.input_file is None:
    print("Error: Please specify an input file. See --help")
    exit()

  with open(args.input_file, newline='') as csvfile:
    dialect = csv.Sniffer().sniff(csvfile.read(1024))
    csvfile.seek(0)
    reader = csv.reader(csvfile, dialect)
    next(reader) # Skip header line

    emailList = []
    credList = []
    for row in reader:
      if row[2] == "plain":
        credList.append([row[0], row[1]])
      emailList.append(row[0])

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
  with open('C6G_credList.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['EMAIL','PASSWORD'])
    for row in credList:
      writer.writerow(row)
      # Keep count of number of credentials listed per email
      if row[0] in dictCount.keys():
        dictCount[row[0]] += 1
      else:
        dictCount[row[0]] = 1

  emailList = sorted(set(emailList))
  with open('C6G_emailList.txt', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    for row in emailList:
      writer.writerow([row])

  dictCount = dict(sorted(dictCount.items(), reverse=True, key=lambda item: item[1]))
  with open('C6G_metadata.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['NUM_CREDS','EMAIL'])
    for email,count in dictCount.items():
      writer.writerow([count,email])


main()
