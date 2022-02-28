# C6GExtract
A python 3.x script which parses one or more CyberSixGill `credentials.csv` dump files into the following lists:
- `C6G_emailList.txt` - Text file containing a deduplicated list of emails found in the dumps
- `C6G_credList.csv` - CSV file of email and password pairs, with a majority of the junk data filtered out
- `C6G_metadata.csv` - CSV file of deduplicated emails along with a count of how many times that email appears

This script has no dependencies outside of python 3.x

### Installation
This is as easy as cloning the repo and executing the C6GExtract.py python script within.

Example for making C6GExtract available through the PATH environment variable:
```
cd /opt
git clone https://github.com/executionByFork/C6GExtract.git
chmod a+x /opt/C6GExtract/C6GExtract.py
ln -s /opt/C6GExtract/C6GExtract.py /usr/local/bin/C6GExtract
C6GExtract --help
```
