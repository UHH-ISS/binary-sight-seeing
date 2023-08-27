#!/bin/bash

# This script downloads the required pip packages for the
# puppeteer VM (Linux, Python 3.8) and the puppet VM
# (Windows, Python 3.8). It also creates scripts which 
# can be used to install the packages on the respective
# machines.

mkdir downloaded_packages
cd downloaded_packages

mkdir auto_puppeteer
mkdir agent

pip download -r ../auto_puppeteer_requirements.txt -d auto_puppeteer
pip download -r ../agent_requirements.txt -d agent --platform win32 --python-version 38 --implementation cp --only-binary=:all: --no-binary=:none:

cd auto_puppeteer
touch install_packages.sh
chmod +x install_packages.sh
echo "#!/bin/bash" > install_packages.sh
for i in {1..5};
do
    ls *.whl *.tar.gz | while read line ;
    do
        echo "pip install --no-index $line" >> install_packages.sh
    done
done

cd ../agent
rm -rf install_packages.bat
touch install_packages.bat
chmod +x install_packages.bat
for i in {1..5};
do
    ls *.whl *.tar.gz | while read line ;
    do
        echo "pip install --no-index $line" >> install_packages.bat
    done
done