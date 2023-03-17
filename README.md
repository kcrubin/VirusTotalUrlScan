URL Scanner using VirusTotal API
This Python code scans a list of URLs using the VirusTotal API to check if they have been detected as malicious by any anti-virus (AV) engines.

Prerequisites
  •	Python 3.x
  •	requests library
  •	VirusTotal API key


Installation
  1.	Install Python 3.x from https://www.python.org/downloads/
  2.	Install the requests library by running pip install requests in your terminal or command prompt.


Usage
  1.	Obtain a VirusTotal API key from https://www.virustotal.com/gui/join-us
  2.	Create a CSV file named 'url_list.csv' in the same directory as your Python code.
  3.	Add the list of URLs you want to scan in the first column of the CSV file.
  4.	Replace the apikey variable in the code with your VirusTotal API key.
  5.	Run the code using the command python url_scanner.py in your terminal or command prompt.

The code will output whether each URL in the list is malicious or not, based on the results of the VirusTotal scan. 
If a URL is detected as malicious, the code will also output the number of AV engines that detected it as such.
