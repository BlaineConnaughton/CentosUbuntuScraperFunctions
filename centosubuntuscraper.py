
import requests
import os
import sys
import csv
import json

try: 
	from BeautifulSoup import BeautifulSoup
except ImportError:
	from bs4 import BeautifulSoup


def scrape_ubuntu(cve , os_version , vulnpackage):
	# sample cve = 'CVE-2015-6240'

	pieces = cve.split("-")
	url = "https://people.canonical.com/~ubuntu-security/cve/%s/%s.html" % (pieces[1], cve)
	
	#get url and put into html parser library
	r = requests.get(url)
	soup = BeautifulSoup(r.content)
	
	container = soup.find('div', {'id': 'container'})
	priority = container.findAll('div')
	prio =  priority[0].text
	
	upstream , status = "Not found" , "Not found"

	#go to table and pull out the value matching os_version ex: 14.04
	packagediv = soup.findAll('div', {'class': 'pkg'})
	
	for packages in packagediv:
		if packages.find('div', {'class': 'value'}).text.find(vulnpackage) > -1:
			table = packages.findAll('table')
			rows = table[0].findAll('tr')
			for tr in rows:
				cols = tr.findAll('td')
				if cols[0].text.find('Upstream') > -1:
					upstream = cols[1].text
				elif cols[0].text.find(os_version) > -1:
					status = cols[1].text

			return url , prio , upstream , status 

	
	return url , prio , "Needs manual confirmation" , "Needs manual confirmation"

def scrape_redhat(cve , os_version , vulnpackage):
	# sample cve = 'CVE-2015-6240'
	# returns url , prio , upstream , status , packageScraped , osChecked

	url = "https://access.redhat.com/labs/securitydataapi/cve/%s.json" % (cve)
	r = requests.get(url)
		
	#Redhat/Centos returns a 404 for missing CVEs.  They do not have CVE's for notices that do not impact redhat
	if r.status_code == 404:
		return url , "N/A" , "N/A" , "Doesn't impact OS" , "N/A" , "N/A"
	else:    
		cveData = json.loads(r.text)

	#First check for package information, not everything has it but most do
	packages = cveData.get("package_state")
	if packages == None:
		return url , cveData.get('threat_severity') , cveData.get('upstream_fix') , "No Package list" ,  "No Package list","No OS list"
	else:
		#Package can be either a dict or a list.  Figure out which, then go through to see if this impacts our OS version
		if type(packages) is dict:
			if packages['product_name'].find(os_version) > -1:
				return url, cveData.get('threat_severity'), cveData.get('upstream_fix') , packages['fix_state'], packages['package_name'] , packages['product_name']
			else: #If we don't find a matching OS note that
				return url, cveData.get('threat_severity'), "Does not Impact OS version" ,  "Does not Impact OS version", "N/A", "N/A"
		else: #assume its a list of dictionaries
			for package in packages:
				if package.get('product_name').find(os_version) > -1:
					return url, cveData.get('threat_severity'), cveData.get('upstream_fix') , package['fix_state'], package['package_name'] , package['product_name']
			return url, cveData.get('threat_severity') ,  "Does not Impact OS version" ,  "Does not Impact OS version" , "N/A" , "N/A"

def get_Vulnerabilities():

	#Implement a way to generate a list of vulnerabilities to analyze
	vulnlist = [('cve' , 'package'), ('cve2' , 'package2') , ('cve3' , 'package3')]

	return vulnlist


def main():
	
	if len(sys.argv) < 5:
		print "Usage: vulnerability_scraper.py osVersion osNumber"
		return

	osversion = sys.argv[1] #If unbuntu use that scraper, otherwise default to redhat/centos
	osnumber = sys.argv[2] #version number of OS for unbuntu expecting 14.04 16.04 etc for centos red hat just the major version 6, 7 etc

	#First query api and get list of CVE and packages
	cvePackageList = get_Vulnerabilities()

	#The two sources have different data for fields and headers, try and consolidate this later
	if osversion == "ubuntu":
		
		with open("UbuntuData", 'w') as csvfile:
		   
			#setup for the csv writer
			fieldnames = ['Package', 'CVE' , 'Priority' , "Upstream" , 'Version' , 'URL']
			writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
			writer.writeheader()
	   
			for CVE in cvePackageList:
				cve = CVE[0]
				package = CVE[1]

				#We use the package name as we scrape to find the correct html table, split off the numbers when we make the call
				url , prio , upstream , status = scrape_ubuntu(cve.strip() , osnumber.strip(), package.split(" ")[0])
				writer.writerow({'Package': package, "CVE" : cve , 'Priority': prio , 'Upstream': upstream , 'Version': status , 'URL': url })
				
	else: #red hat or centos, both pull from redhat cve db

		with open("VulnerabilityData", 'w') as csvfile:
		   
			 #setup for the csv writer
			fieldnames = ['Package', 'CVE' , 'Priority' , "Upstream" , 'Version' , 'URL' , "PackageScraped" , "osChecked"]
			writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
			writer.writeheader()

			for CVE in cvePackageList:
				cve = CVE[0]
				package = CVE[1]
				
				url , prio , upstream , status , packageScraped , osChecked = scrape_redhat(cve.strip() , osnumber.strip(), package.strip())

				writer.writerow({'Package': package, "CVE" : cve , 'Priority': prio , 'Upstream': upstream , 'Version': status , 'osChecked': osChecked, 'PackageScraped': packageScraped , 'URL': url  })
				
			return

if __name__ == "__main__":
	main()
