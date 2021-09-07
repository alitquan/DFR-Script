import os
import sys
import sqlite3
import shutil
import subprocess
import time
import csv
import time
import operator
from tqdm import tqdm

# for presentation purposes
BREAK = "==================================="

# easy way to work 
flags = {
	"-h":"help",
	"-c":"chrome acquisition",
	"-l":"logical walkthrough",
	"-r":"recycling bin",
	"-a":"all"
}


def helpDisplay():

	'''
	Prints out all available flags
	along with whatever each one 
	signifies.
	'''

	print("\n"+ BREAK)
	print ("Displaying help options: \n")
	for flag in flags:
		print("\t%-3s%-8s" % (flag, "  -->> " + flags[flag]))
	print(BREAK)



# minor helping function
def findOccurrences(s, ch):

	'''
	Returns list of integers that 
	represent the indices that are
	the locations of 's' in 'ch'
	'''

	indices = list()
	for index, letter in enumerate(s):
		if letter == ch:
			indices.append(index)
	return indices


def fileToCSV (_file):

	'''
	writes properties of 'file' onto
	a csv file specified by 'csv_path'
	'''
	
	'''
	----
	os.stat return meanings
	----
	st_mode    : file type and file mode bits
	st_ino     : file index
	st_dev     : indentifier of device on which file resides
	st_nlink   : # of hard links
	st_uid     : user identifier of file owner
	st_gid     : group identifier of file owner
	st_size    : size of file in bytes
	st_atime   : time of most recent access (seconds)
	st_mtime   : time of most recent content modification
	st_ctime   : creation time
	'''

	# formatting string that follows the above attributes
	header_format = '{:<30s},{:>8s},{:>20s},{:>12s},{:>8s},{:>8s},{:>8s},{:>25s},{:>12s},{:>12s},{:>12s},{:<40s}\n'
	csv_format     = '{:<30s},{:>8s},{:>20s},{:>12s},{:>8s},{:>8s},{:>8s},{:>25s},{:>12s},{:>12s},{:>12s},{:<40s}'

	header = header_format.format("file_name","st_mode","st_ino","st_dev","st_nlink","st_uid","st_gid","st_size","st_atime","st_mtime","st_ctime","file_path")


	info = os.stat(_file)
	info = info[:] # converts line into tuples

	file_info = "file config.txt"

	if (os.path.isfile(file_info)):
		f = open (file_info,"a+", encoding="utf-8")
	else: 
		f = open (file_info,"w", encoding="utf-8")
		f.write(header)

	file_path = os.path.abspath(_file)
	new_line = csv_format.format(str(_file)[10:-1],str(info[0]),str(info[1]),str(info[2]),str(info[3]),str(info[4]),str(info[5]),str(info[6]),str(info[7]),str(info[8]),str(info[9]),file_path)
	f.write(new_line+"\n")
	f.close()








working_directory = os.getcwd()

'''
throwaway variable: indices that have character '\'

note that depending on the operating system, it can
be either a forward-slash or a back-slash
'''
placeholders = findOccurrences (working_directory,'\\') 


# user name for profile
name    = working_directory[placeholders[1] + 1: placeholders[2]]






# must be run from desktop
def chromeUserData():

	print ("\nGetting Chrome Data...\n")

	config  = 'C:/Users/' + name + '/AppData/Local/Google/Chrome/User Data/Default/'
	new_dir = working_directory + "/Chrome History"

	if (os.path.exists(new_dir)):
		return

	shutil.copytree (config, new_dir)


def recyclingBin():

	#https://www.lifewire.com/how-to-find-a-users-security-identifier-sid-in-windows-2625149
	#https://mattcasmith.net/2018/12/15/python-windows-forensics-recycle-bin-deleted-files/

	print("\nGetting recycling bin data...\n")

	username = "alitm"
	windows_drive = "C"
	wmic_query = "wmic useraccount where name=\"" + username + "\" get sid"
	user_sid = subprocess.check_output(wmic_query, shell=True)
	user_sid = user_sid[4:].strip()
	print (user_sid)

	recycled_directory = windows_drive + ":\$Recycle.Bin\\" + user_sid.decode('utf8') + "\\"
	print ("Recycle Bin directory is %s." % recycled_directory)

	timeline_csv = open ("timeline.csv","w")

	recycled_files = os.listdir(recycled_directory)
	try:
		for deleted_file in recycled_files:
			if deleted_file[1] == "I":
				full_path = recycled_directory + deleted_file
				
				deleted_file_content = open(full_path, "r",encoding="latin-1")
				deleted_file_path = deleted_file_content.read()
				deleted_file_content.close()
				# print(deleted_file_content)

				deleted_file_path = deleted_file_path[28:]
				string_length = len(deleted_file_path)
				deleted_file_path_parsed = ""
				x = 0
				while (x< string_length):
				    deleted_file_path_parsed += deleted_file_path[x]
				    x += 2

				filename = deleted_file_path_parsed.rsplit('\\', 1)[-1]

				creation_time = os.path.getctime(full_path)
				creation_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(creation_time))

				modified_time = os.path.getmtime(full_path)
				modified_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(modified_time))

				access_time = os.path.getatime(full_path)
				access_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(access_time))

				r_filename = "$R" + deleted_file[2:]
				file_size = str(os.path.getsize(recycled_directory + r_filename))

				deleted_file_line = creation_time + "," + "Deleted file/folder" + "," + filename[:-1] + "," + deleted_file_path_parsed[:-1] + "," + username + "," + file_size + "," + creation_time + "," + access_time + "," + modified_time + "," + "Recycle Bin" + "," + deleted_file + "\n"
				timeline_csv.write(deleted_file_line)
				# print ("Recycle Bin data gathered.")
				# print ("")
	except FileNotFoundError:
		print("Skipping a file")


def walkFiles():
	'''
	Walks through key directories of a Windows 
	operating system.

	Models the File System structure in a text
	file

	'''
	_root = "C:\\"
	list = os.scandir(_root)

	hierarchy = "file system.txt"
	if (os.path.isfile(hierarchy)):
		os.remove(hierarchy)


	f = open (hierarchy,"w", encoding="utf-8")

	print()
	print(BREAK)
	print("WALKING THROUGH OPERATING SYSTEM")
	print("WALKING THROUGH DIRECTORIES....")
	print("DO NOT EXIT")
	print(BREAK)
	print()

	for obj in tqdm(list):
		if obj.is_dir():
			f.write(obj.name)
			walkFilesH(os.path.join(_root,obj), 1,f)

		elif obj.is_file():
			f.write(obj.name)
			fileToCSV(obj)

		else:
			continue
		f.write("")

	f.close()


def walkFilesH(dir, counter, writeTo):
	space = " "
	space = space * counter

	writeTo.write(space + "|" + "\n")
	writeTo.write(space + "|-->" + "\n")

	try:
		list = os.scandir(dir)

		for obj in list:

			# print (space,end="")
			if obj.is_dir():
				writeTo.write(space + "|  * " + obj.name + "\n" )
				# print(space + "|  * " + obj.name)
				walkFilesH(os.path.join(dir,obj), counter + 3,writeTo)

			elif obj.is_file():
				writeTo.write(space + "|-- " + obj.name + "\n" )
				# print (space + "|-- " + obj.name)
				fileToCSV(obj)

			else:
				continue
	except PermissionError as p:
		print ("No permission for this directory: " + str(p))

def doAll():
	chromeUserData()
	walkFiles()
	recyclingBin()

def noArgs():
	print("\n\nNo arguments detected. Use arg '-h' for help: ")

	
_flags = {
	"-h":["help",helpDisplay],
	"-c":["chrome acquisition",chromeUserData],
	"-l":["logical walkthrough",walkFiles],
	"-r":["recycling bin",recyclingBin],
	"-a":["all",doAll]
}



if __name__ == "__main__":

	try:

		if (sys.argv == 0):
			noArgs()

		else:
			test = _flags.get(sys.argv[1])[1]()

	except IndexError:
		noArgs()
		



	# chromeUserData()
	# recyclingBin()
	# fileToCSV('./example.txt')
	# walkFiles()

