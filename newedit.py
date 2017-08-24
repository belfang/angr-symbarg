#!/usr/bin/env python

import angr, claripy, time, sys, os, simuvex 
from xml.dom import minidom

def basic_symbolic_execution():

    start_time = time.time()

    xmldoc = minidom.parse('sample2.xml')

#get the arguments
    itemlist = xmldoc.getElementsByTagName('arg')
    commandLine = list()

#at the very beginning of the list is the path
    arguments = list()
    arguments.append(str(xmldoc.getElementsByTagName('exec')[0].childNodes[0].nodeValue))


#create dictionary for bitvectors
    d={}
    count = 0

#iterated through the args
    for s in itemlist:

#if concolic, append to list as bitvector
	if s.attributes['concolic'].value == "true":
	    d["arg{0}".format(count)] = claripy.BVS("arg{0}".format(count), int(s.attributes['size'].value)*8)
	    arguments.append("arg{0}".format(count))

#else append the value as is to the list
	else:
	    arguments.append(str(s.attributes['value'].value))
        count = count+1


#get the files (paths)
    xmlfilelist = xmldoc.getElementsByTagName('file')
    fileList = list()
    for s in xmlfilelist:
	fileList.append(str((s.attributes['path'].value)))
    x = 0

#at the very end of the list are the input files
    while (x < len(fileList)):
    	arguments.append(fileList[x])
        x = x+1
    y = 0

#check the arguments list
    while (y < len(arguments)):
        print arguments[y]
        y = y+1

#create project
    proj = str(xmldoc.getElementsByTagName('exec')[0].childNodes[0].nodeValue)
    p = angr.Project(proj, load_options={'auto_load_libs':True})

##################################################################################

#dictionary of files
    files = {}
    z = 0
    while (z < len(fileList)):
    	files[fileList[z]]= angr.storage.file.SimFile(fileList[z], "r", size=30)
	z = z+1

#check that these two are correct
    print len(files)
    print len(fileList)

#create state and step until timeout
    state = p.factory.entry_state(args=arguments, fs = files)
    #state = p.factory.entry_state(args=[arguments[0], arguments[1], arguments[4], arguments[2], arguments[5], arguments[3]]) 
    #state = p.factory.entry_state(args=[arguments[0], arguments[1], arguments[2], arguments[3]]) 
    sm = p.factory.simgr(state)

    sm.step(until=lambda lpg: (time.time() - start_time) > 40)

##################################################################################

    print len(sm.deadended)
    print len(sm.active)    

#make directories which will hold the test cases
    os.makedirs("active_dir", 0777)

    os.makedirs("deadended_dir", 0777)

#iterate through the args from xml to write test cases
    index = 0
    for count in itemlist:

#if concolic is true, proceed
	if count.attributes['concolic'].value == "true":

#write the actives
            os.chdir("active_dir")	    
            k=0
    	    while (k < len(sm.active)):
	        output1 = open("arg_active{}_{}.bin".format(k, index), "w+")
	        output1.write(sm.active[k].solver.any_str(d.get("arg{0}".format(index))))
	        k = k+1
            os.chdir("../")

#write the deadended
            os.chdir("deadended_dir")
            k = 0    
    	    while (k < len(sm.deadended)):
	        output2 = open("arg_deadended{}_{}.bin".format(k, index), "w+")
	        output2.write(sm.deadended[k].solver.any_str(d.get("arg{0}".format(index))))
                print sm.deadended[k].solver.any_str(d.get("arg{0}".format(index)))
	        k = k+1
            os.chdir("../")  

#else, skip this part, don't create arg
	else:
	    print ""
        index=index+1


##################################################################################


#iterate through the args from xml to write test files    
    index = 0
    for count2 in itemlist:

#if concolic is false, proceed 
	if count2.attributes['concolic'].value == "false":

#write the actives
	    os.chdir("active_dir")	    
 	    k=0
#use 2 loops to write all actives for every file 
   	    while (index < len(fileList)):
	        while (k < len(sm.active)):
	            output3 = open("file_active{}_{}".format(k, index), "w+")
	            output3.write(sm.active[k].posix.dump_file_by_path(fileList[index]))
	            k = k+1
                index = index+1

	    os.chdir("../")

#write the deadended
	    os.chdir("deadended_dir")
	    k = 0  
            index = 0
   	    while (index < len(fileList)):
	        while (k < len(sm.deadended)):
                    print index
	    	    output4 = open("file_deadended{}_{}.bin".format(k, index), "w+")
	    	    output4.write(sm.deadended[k].posix.dump_file_by_path(fileList[index]))
                    print sm.deadended[k].posix.dump_file_by_path(fileList[index])
	    	    k = k+1
                index=index+1

	    os.chdir("../")


#else, skip this part, don't create file
	else:
	    print ""


##################################################################################

def test():
    pass        # appease our CI infrastructure which expects this file to do something lmao

if __name__ == '__main__':
    print basic_symbolic_execution()

# You should be able to run this program and pipe its into fauxware in order to
# produce a "sucessfully authenticated" message
